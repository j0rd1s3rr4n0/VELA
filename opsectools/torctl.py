"""Cliente mínimo del protocolo de control de Tor (control-spec), solo stdlib.

Lo que hace: autenticación SAFECOOKIE/COOKIE/contraseña, GETINFO (circuitos, streams, relays,
guards, bootstrap), SIGNAL NEWNYM con límite de frecuencia y escucha de eventos CIRC/STREAM.

Lo que NO hace, a propósito: no toca guards, ni ExitNodes/EntryNodes, ni fuerza circuitos
concretos. Pedir NEWNYM solo marca los circuitos actuales como sucios: los streams nuevos irán
por circuitos nuevos, pero Tor puede elegir el mismo exit y no se garantiza una IP distinta.
"""

from __future__ import annotations

import binascii
import hashlib
import hmac
import os
import re
import socket
import threading
import time

from .util import now

SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"
NEWNYM_MIN_INTERVAL = 10.0  # Tor ignora NEWNYM más frecuentes


class TorControlError(Exception):
    pass


def parse_target(target) -> str | tuple[str, int]:
    if isinstance(target, tuple):
        return target
    t = str(target)
    if t.startswith("unix:"):
        return t[5:]
    if t.startswith("/"):
        return t
    host, _, port = t.rpartition(":")
    return (host or "127.0.0.1", int(port))


def parse_reply_lines(lines: list[str]) -> list[tuple[str, str, str, list[str]]]:
    """Convierte líneas crudas en [(código, separador, texto, datos)]."""
    out, i = [], 0
    while i < len(lines):
        line = lines[i]
        code, sep, text = line[:3], line[3:4], line[4:]
        data = []
        if sep == "+":
            i += 1
            while i < len(lines) and lines[i] != ".":
                data.append(lines[i][1:] if lines[i].startswith("..") else lines[i])
                i += 1
        out.append((code, sep, text, data))
        i += 1
    return out


def parse_path(path: str) -> list[dict]:
    hops = []
    for item in path.split(","):
        m = re.match(r"\$([0-9A-Fa-f]{40})(?:[~=](\S+))?", item)
        if m:
            hops.append({"fp": m.group(1).upper(), "nick": m.group(2)})
    return hops


def parse_circuit_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 2:
        return None
    circ = {"id": parts[0], "status": parts[1], "path": [], "purpose": None, "flags": [], "created": None}
    rest = parts[2:]
    if rest and rest[0].startswith("$"):
        circ["path"] = parse_path(rest[0])
        rest = rest[1:]
    for tok in rest:
        k, _, v = tok.partition("=")
        if k == "PURPOSE":
            circ["purpose"] = v
        elif k == "BUILD_FLAGS":
            circ["flags"] = v.split(",")
        elif k == "TIME_CREATED":
            circ["created"] = v
    return circ


def parse_stream_line(line: str) -> dict | None:
    parts = line.split()
    if len(parts) < 3:
        return None
    # No conservamos el destino del stream (privacidad): solo estado y circuito.
    return {"id": parts[0], "status": parts[1], "circ": parts[2]}


def parse_ns(text: str) -> dict:
    info = {}
    for line in text.splitlines():
        if line.startswith("r "):
            p = line.split()
            if len(p) >= 8:
                info.update(nick=p[1], ip=p[6], orport=int(p[7]))  # 'published' es ficticio (2038) con microdescs
        elif line.startswith("s "):
            info["flags"] = line[2:].split()
        elif line.startswith("w ") and "Bandwidth=" in line:
            try:
                info["bandwidth"] = int(line.split("Bandwidth=")[1].split()[0])
            except ValueError:
                pass
    return info


class TorControl:
    def __init__(self, target, password: str | None = None, cookie_path: str | None = None, timeout: float = 5.0):
        self.target = parse_target(target)
        self.password = password
        self.cookie_path = cookie_path
        self.timeout = timeout
        self.sock: socket.socket | None = None
        self._buf = b""
        self._lock = threading.Lock()
        self.protocolinfo: dict = {}

    # ── conexión ──
    def connect(self) -> "TorControl":
        if isinstance(self.target, str):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.target)
        else:
            s = socket.create_connection(self.target, timeout=self.timeout)
            s.settimeout(self.timeout)
        self.sock = s
        try:
            self._authenticate()
        except BaseException:
            s.close()
            self.sock = None
            raise
        return self

    def close(self):
        if self.sock:
            try:
                self.sock.sendall(b"QUIT\r\n")
            except OSError:
                pass
            self.sock.close()
            self.sock = None

    def __enter__(self):
        return self if self.sock else self.connect()

    def __exit__(self, *exc):
        self.close()

    # ── E/S ──
    def _readline(self) -> str:
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise TorControlError("conexión cerrada por Tor")
            self._buf += chunk
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line.decode("utf-8", "replace")

    def _read_reply(self) -> list[str]:
        lines = []
        while True:
            line = self._readline()
            lines.append(line)
            if len(line) >= 4 and line[3] == "+":
                while True:
                    dl = self._readline()
                    lines.append(dl)
                    if dl == ".":
                        break
            elif len(line) >= 4 and line[3] == " ":
                return lines

    def command(self, line: str) -> list[tuple[str, str, str, list[str]]]:
        with self._lock:
            self.sock.sendall(line.encode() + b"\r\n")
            while True:
                raw = self._read_reply()
                if raw[0].startswith("650"):   # evento asíncrono en esta conexión: ignorar aquí
                    continue
                break
        reply = parse_reply_lines(raw)
        code = reply[-1][0]
        if not code.startswith("2"):
            raise TorControlError(f"{line.split()[0]}: {code} {reply[-1][2]}")
        return reply

    # ── autenticación ──
    def _authenticate(self):
        reply = self.command("PROTOCOLINFO 1")
        text = " ".join(r[2] for r in reply)
        methods = re.search(r"METHODS=(\S+)", text)
        methods = methods.group(1).split(",") if methods else []
        cookie = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', text)
        version = re.search(r'Tor="([^"]+)"', text)
        self.protocolinfo = {"methods": methods, "cookie_file": cookie.group(1) if cookie else None,
                             "version": version.group(1) if version else None}
        cookie_path = self.cookie_path or self.protocolinfo["cookie_file"]
        if "NULL" in methods:
            self.command("AUTHENTICATE")
        elif "SAFECOOKIE" in methods and cookie_path and os.access(cookie_path, os.R_OK):
            self._safecookie(cookie_path)
        elif "COOKIE" in methods and cookie_path and os.access(cookie_path, os.R_OK):
            with open(cookie_path, "rb") as f:
                self.command("AUTHENTICATE " + f.read().hex())
        elif "HASHEDPASSWORD" in methods and self.password is not None:
            self.command('AUTHENTICATE "' + self.password.replace("\\", "\\\\").replace('"', '\\"') + '"')
        else:
            raise PermissionError(f"no hay método de autenticación utilizable (métodos: {methods}, "
                                  f"cookie: {cookie_path or '-'})")

    def _safecookie(self, cookie_path: str):
        with open(cookie_path, "rb") as f:
            cookie = f.read()
        client_nonce = os.urandom(32)
        reply = self.command("AUTHCHALLENGE SAFECOOKIE " + client_nonce.hex())
        text = reply[-1][2]
        sh = re.search(r"SERVERHASH=([0-9A-Fa-f]+)", text)
        sn = re.search(r"SERVERNONCE=([0-9A-Fa-f]+)", text)
        if not sh or not sn:
            raise TorControlError("respuesta AUTHCHALLENGE inválida")
        server_nonce = binascii.unhexlify(sn.group(1))
        msg = cookie + client_nonce + server_nonce
        expected = hmac.new(SERVER_KEY, msg, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, binascii.unhexlify(sh.group(1))):
            raise TorControlError("SERVERHASH no coincide: el otro extremo no conoce la cookie")
        self.command("AUTHENTICATE " + hmac.new(CLIENT_KEY, msg, hashlib.sha256).hexdigest())

    # ── consultas ──
    def getinfo(self, *keys: str) -> dict[str, str]:
        reply = self.command("GETINFO " + " ".join(keys))
        out = {}
        for code, sep, text, data in reply:
            if "=" in text:
                k, _, v = text.partition("=")
                out[k] = "\n".join(data) if sep == "+" else v
        return out

    def signal(self, name: str):
        self.command("SIGNAL " + name)

    def circuits(self) -> list[dict]:
        raw = self.getinfo("circuit-status").get("circuit-status", "")
        return [c for c in (parse_circuit_line(l) for l in raw.splitlines() if l.strip()) if c]

    def streams(self) -> list[dict]:
        raw = self.getinfo("stream-status").get("stream-status", "")
        return [s for s in (parse_stream_line(l) for l in raw.splitlines() if l.strip()) if s]

    def relay(self, fp: str) -> dict:
        try:
            return parse_ns(self.getinfo(f"ns/id/{fp}").get(f"ns/id/{fp}", ""))
        except TorControlError:
            return {}

    def ip_to_country(self, ip: str) -> str | None:
        try:
            cc = self.getinfo(f"ip-to-country/{ip}").get(f"ip-to-country/{ip}")
        except TorControlError:
            return None
        return cc.upper() if cc and cc not in ("??", "--") else None

    # ── eventos ──
    def set_events(self, *events: str):
        self.command("SETEVENTS " + " ".join(events))

    def read_event(self) -> list[str]:
        """Bloquea hasta recibir un evento 650 (usar en una conexión dedicada)."""
        with self._lock:
            raw = self._read_reply()
        return raw


def find_control(spec: str = "auto") -> list:
    """Candidatos de control por orden de preferencia (socket unix del servicio, 9051, Tor Browser 9151)."""
    if spec and spec != "auto":
        return [parse_target(spec)]
    cands = []
    for path in ("/run/tor/control", "/var/run/tor/control"):
        real = os.path.realpath(path)
        if os.path.exists(real) and real not in cands:
            cands.append(real)
    cands += [("127.0.0.1", 9051), ("127.0.0.1", 9151)]
    return cands


class TorObserver:
    """Vista de alto nivel de una instancia Tor para el motor."""

    def __init__(self, spec: str = "auto", geo=None, password: str | None = None):
        self.spec = spec
        self.geo = geo
        self.password = password
        self.target = None
        self.observe_only = False   # True para Tor Browser: no se rota desde aquí
        self._relay_cache: dict[str, tuple[float, dict]] = {}
        self._last_newnym = 0.0
        self.active_circuit: str | None = None
        self.last_error: str | None = None
        self._events_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.on_event = None

    def _connect(self) -> TorControl:
        errors = []
        cands = [self.target] if self.target else find_control(self.spec)
        for t in cands:
            try:
                ctl = TorControl(t, password=self.password).connect()
                self.target = t
                self.observe_only = t == ("127.0.0.1", 9151)
                return ctl
            except (OSError, TorControlError, PermissionError) as e:
                errors.append(f"{t}: {e}")
        self.target = None
        raise TorControlError("; ".join(errors) or "sin candidatos")

    def _relay(self, ctl: TorControl, fp: str) -> dict:
        cached = self._relay_cache.get(fp)
        if cached and now() - cached[0] < 1800:
            return cached[1]
        info = ctl.relay(fp)
        if info.get("ip") and self.geo:
            g = self.geo.lookup(info["ip"])
            info.update(country=g.get("country"), country_name=g.get("country_name"),
                        lat=g.get("lat"), lon=g.get("lon"), asn=g.get("asn"))
        self._relay_cache[fp] = (now(), info)
        return info

    def status(self) -> dict:
        try:
            ctl = self._connect()
        except TorControlError as e:
            self.last_error = str(e)
            return {"available": False, "error": str(e)}
        try:
            info = ctl.getinfo("version", "status/bootstrap-phase", "status/circuit-established", "network-liveness")
            circuits = ctl.circuits()
            streams = ctl.streams()
            try:
                guards_raw = ctl.getinfo("entry-guards").get("entry-guards", "")
            except TorControlError:
                guards_raw = ""
            per_circ: dict[str, int] = {}
            for s in streams:
                per_circ[s["circ"]] = per_circ.get(s["circ"], 0) + 1
            general = [c for c in circuits if c["status"] == "BUILT" and c["purpose"] in (None, "GENERAL")
                       and len(c["path"]) >= 3 and "IS_INTERNAL" not in c["flags"]]
            for c in general:
                c["streams"] = per_circ.get(c["id"], 0)
                for i, hop in enumerate(c["path"]):
                    hop.update(self._relay(ctl, hop["fp"]))
                    hop["role"] = "guard" if i == 0 else ("exit" if i == len(c["path"]) - 1 else "middle")
            used = [c for c in general if c["streams"]]
            active = None
            if self.active_circuit and any(c["id"] == self.active_circuit for c in general):
                active = next(c for c in general if c["id"] == self.active_circuit)
            elif used:
                active = max(used, key=lambda c: (c["streams"], c["created"] or ""))
            elif general:
                active = max(general, key=lambda c: c["created"] or "")
            guards = []
            for line in guards_raw.splitlines():
                m = re.match(r"\$?([0-9A-Fa-f]{40})\S*\s+(\S+)", line.strip())
                if m:
                    guards.append({"fp": m.group(1).upper(), "status": m.group(2)})
            boot = info.get("status/bootstrap-phase", "")
            prog = re.search(r"PROGRESS=(\d+)", boot)
            self.last_error = None
            return {
                "available": True,
                "target": self.target if isinstance(self.target, str) else f"{self.target[0]}:{self.target[1]}",
                "observe_only": self.observe_only,
                "version": info.get("version"),
                "bootstrap": int(prog.group(1)) if prog else None,
                "circuit_established": info.get("status/circuit-established") == "1",
                "network_live": info.get("network-liveness") == "up",
                "circuits": general,
                "circuit_count": len(circuits),
                "stream_count": len(streams),
                "active": active,
                "exit": active["path"][-1] if active else None,
                "guard": active["path"][0] if active else None,
                "guards": guards[:5],
            }
        except (OSError, TorControlError) as e:
            self.last_error = str(e)
            return {"available": False, "error": str(e)}
        finally:
            ctl.close()

    def newnym(self) -> dict:
        if self.observe_only:
            return {"ok": False, "error": "Tor Browser: usa 'Nueva identidad' en el navegador"}
        wait = NEWNYM_MIN_INTERVAL - (time.monotonic() - self._last_newnym)
        if wait > 0:
            return {"ok": False, "error": f"rate-limit: espera {wait:.0f}s", "retry_in": wait}
        try:
            with self._connect() as ctl:
                ctl.signal("NEWNYM")
        except (OSError, TorControlError, PermissionError) as e:
            return {"ok": False, "error": str(e)}
        self._last_newnym = time.monotonic()
        self.active_circuit = None
        return {"ok": True}

    def start_events(self, callback):
        """Hilo dedicado con SETEVENTS CIRC STREAM; reconecta con espera exponencial."""
        self.on_event = callback

        def loop():
            delay = 2
            while not self._stop.is_set():
                try:
                    ctl = self._connect()
                    ctl.sock.settimeout(None)
                    ctl.set_events("CIRC", "STREAM")
                    delay = 2
                    while not self._stop.is_set():
                        raw = ctl.read_event()
                        self._handle_event(raw)
                except Exception as e:  # noqa: BLE001 — el hilo debe sobrevivir
                    self.last_error = str(e)
                    self._stop.wait(delay)
                    delay = min(delay * 2, 60)

        self._events_thread = threading.Thread(target=loop, daemon=True, name="tor-events")
        self._events_thread.start()

    def _handle_event(self, raw: list[str]):
        line = raw[0][4:]
        parts = line.split()
        if not parts:
            return
        if parts[0] == "STREAM" and len(parts) >= 4 and parts[2] == "SUCCEEDED":
            changed = parts[3] != self.active_circuit
            self.active_circuit = parts[3]
            if changed and self.on_event:
                self.on_event({"kind": "tor_stream_circuit", "circuit": parts[3]})
        elif parts[0] == "CIRC" and len(parts) >= 3 and parts[2] in ("BUILT", "CLOSED", "FAILED"):
            if parts[2] != "BUILT" and parts[1] == self.active_circuit:
                self.active_circuit = None
            if self.on_event:
                self.on_event({"kind": "tor_circuit", "circuit": parts[1], "status": parts[2]})

    def stop(self):
        self._stop.set()
