"""Vigilante de fugas de IP en tiempo real (pasivo, sin root).

Cada pocos segundos lee la tabla de sockets del kernel (/proc/net/tcp, tcp6, udp, udp6: visible para
cualquier usuario) y clasifica cada conexión hacia Internet según la interfaz a la que pertenece su
IP LOCAL:

  * túnel (wg/tun)                 → protegida.
  * física (WiFi/ethernet) con un túnel activo → FUGA: ese programa está saliendo con tu IP real
                                     por fuera de la VPN (split-tunnel, bind a interfaz, IPv6…).
  * física sin ningún túnel        → exposición directa (no es "fuga": no hay VPN que evitar).

El puerto 53 se marca como fuga de DNS. El programa se identifica por el inodo del socket (solo
los procesos de tu usuario; los de root aparecen como "otro usuario").

Limitaciones: no ve conexiones de otros network namespaces (contenedores con red propia) ni el
tráfico de WireGuard del kernel (no tiene socket), y un sondeo cada N segundos puede perder
conexiones muy breves. Para bloqueo garantizado hace falta un kill-switch (cliente VPN o nftables).
"""

from __future__ import annotations

from .i18n import _
from .util import WINDOWS

import glob
import ipaddress
import os
import sys
import threading

from .util import now

TCP_STATES = {"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV"}
TUNNEL_KINDS = {"wireguard", "tun", "ppp"}
PHYSICAL_KINDS = {"ethernet", "wifi"}
# DHCP/NTP/mDNS/SSDP: tráfico de infraestructura local
INFRA_PORTS = {67, 68, 5353, 1900}


def _addr(h: str) -> str:
    raw = bytes.fromhex(h)
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    ip = ipaddress.ip_address(raw)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip)


def parse_proc_net(text: str, proto: str) -> list[dict]:
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        lh, _ign, lp = f[1].partition(":")
        rh, _ign, rp = f[2].partition(":")
        try:
            local, remote = _addr(lh), _addr(rh)
            lport, rport = int(lp, 16), int(rp, 16)
        except ValueError:
            continue
        if proto == "tcp":
            state = TCP_STATES.get(f[3])
            if not state:
                continue
        else:
            if rport == 0:            # UDP sin "connect": no tiene destino fijo
                continue
            state = "UDP"
        out.append({"proto": proto, "local": local, "lport": lport, "remote": remote, "rport": rport,
                    "state": state, "uid": int(f[7]) if f[7].isdigit() else None, "inode": int(f[9])})
    return out


def read_sockets() -> list[dict]:
    if WINDOWS:                       # rama windows-lite: mismos datos desde las API de Windows
        from . import winsys
        return winsys.read_sockets()
    socks = []
    for name, proto in (("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp")):
        try:
            with open(f"/proc/net/{name}") as fh:
                socks += parse_proc_net(fh.read(), proto)
        except OSError:
            continue
    return socks


_OWNER_CACHE: dict[int, tuple[int, str]] = {}


def owners(wanted: set[int] | None = None, cache: bool = True) -> dict[int, tuple[int, str]]:
    """inodo de socket → (pid, comando). Con `wanted` solo busca esos inodos, reutiliza lo ya
    resuelto y para en cuanto los encuentra (recorrer todos los fd de todos los procesos cada 2 s
    es caro con navegadores que tienen miles)."""
    if WINDOWS:                       # rama windows-lite: mismos datos desde las API de Windows
        from . import winsys
        return winsys.owners(wanted)
    res = {}
    if wanted is not None and cache:
        res = {i: _OWNER_CACHE[i] for i in wanted if i in _OWNER_CACHE}
        missing = set(wanted) - set(res)
        if not missing:
            return res
    else:
        missing = None
    uid = os.getuid()
    for d in glob.glob("/proc/[0-9]*"):
        try:
            if os.stat(d).st_uid != uid:          # los fd de otros usuarios no son legibles
                continue
            fds = os.listdir(f"{d}/fd")
            with open(f"{d}/comm") as fh:
                comm = fh.read().strip()
        except OSError:
            continue
        pid = int(d.rsplit("/", 1)[1])
        for fd in fds:
            try:
                link = os.readlink(f"{d}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                ino = int(link[8:-1])
                if missing is None or ino in missing:
                    res[ino] = (pid, comm)
                    if missing is not None:
                        missing.discard(ino)
        if missing is not None and not missing:
            break
    if wanted is not None and cache:
        _OWNER_CACHE.clear()
        _OWNER_CACHE.update(res)
    return res


def _user(uid: int) -> str:
    """Usuario del socket cuando el proceso no es visible (p. ej. debian-tor, root)."""
    try:
        import pwd
        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError):
        return f"uid {uid}"


def is_internet(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global          # excluye privadas, loopback, link-local, CGNAT (100.64/10), ULA…


def address_map(net: dict) -> dict[str, tuple[str, str]]:
    """IP local → (interfaz, tipo)."""
    m = {}
    for i in net["interfaces"]:
        for a in i["addrs"]:
            m[a["addr"].split("%")[0]] = (i["name"], i["kind"])
    return m


def classify(socks: list[dict], net: dict, allow: set[str] | None = None, own: dict | None = None) -> dict:
    """Clasifica las conexiones a Internet. Devuelve flows + resumen."""
    allow = allow or set()
    amap = address_map(net)
    tunnels = [i["name"] for i in net["interfaces"] if i["kind"] in TUNNEL_KINDS and i["up"]]
    tunnel_up = bool(tunnels)
    flows = []
    for s in socks:
        if not is_internet(s["remote"]) or s["rport"] in INFRA_PORTS or s["lport"] in INFRA_PORTS:
            continue
        iface, kind = amap.get(s["local"], (None, None))
        pid, comm = (own or {}).get(s["inode"], (None, None))
        proc = comm or (f"[{_user(s['uid'])}]" if s["uid"] is not None and s["uid"] != os.getuid() else "desconocido")
        if s["remote"] in allow or f"{s['remote']}:{s['rport']}" in allow or (comm and f"proc:{comm}" in allow):
            verdict = "permitida"
        elif kind in TUNNEL_KINDS:
            verdict = "protegida"
        elif kind in PHYSICAL_KINDS or iface is None:
            verdict = "fuga" if tunnel_up else "directa"
        else:
            verdict = "otra"
        flows.append({**s, "iface": iface, "iface_kind": kind, "pid": pid, "process": proc, "verdict": verdict,
                      "dns": s["rport"] == 53 or s["lport"] == 53})
    count = lambda v: sum(1 for f in flows if f["verdict"] == v)  # noqa: E731
    return {"ts": now(), "tunnel_up": tunnel_up, "tunnels": tunnels, "flows": flows,
            "summary": {"protegidas": count("protegida"), "fugas": count("fuga"), "directas": count("directa"),
                        "permitidas": count("permitida"), "otras": count("otra")}}


def flow_key(f: dict) -> str:
    return f"{f['process']}|{f['proto']}|{f['remote']}|{f['rport']}"


class LeakWatcher(threading.Thread):
    """Hilo del daemon: clasifica conexiones cada `interval` s y avisa de fugas nuevas (sin repetir)."""

    def __init__(self, engine, interval: float = 2.0, cooldown: float = 600.0):
        super().__init__(daemon=True, name="leakwatch")
        self.engine = engine
        self.interval = interval
        self.cooldown = cooldown
        self.state: dict | None = None
        self._seen: dict[str, float] = {}
        self._was_exposed = None
        self._stop = threading.Event()
        self.lock = threading.Lock()

    def snapshot(self) -> dict:
        net = self.engine.net
        if net is None:
            return {"ts": now(), "flows": [], "summary": {}, "tunnel_up": False}
        allow = set((self.engine.cfg.get("leakwatch") or {}).get("allow") or [])
        socks = read_sockets()
        wanted = {s["inode"] for s in socks if is_internet(s["remote"])}
        return classify(socks, net, allow, owners(wanted))

    def run(self):
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as e:  # noqa: BLE001 — el vigilante no debe morir
                self.engine.emit("leakwatch_error", "info", {"error": str(e)})
                self._stop.wait(10)
            self._stop.wait(self.interval)

    def step(self):
        st = self.snapshot()
        with self.lock:
            self.state = st
        t = now()
        cfg = self.engine.cfg.get("leakwatch") or {}
        leaks = [f for f in st["flows"] if f["verdict"] == "fuga"]
        for f in leaks:
            k = flow_key(f)
            if t - self._seen.get(k, 0) < self.cooldown:
                continue
            self._seen[k] = t
            self.engine.emit("ip_leak" if not f["dns"] else "dns_leak_live", "critical" if not f["dns"] else "high", {
                "process": f["process"], "pid": f["pid"], "proto": f["proto"], "remote": f"{f['remote']}:{f['rport']}",
                "local": f["local"], "iface": f["iface"],
                "detail": _("conexión fuera del túnel con tu IP real mientras la VPN está activa")})
        if leaks and cfg.get("on_leak") == "killswitch" and not self.engine.ks.state.get("active"):
            res = self.engine.ks.engage(reason=_("fuga detectada en tiempo real"))
            self.engine.emit("killswitch_auto", "critical", {"result": res, "leaks": len(leaks)})
        # Exposición directa con un perfil que exige VPN: un aviso por transición
        exposed = (not st["tunnel_up"]) and st["summary"].get("directas", 0) > 0
        if exposed != self._was_exposed:
            if exposed and self.engine.profile.get("require_vpn"):
                procs = sorted({f["process"] for f in st["flows"] if f["verdict"] == "directa"})[:12]
                self.engine.emit("direct_exposure", "high", {
                    "flows": st["summary"]["directas"], "processes": procs,
                    "detail": _("sin túnel: estas conexiones muestran tu IP real y el perfil exige VPN")})
            self._was_exposed = exposed
        for k in [k for k, v in self._seen.items() if t - v > self.cooldown * 3]:
            del self._seen[k]

    def stop(self):
        self._stop.set()

