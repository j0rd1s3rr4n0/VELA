"""IPC local entre `velad` y las interfaces.

* Socket UNIX en $XDG_RUNTIME_DIR/vela/velad.sock, directorio 0700 y socket 0600.
* Autenticación del cliente por SO_PEERCRED: solo el mismo UID que el daemon.
* JSON por líneas: {"id", "method", "params"} → {"id", "result"} | {"id", "error"}.
* Lista blanca explícita de métodos: no se expone ningún atributo arbitrario del motor.
* Nunca escucha en TCP.
"""

from __future__ import annotations

import json
import os
import queue
import socket
import socketserver
import struct
import threading
from pathlib import Path

from .util import private_dir, runtime_dir

METHODS = {
    "status", "discover", "networks", "leakwatch", "routes", "settings_get", "settings_set", "intel_test", "intel_tor_check", "profiles_generate", "fixes", "intel_keys", "intel_targets", "intel_scan",
    "intel_results", "network", "vpn_list", "proxy_list", "tor_status", "dns_check", "public_ip", "router",
    "sessions", "counters", "events", "leaks", "rotate", "rotation_status", "profiles", "profile_activate",
    "correlation", "stats", "anomalies", "timeline", "map", "worldmap", "capabilities", "config_get", "config_set",
    "panic", "resume", "killswitch", "audit", "audit_log", "doctor", "purge", "webrtc_report", "export",
}


class IPCError(Exception):
    pass


def socket_path() -> Path:
    return runtime_dir() / "velad.sock"


def peer_uid(sock: socket.socket) -> int:
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return uid


def _jsonable(o):
    return json.dumps(o, default=str, ensure_ascii=False)


class _Handler(socketserver.StreamRequestHandler):
    timeout = 60          # una conexión que no envía nada no puede retener un hilo y un socket para siempre

    def handle(self):
        try:
            self._handle()
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass          # el cliente se fue antes de leer la respuesta: no es un error del daemon

    def _handle(self):
        if peer_uid(self.request) != os.getuid():
            self.wfile.write(b'{"error": "UID no autorizado"}\n')
            return
        srv: IPCServer = self.server.ipc
        for raw in self.rfile:
            try:
                req = json.loads(raw)
                method, params, rid = req.get("method"), req.get("params") or {}, req.get("id")
            except (ValueError, AttributeError):
                self.wfile.write(b'{"error": "JSON no valido"}\n')
                continue
            if method == "subscribe":
                self._subscribe(srv)
                return
            if method not in METHODS:
                self.wfile.write((_jsonable({"id": rid, "error": f"método desconocido: {method}"}) + "\n").encode())
                continue
            try:
                result = srv.dispatch(method, params)
                out = {"id": rid, "result": result}
            except Exception as e:  # noqa: BLE001
                out = {"id": rid, "error": f"{type(e).__name__}: {e}"}
            self.wfile.write((_jsonable(out) + "\n").encode())
            self.wfile.flush()
            return        # una petición por conexión: el cliente abre una nueva para cada llamada

    def _subscribe(self, srv):
        self.request.settimeout(None)
        q: queue.Queue = queue.Queue(maxsize=1000)
        srv.engine.subscribers.append(q)
        try:
            while True:
                try:
                    ev = q.get(timeout=15)
                    line = {"event": ev}
                except queue.Empty:
                    line = {"keepalive": True}
                self.wfile.write((_jsonable(line) + "\n").encode())
                self.wfile.flush()
        except (OSError, ValueError):
            pass
        finally:
            srv.engine.subscribers.remove(q)


class _Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


class IPCServer:
    def __init__(self, engine, path: Path | None = None):
        self.engine = engine
        self.path = path or socket_path()
        private_dir(self.path.parent)
        if self.path.exists():
            if ping(self.path):
                raise IPCError(f"ya hay un daemon escuchando en {self.path}")
            self.path.unlink()
        old = os.umask(0o177)
        try:
            self.srv = _Server(str(self.path), _Handler)
        finally:
            os.umask(old)
        os.chmod(self.path, 0o600)
        self.srv.ipc = self
        self.lock = threading.Lock()

    def dispatch(self, method: str, params: dict):
        if method == "export":
            from . import report
            return report.export_data(self.engine, params.get("since"))
        fn = getattr(self.engine, f"api_{method}")
        return fn(**params)

    def serve_forever(self):
        self.srv.serve_forever(poll_interval=0.5)

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True, name="ipc").start()
        return self

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()
        try:
            self.path.unlink()
        except OSError:
            pass


class Client:
    def __init__(self, path: Path | None = None, timeout: float = 120):
        self.path = path or socket_path()
        self.timeout = timeout
        self._id = 0

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(str(self.path))
        return s

    def call(self, method: str, **params):
        self._id += 1
        s = self._connect()
        f = None
        try:
            s.sendall((_jsonable({"id": self._id, "method": method, "params": params}) + "\n").encode())
            f = s.makefile("rb")
            line = f.readline()
        finally:
            # cierre explícito: un makefile vivo (p. ej. retenido por un traceback) mantendría el socket abierto
            if f is not None:
                f.close()
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        if not line:
            raise IPCError("el daemon cerró la conexión")
        resp = json.loads(line)
        if "error" in resp:
            raise IPCError(resp["error"])
        return resp["result"]

    def subscribe(self):
        s = self._connect()
        s.settimeout(None)
        s.sendall(b'{"method": "subscribe"}\n')
        f = s.makefile("rb")
        try:
            for line in f:
                msg = json.loads(line)
                if "event" in msg:
                    yield msg["event"]
        finally:
            s.close()


def ping(path: Path | None = None) -> bool:
    try:
        Client(path, timeout=8).call("profiles")
        return True
    except (OSError, IPCError, ValueError):
        return False


class LocalBackend:
    """Motor en el propio proceso cuando el daemon no está en marcha (no registra sesiones)."""
    remote = False

    def __init__(self):
        from .engine import Engine
        self.engine = Engine(actor="local", track=False)

    def call(self, method: str, **params):
        if method not in METHODS:
            raise IPCError(f"método desconocido: {method}")
        if method == "export":
            from . import report
            return json.loads(_jsonable(report.export_data(self.engine, params.get("since"))))
        # serializar/deserializar para que el resultado sea idéntico al del daemon
        return json.loads(_jsonable(getattr(self.engine, f"api_{method}")(**params)))

    def subscribe(self):
        q: queue.Queue = queue.Queue()
        self.engine.subscribers.append(q)
        while True:
            yield q.get()


class RemoteBackend(Client):
    remote = True


def connect(prefer_daemon: bool = True):
    if prefer_daemon and socket_path().exists() and ping():
        return RemoteBackend()
    return LocalBackend()
