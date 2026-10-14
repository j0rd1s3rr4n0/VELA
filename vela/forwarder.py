"""Forwarder local para rotar proxies sin reconfigurar las aplicaciones.

Las aplicaciones apuntan a 127.0.0.1:<listen>; el forwarder reenvía cada conexión NUEVA al proxy
upstream activo. Es transparente al protocolo (bytes), así que el pool debe ser homogéneo
(todos HTTP o todos SOCKS5): la aplicación habla el protocolo del upstream. Las conexiones ya
abiertas conservan su upstream hasta cerrarse.
"""

from __future__ import annotations

from .i18n import _

import re
import select
import socket
import socketserver
import threading


def parse_proxy(url: str) -> tuple[str, str, int]:
    m = re.match(r"^(\w+)://(?:[^@/]+@)?\[?([^\]/]+?)\]?:(\d+)/?$", url)
    if not m:
        raise ValueError(_("URL de proxy no válida: {url}", url=url))
    return m.group(1).lower(), m.group(2), int(m.group(3))


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fw: ProxyForwarder = self.server.forwarder
        upstream = fw.upstream
        if not upstream:
            return
        _ign, host, port = parse_proxy(upstream)
        try:
            remote = socket.create_connection((host, port), timeout=10)
        except OSError:
            fw.errors += 1
            return
        fw.connections += 1
        client = self.request
        socks = [client, remote]
        try:
            while True:
                r, _ign, x = select.select(socks, [], socks, 300)
                if x or not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        return
                    (remote if s is client else client).sendall(data)
        except OSError:
            pass
        finally:
            remote.close()


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyForwarder:
    def __init__(self, listen: str = "127.0.0.1:1088", upstream: str | None = None):
        host, _ign, port = listen.rpartition(":")
        if host not in ("127.0.0.1", "::1", "localhost"):
            raise ValueError(_("el forwarder solo puede escuchar en loopback"))
        self.addr = (host, int(port))
        self.upstream = upstream
        self.connections = 0
        self.errors = 0
        self._srv: _Server | None = None

    def start(self):
        self._srv = _Server(self.addr, _Handler)
        self._srv.forwarder = self
        self.addr = self._srv.server_address[:2]
        threading.Thread(target=self._srv.serve_forever, daemon=True, name="proxy-forwarder").start()
        return self

    def stop(self):
        if self._srv:
            self._srv.shutdown()
            self._srv.server_close()

    def set_upstream(self, url: str):
        parse_proxy(url)
        self.upstream = url

    @staticmethod
    def probe_upstream(url: str, timeout: float = 5) -> tuple[bool, str | None]:
        try:
            _ign, host, port = parse_proxy(url)
            with socket.create_connection((host, port), timeout=timeout):
                return True, None
        except (OSError, ValueError) as e:
            return False, str(e)

    def status(self) -> dict:
        return {"listen": f"{self.addr[0]}:{self.addr[1]}", "upstream": self.upstream,
                "connections": self.connections, "errors": self.errors, "running": self._srv is not None}
