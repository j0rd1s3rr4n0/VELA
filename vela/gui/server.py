"""Servidor de la GUI (stdlib).

Seguridad:
  * Solo escucha en 127.0.0.1 (o ::1). Nunca en interfaces públicas.
  * Token aleatorio por arranque, entregado en el fragmento de la URL (#t=…): el navegador no lo
    envía en peticiones ni queda en logs. La API exige la cabecera X-VELA-Token.
  * Comprobación de Host/Origin contra DNS rebinding y CSRF.
  * CSP estricta sin recursos externos: todo (JS, CSS, mapa) se sirve desde aquí.
"""

from __future__ import annotations

from ..i18n import _

import hmac
import json
import mimetypes
import secrets
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

from ..ipc import METHODS

STATIC = Path(__file__).parent / "static"
READ_ONLY = {"status", "discover", "network", "vpn_list", "proxy_list", "tor_status", "sessions", "counters",
             "events", "rotation_status", "profiles", "correlation", "stats", "anomalies", "timeline", "map",
             "worldmap", "capabilities", "config_get", "audit", "audit_log", "doctor", "export"}
CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
       "font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "vela-gui"
    sys_version = ""

    def log_message(self, *args):  # sin logs de peticiones (podrían contener datos sensibles)
        pass

    def _headers(self, code: int, ctype: str, length: int | None = None, extra: dict | None = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        if length is not None:
            self.send_header("Content-Length", str(length))
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _json(self, code: int, obj):
        body = json.dumps(obj, default=str, ensure_ascii=False).encode()
        self._headers(code, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
        if host not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin and urlsplit(origin).netloc.lower() not in allowed:
            return False
        return True

    def _auth(self) -> bool:
        tok = self.headers.get("X-VELA-Token", "")
        return hmac.compare_digest(tok.encode(), self.server.token.encode())

    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": _("host/origen no permitido")})
        path = urlsplit(self.path).path
        if path == "/":
            path = "/index.html"
        if path.startswith("/api/"):
            return self._json(405, {"error": _("usa POST")})
        if path == "/i18n.json":                      # catálogo del idioma activo (no es información sensible)
            from .. import i18n
            lang = i18n.language()
            return self._json(200, {"lang": lang, "locale": i18n.LOCALES.get(lang, "es-ES"),
                                    "catalog": i18n.catalog(lang)})
        if path == "/theme.css":                      # colores del tema elegido en Ajustes (vela/themes.py)
            from .. import themes
            body = themes.web_css(themes.load_prefs()["theme"]).encode()
            self._headers(200, "text/css; charset=utf-8", len(body))
            return self.wfile.write(body)
        f = (STATIC / path.lstrip("/")).resolve()
        if STATIC.resolve() not in f.parents or not f.is_file():
            return self._json(404, {"error": _("no encontrado")})
        data = f.read_bytes()
        ctype = mimetypes.guess_type(f.name)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript",):
            ctype += "; charset=utf-8"
        self._headers(200, ctype, len(data))
        self.wfile.write(data)

    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": _("host/origen no permitido")})
        if not self._auth():
            return self._json(401, {"error": _("token no válido")})
        path = urlsplit(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 2_000_000:
            return self._json(413, {"error": _("petición demasiado grande")})
        try:
            params = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json(400, {"error": _("JSON no válido")})
        if path == "/api/stream":
            return self._stream()
        if path == "/api/export_html":
            from ..report import to_html
            data = self.server.backend.call("export")
            body = to_html(None, data, self.server.backend.call("audit")).encode()
            self._headers(200, "text/html; charset=utf-8", len(body),
                          {"Content-Disposition": 'attachment; filename="vela-informe.html"'})
            return self.wfile.write(body)
        method = path.removeprefix("/api/")
        if method not in METHODS:
            return self._json(404, {"error": _("método desconocido: {method}", method=method)})
        try:
            with self.server.call_lock if method not in READ_ONLY else _nullctx():
                result = self.server.backend.call(method, **(params or {}))
            self._json(200, {"result": result})
        except Exception as e:  # noqa: BLE001
            self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def _stream(self):
        self._headers(200, "application/x-ndjson")
        try:
            for ev in self.server.backend.subscribe():
                self.wfile.write((json.dumps(ev, default=str, ensure_ascii=False) + "\n").encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass


class _nullctx:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class GUIServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, addr, backend):
        super().__init__(addr, Handler)
        self.backend = backend
        self.token = secrets.token_urlsafe(32)
        self.call_lock = threading.Lock()


def serve(backend, host: str = "127.0.0.1", port: int = 0, open_browser: bool = True):
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise ValueError(_("la GUI solo puede escuchar en loopback"))
    srv = GUIServer((host, port), backend)
    url = f"http://127.0.0.1:{srv.server_address[1]}/#t={srv.token}"
    if not getattr(backend, "remote", False):
        # sin daemon: el propio servidor hace avanzar el motor (sin registrar sesiones)
        def ticker():
            import time
            while True:
                try:
                    backend.engine.tick()
                except Exception:  # noqa: BLE001
                    pass
                time.sleep(2)
        threading.Thread(target=ticker, daemon=True).start()
    print(_("GUI en {url}\n(el token va en el fragmento #; no compartas esta URL) · Ctrl-C para salir", url=url), flush=True)
    if open_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return url
