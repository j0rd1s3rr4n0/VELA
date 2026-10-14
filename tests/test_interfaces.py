"""Comunicación motor ↔ IPC ↔ CLI/TUI/GUI."""

import http.client
import json
import os
import queue
import tempfile
import threading
import unittest
from unittest import mock
from pathlib import Path

from vela import cli, ipc
from vela.engine import Engine
from vela.gui.server import GUIServer
from vela.store import Store

from .helpers import cfg

TMP = os.environ.get("TMPDIR") or None


class IPCTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))
        self.engine = Engine(cfg(), store=Store(memory=True), actor="test", track=True)
        self.srv = ipc.IPCServer(self.engine, self.dir / "s" / "velad.sock").start()
        self.client = ipc.Client(self.srv.path, timeout=10)

    def tearDown(self):
        self.srv.stop()

    def test_permissions(self):
        self.assertEqual(os.stat(self.srv.path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(self.srv.path.parent).st_mode & 0o777, 0o700)

    def test_calls(self):
        self.assertEqual(self.client.call("profiles")["active"], "default")
        self.assertEqual(self.client.call("sessions"), [])
        self.engine.store.open_interval(None, "default", "tor_exit", "E1", "exit1")
        rows = self.client.call("counters", layer="tor_exit")
        self.assertEqual(rows[0]["key"], "E1")
        self.assertRegex(rows[0]["current_fmt"], r"^\d\dd \d\dh \d\dm \d\ds$")

    def test_whitelist_and_errors(self):
        with self.assertRaises(ipc.IPCError):
            self.client.call("__init__")
        with self.assertRaises(ipc.IPCError):
            self.client.call("store")
        with self.assertRaises(ipc.IPCError):
            self.client.call("profile_activate", name="no-existe")

    def test_profile_activation_audited(self):
        self.engine.cfg["profiles"]["anon"] = {"description": "x", "use_tor": True}
        self.engine.net = None
        self.engine.update_sessions = lambda: None      # sin red real en la prueba
        self.client.call("profile_activate", name="anon")
        self.assertEqual(self.engine.cfg["active_profile"], "anon")
        self.assertEqual(self.engine.store.audit_log()[0]["action"], "profile_activate")

    def test_subscribe_receives_events(self):
        got = queue.Queue()

        def listen():
            for ev in ipc.Client(self.srv.path).subscribe():
                got.put(ev)
                break
        threading.Thread(target=listen, daemon=True).start()
        for _ in range(50):
            if self.engine.subscribers:
                break
            threading.Event().wait(0.05)
        self.engine.emit("prueba", "high", {"x": 1})
        ev = got.get(timeout=5)
        self.assertEqual((ev["kind"], ev["severity"], ev["data"]), ("prueba", "high", {"x": 1}))

    def test_second_daemon_refused(self):
        with self.assertRaises(ipc.IPCError):
            ipc.IPCServer(self.engine, self.srv.path)


class FakeBackend:
    remote = True

    def call(self, method, **params):
        if method == "boom":
            raise RuntimeError("x")
        return {"method": method, "params": params}

    def subscribe(self):
        yield {"kind": "k"}


class GUITests(unittest.TestCase):
    def setUp(self):
        self.srv = GUIServer(("127.0.0.1", 0), FakeBackend())
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.port = self.srv.server_address[1]

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": f"127.0.0.1:{self.port}", "Content-Type": "application/json", **(headers or {})}
        c.request(method, path, body=json.dumps(body or {}) if method == "POST" else None, headers=h)
        r = c.getresponse()
        return r.status, r.read(), dict(r.getheaders())

    def test_static_and_csp(self):
        code, body, headers = self.req("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"VELA", body)
        self.assertIn("script-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn(b"http://", body.replace(b"http://www.w3.org", b""))     # sin recursos externos
        self.assertEqual(self.req("GET", "/../server.py")[0], 404)

    def test_theme_css(self):
        """Los colores de la GUI web salen del tema elegido en Ajustes (sin token: no es información sensible)."""
        with mock.patch.dict(os.environ, {"VELA_THEME": "obsidian"}):
            code, body, headers = self.req("GET", "/theme.css")
        self.assertEqual(code, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/css"))
        self.assertIn(b"VELA Obsidian", body)
        self.assertIn(b':root[data-theme="light"]', body)
        self.assertIn(b'href="theme.css"', self.req("GET", "/")[1])

    def test_token_required(self):
        self.assertEqual(self.req("POST", "/api/status")[0], 401)
        self.assertEqual(self.req("POST", "/api/status", headers={"X-VELA-Token": "malo"})[0], 401)
        code, body, _ = self.req("POST", "/api/status", {"x": 1}, {"X-VELA-Token": self.srv.token})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["result"], {"method": "status", "params": {"x": 1}})

    def test_dns_rebinding_and_csrf(self):
        tok = {"X-VELA-Token": self.srv.token}
        self.assertEqual(self.req("POST", "/api/status", headers={**tok, "Host": "evil.example"})[0], 403)
        self.assertEqual(self.req("POST", "/api/status", headers={**tok, "Origin": "http://evil.example"})[0], 403)

    def test_unknown_method_and_get_api(self):
        tok = {"X-VELA-Token": self.srv.token}
        self.assertEqual(self.req("POST", "/api/nope", headers=tok)[0], 404)
        self.assertEqual(self.req("GET", "/api/status")[0], 405)

    def test_loopback_only(self):
        from vela.gui.server import serve
        with self.assertRaises(ValueError):
            serve(FakeBackend(), host="0.0.0.0", open_browser=False)


class CLITests(unittest.TestCase):
    def test_parser_covers_commands(self):
        p = cli.build_parser()
        for argv in (["status"], ["discover", "--json"], ["network"], ["vpn", "list"], ["proxy", "list"],
                     ["tor", "status"], ["dns", "check"], ["sessions"], ["history"], ["rotate", "--dry-run"],
                     ["rotate", "tor", "--dry-run"], ["leaks", "check"], ["profiles"], ["audit"], ["doctor"],
                     ["gui", "--no-browser"], ["tui"], ["counters", "--layer", "tor_exit"], ["export", "--out", "x"],
                     ["killswitch", "preview"], ["panic"], ["stats", "--period", "day"]):
            a = p.parse_args(argv)
            self.assertTrue(callable(a.fn), argv)

    def test_json_flag(self):
        a = cli.build_parser().parse_args(["--json", "status"])
        self.assertTrue(a.json)
        a = cli.build_parser().parse_args(["status", "--json"])
        self.assertTrue(a.json_sub)


if __name__ == "__main__":
    unittest.main()
