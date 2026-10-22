"""Invalidación inmediata del estado tras acciones que cambian el sistema."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import ipc
from vela.engine import Engine
from vela.store import Store

from .helpers import cfg


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.e = Engine(cfg(), store=Store(memory=True), track=False)

    def tearDown(self):
        self.e.close()

    def test_refresh_ipc_is_whitelisted(self):
        self.assertIn("refresh", ipc.METHODS)

    def test_invalidate_dns_clears_cache_and_runs_leaks(self):
        self.e.dns = {"encrypted": False}
        self.e.findings = [{"check": "dns_plaintext"}]
        with mock.patch.object(self.e, "refresh_dns") as rd, \
                mock.patch.object(self.e, "refresh_networks"), \
                mock.patch.object(self.e, "run_leaks") as rl, \
                mock.patch.object(self.e, "update_sessions"), \
                mock.patch.object(self.e, "build_obs", return_value={}), \
                mock.patch.object(self.e, "emit"):
            r = self.e.invalidate("dns")
        self.assertIsNone(self.e.dns)
        self.assertEqual(self.e.findings, [])
        rd.assert_called_once()
        rl.assert_called_once()
        self.assertEqual(r["revision"], 1)
        self.assertIn("dns", r["domains"])

    def test_invalidate_network_refreshes_dns_and_networks(self):
        with mock.patch.object(self.e, "refresh_network") as rn, \
                mock.patch.object(self.e, "refresh_networks") as rw, \
                mock.patch.object(self.e, "run_leaks"), \
                mock.patch.object(self.e, "update_sessions"), \
                mock.patch.object(self.e, "build_obs", return_value={}), \
                mock.patch.object(self.e, "emit"):
            self.e.invalidate("network")
        rn.assert_called_once()
        rw.assert_called_once()

    def test_invalidate_unknown_domain(self):
        with self.assertRaises(ValueError):
            self.e.invalidate("inventado")

    def test_api_refresh_returns_status_and_fixes(self):
        with mock.patch.object(self.e, "invalidate") as inv, \
                mock.patch.object(self.e, "api_status", return_value={"revision": 7}), \
                mock.patch.object(self.e, "api_fixes", return_value=[{"title": "x"}]):
            r = self.e.api_refresh(["dns", "leaks"])
        inv.assert_called_once_with("dns", "leaks")
        self.assertEqual(r["status"]["revision"], 7)
        self.assertEqual(r["fixes"], [{"title": "x"}])

    def test_fixes_never_use_stale_findings(self):
        self.e.findings = [{"check": "dns_plaintext", "title": "viejo"}]
        with mock.patch.object(self.e, "ensure_fresh"), \
                mock.patch.object(self.e, "run_leaks", return_value=[]) as rl:
            out = self.e.api_fixes()
        rl.assert_called_once()
        self.assertEqual(out, [])

    def test_settings_dns_invalidates_dns_and_leaks(self):
        d = Path(tempfile.mkdtemp())
        old = {k: os.environ.get(k) for k in ("VELA_SETTINGS", "VELA_CONFIG")}
        os.environ["VELA_SETTINGS"] = str(d / "app-settings.toml")
        os.environ["VELA_CONFIG"] = str(d / "config.toml")
        try:
            with mock.patch.object(self.e, "invalidate") as inv:
                self.e.api_settings_set({"dns.fix_transport": "doh"})
            called = set(inv.call_args.args)
            self.assertIn("dns", called)
            self.assertIn("leaks", called)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    unittest.main()
