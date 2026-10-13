"""Ajustes persistentes desde la app, claves de API y arranque con la sesión."""

import os
import tempfile
import tomllib
import unittest
from pathlib import Path

from vela import autostart, config, intel
from vela.engine import Engine
from vela.store import Store

from .helpers import cfg

TMP = os.environ.get("TMPDIR") or None


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(dir=TMP))
        os.environ["VELA_SETTINGS"] = str(self.dir / "app-settings.toml")
        os.environ["VELA_CONFIG"] = str(self.dir / "config.toml")
        (self.dir / "config.toml").write_text("# mi comentario\n[consent]\ntor_ip_checks = true\n")

    def tearDown(self):
        del os.environ["VELA_SETTINGS"]
        del os.environ["VELA_CONFIG"]

    def test_coerce_and_whitelist(self):
        self.assertTrue(config.coerce_setting("consent.allow_killswitch", True))
        with self.assertRaises(KeyError):
            config.coerce_setting("gui.host", "0.0.0.0")          # no se puede abrir la GUI a la red desde la app
        with self.assertRaises(ValueError):
            config.coerce_setting("leakwatch.on_leak", "borrar_todo")
        with self.assertRaises(ValueError):
            config.coerce_setting("monitor.public_ip_interval", "pronto")
        self.assertEqual(config.coerce_setting("storage.retention_days", "30"), 30)

    def test_engine_settings_persist_and_apply_live(self):
        e = Engine(cfg(), store=Store(memory=True), track=False)
        res = e.api_settings_set({"consent.threat_intel_lookups": True, "leakwatch.on_leak": "killswitch",
                                  "public_ip.realtime_interval": "30s"})
        self.assertTrue(e.cfg["consent"]["threat_intel_lookups"])        # aplicado en caliente
        self.assertEqual(e.pubip.cfg["consent"]["threat_intel_lookups"], True)   # mismo dict compartido
        saved = tomllib.loads(Path(res["saved"]).read_text())
        self.assertEqual(saved["leakwatch"]["on_leak"], "killswitch")
        self.assertEqual(os.stat(res["saved"]).st_mode & 0o777, 0o600)
        loaded = config.load()                                            # sobrevive a un reinicio
        self.assertTrue(loaded["consent"]["threat_intel_lookups"])
        self.assertTrue(loaded["consent"]["tor_ip_checks"])
        self.assertIn("# mi comentario", (self.dir / "config.toml").read_text())   # config.toml intacto
        self.assertIn("settings_set", [a["action"] for a in e.store.audit_log()])
        g = e.api_settings_get()
        self.assertEqual(g["values"]["public_ip.realtime_interval"], "30s")

    def test_rejects_invalid_without_writing(self):
        e = Engine(cfg(), store=Store(memory=True), track=False)
        with self.assertRaises(ValueError):
            e.api_settings_set({"storage.retention_days": -1})
        self.assertFalse((self.dir / "app-settings.toml").exists())


class KeysAndAutostartTests(unittest.TestCase):
    def test_delete_key(self):
        d = tempfile.mkdtemp(dir=TMP)
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = d
        try:
            intel.save_key("virustotal", "aaa")
            intel.save_key("shodan", "bbb")
            self.assertTrue(intel.delete_key("virustotal"))
            self.assertFalse(intel.delete_key("virustotal"))
            self.assertEqual(intel.load_keys(), {"shodan": "bbb"})
            self.assertEqual(os.stat(intel.secrets_path()).st_mode & 0o777, 0o600)
        finally:
            if old is None:
                del os.environ["XDG_CONFIG_HOME"]
            else:
                os.environ["XDG_CONFIG_HOME"] = old

    def test_tray_autostart_file(self):
        home = tempfile.mkdtemp(dir=TMP)
        old = os.environ["HOME"]
        os.environ["HOME"] = home
        try:
            p = autostart.tray_enable(start_now=False)
            text = Path(p).read_text()
            self.assertIn("-m vela tray", text)
            self.assertTrue(autostart.tray_autostart_enabled())
            autostart.tray_disable(stop_now=False)
            self.assertFalse(autostart.tray_autostart_enabled())
        finally:
            os.environ["HOME"] = old

    def test_unit_text(self):
        t = autostart.unit_text()
        self.assertIn("-m vela daemon run", t)
        self.assertIn("WantedBy=default.target", t)
        self.assertIn("Restart=on-failure", t)


if __name__ == "__main__":
    unittest.main()
