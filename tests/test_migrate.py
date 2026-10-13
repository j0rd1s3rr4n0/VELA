"""Migración del nombre anterior (opsectools/opsecd) a VELA sin perder datos ni lo que estaba activado."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import migrate


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        h = Path(self.d.name)
        self.h = h
        env = {"HOME": str(h), "XDG_CONFIG_HOME": str(h / ".config"), "XDG_DATA_HOME": str(h / ".local/share"),
               "XDG_STATE_HOME": str(h / ".local/state"), "XDG_CACHE_HOME": str(h / ".cache"),
               "XDG_RUNTIME_DIR": str(h / "run")}
        self.patches = [mock.patch.dict(os.environ, env),
                        mock.patch.object(migrate.Path, "home", lambda: h),
                        mock.patch.object(migrate, "OLD_TRAY", h / ".config/autostart/opsec-tray.desktop"),
                        mock.patch.object(migrate, "OLD_LAUNCHER", h / ".local/share/applications/old.desktop")]
        for p in self.patches:
            p.start()
        self.calls = []
        self.sysd = mock.patch.object(migrate, "_systemctl", lambda *a, **k: (self.calls.append(a), 0)[1])
        self.sysd.start()

    def tearDown(self):
        self.sysd.stop()
        for p in reversed(self.patches):
            p.stop()
        self.d.cleanup()

    def legacy(self):
        h = self.h
        (h / ".config/opsectools").mkdir(parents=True, mode=0o700)
        (h / ".config/opsectools/secrets.toml").write_text("[intel]\nvirustotal = 'x'\n")
        os.chmod(h / ".config/opsectools/secrets.toml", 0o600)
        (h / ".local/share/opsectools/map").mkdir(parents=True)
        for suf in ("", "-wal", "-shm"):
            (h / f".local/share/opsectools/opsec.db{suf}").write_text(f"db{suf}")
        (h / ".local/state/opsectools").mkdir(parents=True)
        (h / ".local/state/opsectools/opsecd.log").write_text("log")
        (h / ".cache/opsectools/map").mkdir(parents=True)
        (h / "run/opsectools").mkdir(parents=True)
        (h / "run/opsectools/opsecd.pid").write_text("999999999")      # pid inexistente: daemon parado
        (h / ".config/systemd/user").mkdir(parents=True)
        (h / ".config/systemd/user/opsecd.service").write_text("[Unit]\n")

    def test_moves_everything_and_reenables_service(self):
        self.legacy()
        with mock.patch("vela.autostart.enable", return_value={"ok": True}) as en:
            done = migrate.migrate()
        h = self.h
        self.assertTrue((h / ".config/vela/secrets.toml").exists())
        self.assertEqual(oct((h / ".config/vela/secrets.toml").stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct((h / ".config/vela").stat().st_mode & 0o777), "0o700")
        for suf in ("", "-wal", "-shm"):
            self.assertEqual((h / f".local/share/vela/vela.db{suf}").read_text(), f"db{suf}")
        self.assertTrue((h / ".local/state/vela/velad.log").exists())
        self.assertTrue((h / ".cache/vela/map").is_dir())
        self.assertFalse((h / ".config/opsectools").exists())
        self.assertFalse((h / "run/opsectools").exists())
        self.assertFalse((h / ".config/systemd/user/opsecd.service").exists())
        self.assertIn(("disable", "--now", "opsecd.service"), self.calls)
        en.assert_called_once()                                    # estaba habilitado → el nuevo también
        self.assertTrue(any("vela.db" in m for m in done))
        self.assertEqual(migrate.migrate(), [])                    # idempotente

    def test_does_nothing_while_old_daemon_runs(self):
        self.legacy()
        (self.h / "run/opsectools/opsecd.pid").write_text(str(os.getpid()))
        done = migrate.migrate()
        self.assertIn("sigue en marcha", done[0])
        self.assertTrue((self.h / ".local/share/opsectools/opsec.db").exists())
        self.assertEqual(self.calls, [])

    def test_never_overwrites_new_data(self):
        self.legacy()
        (self.h / ".config/vela").mkdir(parents=True)
        (self.h / ".config/vela/config.toml").write_text("nuevo")
        with mock.patch("vela.autostart.enable", return_value={"ok": True}):
            done = migrate.migrate()
        self.assertEqual((self.h / ".config/vela/config.toml").read_text(), "nuevo")
        self.assertTrue((self.h / ".config/opsectools/secrets.toml").exists())
        self.assertTrue(any("se conserva" in m for m in done))


if __name__ == "__main__":
    unittest.main()
