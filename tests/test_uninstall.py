"""Desinstalación fácil: con un HOME falso; systemctl y la bandeja reales nunca se tocan."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import autostart, uninstall

APP_ID = uninstall.APP_ID
WRAPPER = "#!/bin/sh\nexec python3 -c 'from vela.cli import main' \"$@\"\n"


class UninstallTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        env = {k: v for k, v in os.environ.items() if not k.startswith(("XDG_", "VELA_"))}
        env.update({"HOME": str(self.home), "XDG_RUNTIME_DIR": str(self.home / "run")})
        p = mock.patch.dict(os.environ, env, clear=True)
        p.start()
        self.addCleanup(p.stop)
        # nada de systemctl ni de matar procesos de verdad
        for name in ("disable", "tray_disable"):
            m = mock.patch.object(autostart, name, return_value={})
            setattr(self, name, m.start())
            self.addCleanup(m.stop)
        m = mock.patch.object(autostart, "status", return_value={"available": True})
        m.start()
        self.addCleanup(m.stop)
        m = mock.patch.object(uninstall.subprocess, "run", wraps=uninstall.subprocess.run)
        self.sp = m.start()
        self.addCleanup(m.stop)
        self.install()

    def install(self):
        h = self.home
        pre = h / ".local/lib/vela"
        (pre / "vela").mkdir(parents=True)
        (pre / "vela/__init__.py").write_text('__version__ = "9"\n')
        (pre / "INSTALL.json").write_text("{}")
        (h / ".local/bin").mkdir(parents=True)
        for n in ("vela", "velad"):
            (h / ".local/bin" / n).write_text(WRAPPER)
        for f in (h / ".config/systemd/user/velad.service", h / ".config/autostart/vela-tray.desktop",
                  h / f".local/share/applications/{APP_ID}.desktop",
                  h / f".local/share/icons/hicolor/64x64/apps/{APP_ID}.png"):
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("x")
        for d in (h / ".config/vela", h / ".local/share/vela", h / ".local/state/vela", h / ".cache/vela"):
            d.mkdir(parents=True, exist_ok=True)
            (d / "algo").write_text("datos")

    def test_dry_run_changes_nothing(self):
        before = sorted(str(p) for p in self.home.rglob("*"))
        res = uninstall.run(dry_run=True)
        self.assertFalse(res["done"])
        self.assertEqual(sorted(str(p) for p in self.home.rglob("*")), before)
        self.disable.assert_not_called()

    def test_removes_program_keeps_data(self):
        res = uninstall.run()
        self.assertEqual(res["errors"], [])
        h = self.home
        for gone in (".local/lib/vela", ".local/bin/vela", ".local/bin/velad", ".config/systemd/user/velad.service",
                     ".config/autostart/vela-tray.desktop", f".local/share/applications/{APP_ID}.desktop",
                     f".local/share/icons/hicolor/64x64/apps/{APP_ID}.png"):
            self.assertFalse((h / gone).exists(), gone)
        for kept in (".config/vela/algo", ".local/share/vela/algo", ".local/state/vela/algo", ".cache/vela/algo"):
            self.assertTrue((h / kept).exists(), kept)
        self.disable.assert_called_once()
        self.tray_disable.assert_called_once()

    def test_purge_removes_data(self):
        uninstall.run(purge=True)
        for d in (".config/vela", ".local/share/vela", ".local/state/vela", ".cache/vela"):
            self.assertFalse((self.home / d).exists(), d)

    def test_foreign_command_with_same_name_is_kept(self):
        (self.home / ".local/bin/vela").write_text("#!/bin/sh\necho otro programa\n")
        uninstall.run()
        self.assertTrue((self.home / ".local/bin/vela").exists())

    def test_git_repo_prefix_is_never_deleted(self):
        (self.home / ".local/lib/vela/.git").mkdir()
        p = uninstall.plan()
        self.assertNotIn(self.home / ".local/lib/vela", p["dirs"])
        uninstall.run()
        self.assertTrue((self.home / ".local/lib/vela/vela/__init__.py").exists())

    def test_dangerous_prefix_refused(self):
        os.environ["VELA_PREFIX"] = str(self.home)
        (self.home / "vela").mkdir()
        (self.home / "vela/__init__.py").write_text("")
        p = uninstall.plan()
        self.assertNotIn(self.home, p["dirs"])
        uninstall.run()
        self.assertTrue(self.home.exists())

    def test_autoinstall_clone_removed_only_if_clean(self):
        if not shutil.which("git"):
            self.skipTest("git no disponible")
        clone = self.home / ".local/src/VELA"
        (clone / "vela").mkdir(parents=True)
        (clone / "vela/__init__.py").write_text("")
        (clone / "autoinstall.sh").write_text("")
        genv = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        import subprocess
        for args in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "x"]):
            subprocess.run(["git", *args], cwd=clone, env=genv, check=True, capture_output=True)
        (clone / "vela/__init__.py").write_text("# cambio local\n")
        self.assertNotIn(clone, uninstall.plan()["dirs"])
        subprocess.run(["git", "checkout", "-q", "--", "."], cwd=clone, env=genv, check=True)
        self.assertIn(clone, uninstall.plan()["dirs"])

    def test_no_systemctl_when_unit_is_not_ours(self):
        (self.home / ".config/systemd/user/velad.service").unlink()
        uninstall.run()
        self.disable.assert_not_called()

    def test_describe_lists_everything(self):
        text = "\n".join(uninstall.describe(uninstall.plan(purge=True)))
        self.assertIn("~/.local/lib/vela", text)
        self.assertIn("~/.config/vela", text)


if __name__ == "__main__":
    unittest.main()
