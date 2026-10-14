"""Actualizaciones: con un remoto git local (sin red) y la política de rutas Tor > VPN > directo."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from vela import updater

GIT = shutil.which("git")


def git(cwd, *args):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


@unittest.skipUnless(GIT, "git no disponible")
class UpdaterGitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.env_backup = dict(os.environ)
        os.environ.update({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"})
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.env_backup)))
        self.remote = self.tmp / "remote.git"
        git(self.tmp, "init", "-q", "--bare", "-b", "master", str(self.remote))
        self.dev = self.tmp / "dev"
        git(self.tmp, "clone", "-q", str(self.remote), str(self.dev))
        (self.dev / "vela").mkdir()
        (self.dev / "vela" / "__init__.py").write_text('__version__ = "1.0.0"\n')
        (self.dev / "install.sh").write_text("#!/bin/sh\nexit 0\n")
        git(self.dev, "add", "-A")
        git(self.dev, "commit", "-q", "-m", "inicial")
        git(self.dev, "push", "-q", "origin", "HEAD:master")
        self.src = self.tmp / "src"                       # el clon del usuario
        git(self.tmp, "clone", "-q", str(self.remote), str(self.src))
        self.prefix = self.tmp / "prefix"                 # la instalación (~/.local/lib/vela)
        (self.prefix / "vela").mkdir(parents=True)
        updater.write_manifest(self.prefix, self.src)
        self.installs = []

    def push_change(self, version="1.1.0", msg="mejora"):
        (self.dev / "vela" / "__init__.py").write_text(f'__version__ = "{version}"\n')
        git(self.dev, "commit", "-qam", msg)
        git(self.dev, "push", "-q", "origin", "HEAD:master")

    def installer(self, src):
        self.installs.append(src)
        updater.write_manifest(self.prefix, src)

    def test_manifest_and_status(self):
        man = json.loads((self.prefix / "INSTALL.json").read_text())
        self.assertEqual(man["source"], str(self.src))
        self.assertEqual(man["version"], "1.0.0")
        st = updater.status(self.prefix)
        self.assertTrue(st["git"])
        self.assertEqual(st["upstream"], "origin/master")
        self.assertFalse(st["dirty"])
        self.assertFalse(st["pending_install"])

    def test_check_does_not_modify_anything(self):
        self.push_change()
        head = git(self.src, "rev-parse", "HEAD")
        res = updater.check("auto", root=self.prefix)
        self.assertEqual(res["route"], "local")
        self.assertEqual((res["behind"], res["ahead"]), (1, 0))
        self.assertEqual(res["commits"][0]["subject"], "mejora")
        self.assertEqual(res["new_version"], "1.1.0")
        self.assertTrue(res["can_update"])
        self.assertEqual(git(self.src, "rev-parse", "HEAD"), head)          # solo fetch
        self.assertEqual(self.installs, [])

    def test_apply_fast_forwards_and_reinstalls(self):
        self.push_change()
        res = updater.apply("auto", root=self.prefix, installer=self.installer)
        self.assertTrue(res["updated"])
        self.assertEqual(self.installs, [self.src])
        self.assertIn('"1.1.0"', (self.src / "vela" / "__init__.py").read_text())
        self.assertIn(res["from_commit"], res["rollback"])
        self.assertEqual(updater.read_manifest(self.prefix)["version"], "1.1.0")

    def test_up_to_date(self):
        res = updater.apply("auto", root=self.prefix, installer=self.installer)
        self.assertFalse(res["updated"])
        self.assertEqual(self.installs, [])

    def test_refuses_with_local_changes(self):
        self.push_change()
        (self.src / "vela" / "__init__.py").write_text('__version__ = "mio"\n')
        with self.assertRaises(updater.UpdateError):
            updater.apply("auto", root=self.prefix, installer=self.installer)
        self.assertEqual((self.src / "vela" / "__init__.py").read_text(), '__version__ = "mio"\n')
        self.assertEqual(self.installs, [])

    def test_refuses_when_diverged(self):
        self.push_change()
        (self.src / "nota.txt").write_text("x")
        git(self.src, "add", "nota.txt")
        git(self.src, "commit", "-qm", "local")
        with self.assertRaises(updater.UpdateError):
            updater.apply("auto", root=self.prefix, installer=self.installer)
        self.assertTrue((self.src / "nota.txt").exists())

    def test_pending_install_after_manual_pull(self):
        self.push_change()
        git(self.src, "pull", "-q", "--ff-only")
        st = updater.status(self.prefix)
        self.assertTrue(st["pending_install"])
        res = updater.apply("auto", root=self.prefix, installer=self.installer)
        self.assertTrue(res["updated"])
        self.assertEqual(self.installs, [self.src])

    def test_no_git_source(self):
        plain = self.tmp / "plain"
        (plain / "vela").mkdir(parents=True)
        (self.prefix / "INSTALL.json").write_text(json.dumps({"source": str(plain), "version": "1.0.0"}))
        st = updater.status(self.prefix)
        self.assertFalse(st["git"])
        self.assertTrue(st["hint"])
        with self.assertRaises(updater.UpdateError):
            updater.check("auto", root=self.prefix)


class RouteTests(unittest.TestCase):
    """Nunca sale con tu IP real salvo que lo pidas (--via direct)."""
    URL = "https://github.com/example/VELA.git"

    def env(self, socks=None, egress_kind="ethernet"):
        return {"tor": {"socks": socks or []}, "interfaces": [{"name": "eth0", "kind": egress_kind}],
                "egress": {"ipv4": "eth0"}}

    def test_tor_preferred(self):
        route, cfg = updater.git_proxy_config(self.URL, "auto", self.env(socks=[9050]))
        self.assertEqual(route, "tor")
        self.assertEqual(cfg, ["http.proxy=socks5h://127.0.0.1:9050"])   # socks5h: el DNS también por Tor

    def test_vpn_without_proxy(self):
        self.assertEqual(updater.git_proxy_config(self.URL, "auto", self.env(egress_kind="wireguard")), ("vpn", []))

    def test_no_tor_no_vpn_refuses_direct(self):
        with self.assertRaises(OSError):
            updater.git_proxy_config(self.URL, "auto", self.env())

    def test_direct_only_when_asked(self):
        self.assertEqual(updater.git_proxy_config(self.URL, "direct", self.env()), ("direct", []))

    def test_tor_needs_https_remote(self):
        with self.assertRaises(updater.UpdateError):
            updater.git_proxy_config("git@github.com:example/VELA.git", "tor", self.env(socks=[9050]))

    def test_local_remote_needs_no_route(self):
        self.assertEqual(updater.git_proxy_config("/srv/git/vela.git", "auto", self.env()), ("local", []))


if __name__ == "__main__":
    unittest.main()
