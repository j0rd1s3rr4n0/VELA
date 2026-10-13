"""Guardián de git: ficheros prohibidos, secretos genéricos, valores exactos del equipo y correo del autor.

Los secretos de prueba se construyen en tiempo de ejecución para que este fichero no los contenga."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from opsectools import gitguard

FAKE_KEY = "k" * 4 + "0123456789abcdef" * 2          # «clave de API» de este equipo (falsa)
FAKE_IP = ".".join(["203", "0", "113", "77"])        # «IP real» (rango de documentación)
GH = "gh" + "p_" + "A" * 36
EXACT = [("tu clave de API (virustotal)", re.compile(re.escape(FAKE_KEY))),
         ("tu IP real", re.compile(r"(?<![\w.])" + re.escape(FAKE_IP) + r"(?!\w|\.\d)"))]


class ScanTests(unittest.TestCase):
    def test_forbidden_paths(self):
        for p in (".devlogs/discover.json", "opsectools/__pycache__/x.pyc", "opsec.db", "opsec.db-wal",
                  "x/secrets.toml", "config.toml", "home/app-settings.toml", "GeoLite2-City.mmdb", ".env",
                  "wg0.conf", "mi.ovpn", "tor/control_auth_cookie", "id_ed25519"):
            self.assertIsNotNone(gitguard.check_path(p), p)
        for p in ("config.example.toml", "opsectools/data/basemap-osm.bin", "README.md", "tests/test_core.py"):
            self.assertIsNone(gitguard.check_path(p), p)

    def test_patterns_and_exact_values(self):
        data = (f'TOKEN = "{GH}"\nhost = {FAKE_IP}:443\nkey: {FAKE_KEY}\n'
                f'nada {FAKE_IP}5 ni 1{FAKE_IP}\n').encode()
        kinds = {(n, k) for _p, n, k in gitguard.scan_blob("f.py", data, EXACT)}
        self.assertIn((1, "token de GitHub"), kinds)
        self.assertIn((2, "tu IP real"), kinds)
        self.assertIn((3, "tu clave de API (virustotal)"), kinds)
        self.assertFalse(any(n == 4 for n, _ in kinds))             # no confunde IPs que solo la contienen

    def test_allow_marker_and_binary(self):
        line = f'example_token = "{GH}"  # {gitguard.ALLOW}'.encode()
        self.assertEqual(gitguard.scan_blob("f.py", line, EXACT), [])
        blob = b"\0bin" + FAKE_KEY.encode()                         # valores exactos también en binarios
        self.assertEqual([k for *_, k in gitguard.scan_blob("x.bin", blob, EXACT)], ["tu clave de API (virustotal)"])
        self.assertEqual(gitguard.scan_blob("x.bin", b"\0" + GH.encode(), EXACT), [])

    def test_email(self):
        self.assertIsNone(gitguard.email_problem("123+yo@users.noreply.github.com"))
        self.assertIn("quedará publicado", gitguard.email_problem("persona@gmail.com"))


class RepoTests(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.d.name)
        env = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.env = mock.patch.dict(os.environ, env)
        self.env.start()
        for c in (["init", "-q"], ["config", "user.email", "t@example.invalid"], ["config", "user.name", "t"]):
            subprocess.run(["git", *c], check=True)
        self.p = mock.patch.object(gitguard, "sensitive_values", lambda: EXACT)
        self.p.start()

    def tearDown(self):
        self.p.stop()
        self.env.stop()
        os.chdir(self.cwd)
        self.d.cleanup()

    def add(self, name, content):
        Path(name).parent.mkdir(parents=True, exist_ok=True)
        Path(name).write_text(content)
        subprocess.run(["git", "add", "-f", name], check=True)

    def test_pre_commit(self):
        self.add("ok.py", "print('hola')\n")
        self.assertEqual(gitguard.pre_commit(), 0)
        self.add("cfg.py", f"IP = '{FAKE_IP}'\n")
        self.add(".devlogs/x.txt", "x")
        with mock.patch("sys.stderr"):
            self.assertEqual(gitguard.pre_commit(), 1)

    def test_pre_push_scans_history(self):
        self.add("a.py", f"k = '{FAKE_KEY}'\n")
        subprocess.run(["git", "commit", "-qm", "1", "--no-verify"], check=True)
        Path("a.py").write_text("k = None\n")                      # borrado después: sigue en el historial
        subprocess.run(["git", "commit", "-qam", "2", "--no-verify"], check=True)
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        with mock.patch("sys.stderr"):
            self.assertEqual(gitguard.pre_push([f"refs/heads/main {head} refs/heads/main {gitguard.ZERO}"]), 1)


if __name__ == "__main__":
    unittest.main()
