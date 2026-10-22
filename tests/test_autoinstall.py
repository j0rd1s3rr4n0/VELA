"""Autoinstalador de una línea: sintaxis, URL raw y ausencia de rutas de usuario fijas."""

import subprocess
import unittest
from pathlib import Path


class AutoinstallTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", "autoinstall.sh"], check=True)

    def test_uses_raw_url_and_installer(self):
        text = Path("autoinstall.sh").read_text(encoding="utf-8")
        self.assertIn("raw.githubusercontent.com/j0rd1s3rr4n0/VELA/master/autoinstall.sh", text)
        self.assertIn("./install.sh", text)
        self.assertIn("--with-all", text)

    def test_no_hardcoded_user_home(self):
        text = Path("autoinstall.sh").read_text(encoding="utf-8")
        self.assertNotIn("/home/", text)
        self.assertIn("${HOME}", text)

    def test_installer_is_executable(self):
        mode = Path("autoinstall.sh").stat().st_mode
        self.assertTrue(mode & 0o111)


if __name__ == "__main__":
    unittest.main()
