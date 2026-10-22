"""Estado de notificaciones: activas, silencio temporal e indefinido."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import notifications


class NotificationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("XDG_CONFIG_HOME", None)
        else:
            os.environ["XDG_CONFIG_HOME"] = self.old
        self.tmp.cleanup()

    def test_enable_and_indefinite(self):
        notifications.enable()
        self.assertTrue(notifications.allowed())
        notifications.disable()
        self.assertFalse(notifications.allowed())
        st = notifications.status()
        self.assertTrue(st["indefinite"])
        self.assertIn("indefinid", notifications.describe(st))

    def test_temporary_mute_expires(self):
        with mock.patch.object(notifications, "now", return_value=1000.0):
            notifications.mute(60)
            self.assertFalse(notifications.allowed())
            self.assertAlmostEqual(notifications.status()["remaining"], 60.0, places=1)
        with mock.patch.object(notifications, "now", return_value=1061.0):
            self.assertTrue(notifications.allowed())
            self.assertFalse(notifications.status()["muted"])

    def test_state_file_is_private(self):
        notifications.mute(60)
        p = Path(notifications.path())
        self.assertTrue(p.exists())
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_reactivate(self):
        notifications.mute(None)
        self.assertFalse(notifications.allowed())
        notifications.enable()
        self.assertTrue(notifications.allowed())


if __name__ == "__main__":
    unittest.main()
