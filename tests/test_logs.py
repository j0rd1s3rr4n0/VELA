"""Logs de auditoría y errores: escritura, lectura, borrado y rotación básica."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import logs
from vela.store import Store


class LogsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = self.tmp.name

    def tearDown(self):
        if self.old is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self.old
        self.tmp.cleanup()

    def test_audit_and_errors_are_separate(self):
        logs.audit("test", "dns_encrypt", {"ok": True})
        logs.error("fallo de prueba", ValueError("boom"), {"step": "x"})
        audit = logs.read("audit")["audit"]
        errors = logs.read("errors")["errors"]
        self.assertEqual(audit[0]["action"], "dns_encrypt")
        self.assertEqual(errors[0]["message"], "fallo de prueba")
        self.assertEqual(errors[0]["type"], "ValueError")
        self.assertIn("boom", errors[0]["exception"])
        self.assertTrue(logs.audit_path().exists())
        self.assertTrue(logs.errors_path().exists())

    def test_read_returns_newest_first(self):
        logs.audit("a", "one")
        logs.audit("a", "two")
        self.assertEqual([x["action"] for x in logs.read("audit")["audit"]], ["two", "one"])

    def test_clear_only_selected(self):
        logs.audit("a", "one")
        logs.error("boom")
        logs.clear("errors")
        self.assertEqual(logs.read("errors")["errors"], [])
        self.assertTrue(logs.read("audit")["audit"])

    def test_store_audit_writes_file_on_disk(self):
        st = Store(Path(self.tmp.name) / "vela.db")
        try:
            with mock.patch.dict(os.environ, {"VELA_NO_AUDIT_FILE": "0"}):
                st.audit("test", "action", {"x": 1})
            self.assertTrue(logs.audit_path().exists())
            self.assertEqual(logs.read("audit")["audit"][0]["action"], "action")
        finally:
            st.close()

    def test_memory_store_does_not_write_audit_file(self):
        st = Store(memory=True)
        try:
            st.audit("test", "memory")
            self.assertFalse(logs.audit_path().exists())
        finally:
            st.close()


if __name__ == "__main__":
    unittest.main()
