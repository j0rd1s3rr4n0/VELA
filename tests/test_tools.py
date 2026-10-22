"""Utilidades nuevas: backup, dependencias, anomalías, OCR, traducción, TZ, MAC, DNS y About.

Todos los tests usan mocks o modos secos: no tocan red, pkexec, DNS, MAC ni la pantalla real.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vela import about, anomaly, applaunch, backup, deps, dnsfix, mac, ocr, translate
from vela.store import Store


class FakeEngine:
    def __init__(self, store):
        self.store = store
        self.cfg = {"active_profile": "default", "leakwatch": {"allow": []}, "anomaly": {"enabled": True}}
        self.actor = "test"
        self.net = None
        self.net_rates = {}
        self.geo = mock.Mock()
        self.geo.lookup.return_value = {"country": "ES"}


class BackupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "vela.db")
        self.engine = FakeEngine(self.store)
        self.store.add_event("test", "info", {"x": 1})
        self.store.put("hello", "world")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_export_and_import_json(self):
        dest = Path(self.tmp.name) / "b.json"
        r = backup.export_bundle(self.engine, dest, {"history": True})
        self.assertTrue(r["ok"])
        self.assertTrue(dest.exists())
        self.assertEqual(dest.stat().st_mode & 0o777, 0o600)
        info = backup.inspect_bundle(dest)
        self.assertTrue(info["has"]["history"])
        # borrar y volver a importar
        self.store.reset(everything=True)
        self.assertEqual(self.store.count("events"), 0)
        r2 = backup.import_bundle(self.engine, dest, mode="merge", include={"history": True})
        self.assertGreaterEqual(r2["history"]["imported"]["events"], 1)
        self.assertGreaterEqual(self.store.count("events"), 1)

    def test_export_zip_roundtrip(self):
        dest = Path(self.tmp.name) / "b.zip"
        r = backup.export_bundle(self.engine, dest, {"history": True, "settings": False})
        self.assertTrue(r["ok"])
        self.assertTrue(dest.exists())
        info = backup.inspect_bundle(dest)
        self.assertTrue(info["has"]["history"])

    def test_bad_backup_rejected(self):
        p = Path(self.tmp.name) / "bad.json"
        p.write_text(json.dumps({"manifest": {"app": "OTRA"}}))
        with self.assertRaises(ValueError):
            backup.inspect_bundle(p)

    def test_reset_history_and_all(self):
        r = backup.reset(self.engine, "history")
        self.assertEqual(r["scope"], "history")
        self.assertEqual(self.store.count("events"), 0)
        self.assertEqual(self.store.get("hello"), "world")   # kv se conserva


class DepsTests(unittest.TestCase):
    def test_status_and_plan(self):
        st = deps.status("ocr")
        self.assertIn("title", st)
        pl = deps.plan("ocr")
        self.assertIn("command", pl)
        self.assertIsInstance(pl["packages"], list)

    def test_install_requires_confirmation(self):
        with mock.patch.object(deps, "plan", return_value={"features": ["x"], "packages": ["p"],
                                                           "command": ["apt-get", "install", "-y", "p"],
                                                           "family": "deb", "can_install": True,
                                                           "pkexec": True, "sudo": True}):
            r = deps.install("x", yes=False)
            self.assertFalse(r["ok"])
            self.assertIn("confirmación", r["error"])

    def test_feature_unknown(self):
        with self.assertRaises(KeyError):
            deps.status("nope")


class AnomalyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "vela.db")

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_detect_traffic_and_fanout(self):
        import time
        t = time.time()
        for i in range(30):
            self.store.add_metric("flows", 5, meta={"processes": [{"name": "firefox", "flows": 2}],
                                                     "countries": [{"cc": "ES", "flows": 1}],
                                                     "ports": [{"port": 443, "flows": 1}],
                                                     "edges": [{"edge": "1.1.1.1:443", "flows": 1}]}, ts=t - 1800 + i * 60)
            self.store.add_metric("tx_bps", 1000, ts=t - 1800 + i * 60)
            self.store.add_metric("rx_bps", 1000, ts=t - 1800 + i * 60)
            self.store.add_metric("max_fanout", 2, ts=t - 1800 + i * 60)
        self.store.add_metric("flows", 40, meta={"processes": [{"name": "nuevo", "flows": 20}],
                                                 "countries": [{"cc": "RU", "flows": 9}],
                                                 "ports": [{"port": 4444, "flows": 8}],
                                                 "edges": [{"edge": "2.2.2.2:4444", "flows": 6}]}, ts=t)
        self.store.add_metric("tx_bps", 5_000_000, ts=t)
        self.store.add_metric("rx_bps", 1_000, ts=t)
        self.store.add_metric("max_fanout", 20, ts=t)
        found = anomaly.detect(self.store, "alta")
        types = {x["type"] for x in found}
        self.assertIn("traffic_spike", types)
        self.assertIn("connection_spike", types)
        self.assertIn("fanout", types)
        self.assertTrue(any(t in types for t in ("new_process", "new_country", "rare_port")))

    def test_detect_empty(self):
        self.assertEqual(anomaly.detect(self.store), [])


class TextTests(unittest.TestCase):
    def test_chunks_respect_size(self):
        text = "\n\n".join("frase " * 20 for _ in range(20))
        parts = translate._chunks(text, 300)
        self.assertTrue(parts)
        self.assertTrue(all(len(p) <= 300 for p in parts))

    def test_clean(self):
        self.assertEqual(translate._clean("```\nHola\n```"), "Hola")
        self.assertEqual(translate._clean("Translation: Hola"), "Hola")

    def test_bad_target(self):
        with self.assertRaises(translate.TranslationError):
            translate.translate("hola", "auto")
        with self.assertRaises(translate.TranslationError):
            translate.translate("hola", "xx")

    def test_ollama_call(self):
        cfg = {"translate": {"engine": "ollama", "endpoint": "http://127.0.0.1:11434",
                             "model": "m", "timeout": "10s", "max_chars": 100},
               "consent": {}}
        st = {"ok": True, "engine": "ollama", "endpoint": "http://127.0.0.1:11434", "model": "m",
              "models": ["m"], "local": True}
        with mock.patch.object(translate, "status", return_value=st), \
                mock.patch.object(translate, "_post", return_value={"message": {"content": "Hello"}}) as post:
            r = translate.translate("Hola", target="en", cfg=cfg)
        self.assertEqual(r["text"], "Hello")
        self.assertEqual(post.call_args.args[1]["model"], "m")


class OcrTests(unittest.TestCase):
    def test_copy_uri(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "a.png"
            src.write_bytes(b"x")
            dst = Path(d) / "b.png"
            ocr._copy_uri("file://" + str(src), dst)
            self.assertEqual(dst.read_bytes(), b"x")

    def test_portal_uri_can_be_a_single_string(self):
        # Algunos portales devuelven "uri" como cadena, no como lista de cadenas.
        self.assertEqual(ocr.uri_list("file:///tmp/a.png"), ["file:///tmp/a.png"])
        self.assertEqual(ocr.uri_list(["file:///a", "file:///b"]), ["file:///a", "file:///b"])
        self.assertEqual(ocr.uri_list(None), [])

    def test_copy_uri_accepts_plain_path(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "a.png"
            src.write_bytes(b"x")
            dst = Path(d) / "b.png"
            ocr._copy_uri(str(src), dst)
            self.assertEqual(dst.read_bytes(), b"x")

    def test_missing_tesseract(self):
        with mock.patch.object(ocr, "which", return_value=None):
            with self.assertRaises(ocr.OcrError):
                ocr.ocr_image("/tmp/no.png")


class LaunchTests(unittest.TestCase):
    def test_timezone_validation(self):
        self.assertEqual(applaunch.validate_timezone("UTC"), "UTC")
        with self.assertRaises(ValueError):
            applaunch.validate_timezone("Marte/Olympus")

    def test_dry_run_launch(self):
        app = {"id": "x", "name": "X", "exec": ["echo", "hola"], "terminal": False, "dbus": False}
        r = applaunch.launch(app, "UTC", dry_run=True)
        self.assertTrue(r["dry_run"])
        self.assertEqual(r["command"], ["echo", "hola"])

    def test_dry_run_command(self):
        r = applaunch.launch_command("echo hola", "Europe/Madrid", dry_run=True)
        self.assertEqual(r["command"], ["echo", "hola"])


class MacTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(mac.validate_mac("02:11:22:33:44:55"), "02:11:22:33:44:55")
        with self.assertRaises(mac.MacError):
            mac.validate_mac("01:11:22:33:44:55")
        with self.assertRaises(mac.MacError):
            mac.validate_mac("no")

    def test_random_is_local_unicast(self):
        value = mac.random_mac()
        first = int(value.split(":")[0], 16)
        self.assertFalse(first & 1)
        self.assertTrue(first & 2)

    def test_interfaces_has_lo_excluded(self):
        for i in mac.interfaces():
            self.assertNotEqual(i["name"], "lo")


class DnsTests(unittest.TestCase):
    def test_dot_plan_content(self):
        p = dnsfix.plan("dot", "cloudflare")
        self.assertIn("DNSOverTLS=yes", p["content"])
        self.assertIn("cloudflare-dns.com", p["content"])

    def test_bad_transport(self):
        with self.assertRaises(dnsfix.DnsFixError):
            dnsfix.plan("xxx")

    def test_doh_requires_cloudflared(self):
        with mock.patch.object(dnsfix, "which", return_value=None):
            with self.assertRaises(dnsfix.DnsFixError):
                dnsfix.plan("doh", "cloudflare")


class AboutTests(unittest.TestCase):
    def test_offline_profile(self):
        p = about.profile(refresh=False)
        self.assertEqual(p["login"], "j0rd1s3rr4n0")
        self.assertIn("name", p)
        info = about.app_info()
        self.assertEqual(info["name"], "VELA")
        self.assertIn("credits", info)

    def test_sync_disabled_by_default(self):
        p = about.profile(refresh=True)
        self.assertIn("error", p)


if __name__ == "__main__":
    unittest.main()
