"""Geolocalización + puntuación de VirusTotal de las conexiones en tiempo real."""

import unittest

from vela import intel, leakwatch
from vela.engine import Engine
from vela.store import Store

from .helpers import cfg, net
from .test_leakwatch import sock


class FakeLW:
    def __init__(self, state):
        self.state = state


def make(**over):
    base = {"consent": {"threat_intel_lookups": True}, "intel": {"auto_live": True, "live_daily_limit": 5}}
    for k, v in over.items():
        base[k] = {**base.get(k, {}), **v}
    c = cfg(**base)
    e = Engine(c, store=Store(memory=True), track=False)
    e.net = net(tunnel=True)
    e.leakwatcher = FakeLW(leakwatch.classify([sock("10.66.0.2", "185.220.101.7", inode=1)], e.net,
                                              own={1: (99, "firefox")}))
    return e


class LiveIntelTests(unittest.TestCase):
    def test_vt_score(self):
        r = {"status": "ok", "verdict": "malicioso", "summary": {"malicious": 5, "suspicious": 1, "harmless": 60,
                                                                  "undetected": 28, "as_owner": "X"}}
        s = intel.vt_score(r)
        self.assertEqual((s["malicious"], s["total"]), (5, 94))
        self.assertIsNone(intel.vt_score({"status": "rate_limited"}))

    def test_blocked_reasons(self):
        e = make(intel={"auto_live": False})
        li = intel.LiveIntel(e)
        self.assertIn("desactivado", li._reason_blocked())
        e = make()
        li = intel.LiveIntel(e)
        orig = intel.load_keys
        intel.load_keys = lambda: {}
        try:
            self.assertIn("API key", li._reason_blocked())
        finally:
            intel.load_keys = orig

    def test_scores_and_notifies(self):
        e = make()
        li = intel.LiveIntel(e)
        calls = []

        def fake_lookup(self_, ip, provider, refresh=False):
            calls.append(ip)
            res = {"status": "ok", "verdict": "malicioso", "summary": {"malicious": 7, "suspicious": 0, "harmless": 50,
                                                                         "undetected": 30, "as_owner": "TorExit"}}
            self_._save(ip, provider, res)
            return res
        orig_keys, orig_lookup = intel.load_keys, intel.Scanner.lookup
        intel.load_keys = lambda: {"virustotal": "k"}
        intel.Scanner.lookup = fake_lookup
        try:
            li.step()
            li.step()                                                     # ya en caché: no repite
        finally:
            intel.load_keys, intel.Scanner.lookup = orig_keys, orig_lookup
        self.assertEqual(calls, ["185.220.101.7"])
        ev = [x for x in e.store.events() if x["kind"] == "intel_live_score"][0]
        self.assertEqual((ev["severity"], ev["data"]["score"], ev["data"]["process"]), ("high", "7/87", "firefox"))
        self.assertTrue(ev["data"]["notify"])
        st = e.api_leakwatch()                                            # la tabla en vivo lleva la puntuación
        f = st["flows"][0]
        self.assertEqual((f["vt"]["malicious"], f["vt"]["total"]), (7, 87))
        self.assertEqual(st["vt_flagged"], 1)
        self.assertIn("country", f)

    def test_intel_results_geolocated(self):
        e = make()
        sc = intel.Scanner(e.store, e.cfg, keys={})
        sc._save("185.220.101.7", "virustotal", {"status": "ok", "verdict": "malicioso", "summary": {
            "malicious": 9, "suspicious": 0, "harmless": 50, "undetected": 30, "as_owner": "Foundation for Applied Privacy",
            "country": "DE", "asn": 208323}})
        r = e.api_intel_results()[0]
        self.assertEqual(r["geo"]["country"], r["geo"]["country"] or "DE")
        self.assertIsNotNone(r["geo"]["country"])
        self.assertEqual(r["org"], "Foundation for Applied Privacy")
        self.assertEqual((r["vt"]["malicious"], r["vt"]["total"]), (9, 89))

    def test_daily_limit(self):
        e = make()
        e.store.put("intel_live_count:" + __import__("time").strftime("%Y-%m-%d"), 5)
        li = intel.LiveIntel(e)
        orig = intel.load_keys
        intel.load_keys = lambda: {"virustotal": "k"}
        try:
            li.step()
        finally:
            intel.load_keys = orig
        self.assertEqual(li.state["status"], "tope diario alcanzado")


if __name__ == "__main__":
    unittest.main()
