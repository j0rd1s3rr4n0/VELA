"""Vigilante de fugas en tiempo real y verificación de la IP pública."""

import unittest

from opsectools import leaks, leakwatch
from opsectools.engine import Engine
from opsectools.store import Store

from .helpers import cfg, net

HDR = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def tcp_line(local, lport, remote, rport, st="01", inode=111, uid=1000):
    enc = lambda ip: "".join(f"{int(o):02X}" for o in reversed(ip.split(".")))  # noqa: E731  (little-endian)
    return (f"   0: {enc(local)}:{lport:04X} {enc(remote)}:{rport:04X} {st} 00000000:00000000 00:00000000 "
            f"00000000  {uid}        0 {inode} 1 0000000000000000 20 4 30 10 -1\n")


def sock(local, remote, rport=443, proto="tcp", inode=1):
    return {"proto": proto, "local": local, "lport": 50000, "remote": remote, "rport": rport, "state": "ESTABLISHED",
            "uid": 1000, "inode": inode}


class ParseTests(unittest.TestCase):
    def test_parse(self):
        text = HDR + tcp_line("192.168.1.10", 50000, "149.154.167.92", 443) + \
            tcp_line("0.0.0.0", 22, "0.0.0.0", 0, st="0A")
        s = leakwatch.parse_proc_net(text, "tcp")
        self.assertEqual(len(s), 1)                                    # LISTEN se ignora
        self.assertEqual((s[0]["local"], s[0]["remote"], s[0]["rport"]), ("192.168.1.10", "149.154.167.92", 443))


class ClassifyTests(unittest.TestCase):
    def test_leak_with_tunnel(self):
        n = net(tunnel=True)
        r = leakwatch.classify([sock("192.168.1.10", "149.154.167.92", inode=7), sock("10.66.0.2", "1.1.1.1", inode=8),
                                sock("192.168.1.10", "192.168.1.1", 53), sock("192.168.1.10", "9.9.9.9", 53, "udp")],
                               n, own={7: (4242, "telegram")})
        v = {(f["remote"], f["rport"]): f for f in r["flows"]}
        self.assertEqual(v[("149.154.167.92", 443)]["verdict"], "fuga")
        self.assertEqual(v[("149.154.167.92", 443)]["process"], "telegram")
        self.assertEqual(v[("1.1.1.1", 443)]["verdict"], "protegida")
        self.assertNotIn(("192.168.1.1", 53), v)                       # LAN: no es Internet
        self.assertTrue(v[("9.9.9.9", 53)]["dns"])
        self.assertEqual(r["summary"]["fugas"], 2)

    def test_direct_without_tunnel_and_allowlist(self):
        r = leakwatch.classify([sock("192.168.1.10", "149.154.167.92"), sock("192.168.1.10", "185.220.101.1")],
                               net(tunnel=False), allow={"185.220.101.1"})
        self.assertEqual([f["verdict"] for f in r["flows"]], ["directa", "permitida"])
        self.assertFalse(r["tunnel_up"])

    def test_cgnat_is_not_internet(self):
        self.assertFalse(leakwatch.is_internet("100.85.0.1"))           # interfaz de bloqueo de ProtonVPN
        self.assertTrue(leakwatch.is_internet("149.154.167.92"))


class WatcherTests(unittest.TestCase):
    def make(self, on_leak="alert", profile_vpn=False):
        c = cfg(leakwatch={"on_leak": on_leak}, consent={"allow_killswitch": True})
        if profile_vpn:
            c["profiles"]["default"]["require_vpn"] = True
        e = Engine(c, store=Store(memory=True), track=False)
        e.net = net(tunnel=True)
        w = leakwatch.LeakWatcher(e, cooldown=600)
        return e, w

    def test_emits_once_per_flow(self):
        e, w = self.make()
        leak = leakwatch.classify([sock("192.168.1.10", "149.154.167.92")], e.net)
        w.snapshot = lambda: leak
        w.step()
        w.step()
        evs = [x for x in e.store.events() if x["kind"] == "ip_leak"]
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0]["severity"], "critical")

    def test_auto_killswitch(self):
        e, w = self.make(on_leak="killswitch")
        calls = []
        e.ks.engage = lambda **k: (calls.append(k), {"ok": True})[1]
        w.snapshot = lambda: leakwatch.classify([sock("192.168.1.10", "149.154.167.92")], e.net)
        w.step()
        self.assertEqual(len(calls), 1)
        self.assertIn("killswitch_auto", [x["kind"] for x in e.store.events()])

    def test_direct_exposure_once_per_transition(self):
        e, w = self.make(profile_vpn=True)
        e.net = net(tunnel=False)
        w.snapshot = lambda: leakwatch.classify([sock("192.168.1.10", "149.154.167.92")], e.net)
        w.step()
        w.step()
        self.assertEqual(len([x for x in e.store.events() if x["kind"] == "direct_exposure"]), 1)


class PublicIPTests(unittest.TestCase):
    def test_real_ip_with_tunnel_is_critical(self):
        e = Engine(cfg(public_ip={"known_real_ips": ["203.0.113.9"]}), store=Store(memory=True), track=False)
        e.net = net(tunnel=True)
        res = {"ok": True, "ip": "203.0.113.9", "geo": {"country": "SE"}, "endpoint": "x", "ts": 0}
        e._verify_public(res)
        self.assertTrue(res["is_real_ip"])
        self.assertIn("public_ip_is_real", [x["kind"] for x in e.store.events()])
        f = leaks.check_realtime(None, {"default": res}, {})[0]
        self.assertEqual((f["check"], f["status"], f["severity"]), ("public_real_ip", "fail", "critical"))

    def test_vpn_ip_passes(self):
        e = Engine(cfg(public_ip={"known_real_ips": ["203.0.113.9"]}), store=Store(memory=True), track=False)
        e.net = net(tunnel=True)
        res = {"ok": True, "ip": "185.159.157.1", "geo": {"country": "DE"}, "endpoint": "x", "ts": 0}
        e._verify_public(res)
        f = leaks.check_realtime(None, {"default": res}, {})[0]
        self.assertEqual(f["status"], "pass")
        self.assertEqual(f["confidence"], "alta")                     # se conoce la IP real

    def test_live_findings(self):
        lw = leakwatch.classify([sock("192.168.1.10", "149.154.167.92")], net(tunnel=True))
        f = leaks.check_realtime(lw, {}, {})[0]
        self.assertEqual((f["check"], f["status"]), ("ip_leak_live", "fail"))
        lw = leakwatch.classify([sock("192.168.1.10", "149.154.167.92")], net(tunnel=False))
        f = leaks.check_realtime(lw, {}, {"require_vpn": True})[0]
        self.assertEqual((f["check"], f["status"], f["severity"]), ("direct_exposure", "fail", "high"))
        from opsectools import remediation
        fx = remediation.fix_for(f, {})
        self.assertIn("Permanente", " ".join(s["desc"] for s in fx["steps"]))


if __name__ == "__main__":
    unittest.main()
