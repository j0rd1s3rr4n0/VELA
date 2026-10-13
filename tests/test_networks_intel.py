"""Redes (inventario/alertas), threat intel (proveedores simulados) y remediación."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from vela import intel, networks, remediation
from vela.engine import Engine
from vela.store import Store
from vela.util import now

from .helpers import cfg, net

TMP = os.environ.get("TMPDIR") or None


def inv(gw_mac="aa:bb:cc:00:00:01", neigh=(), ssid="CASA", libvirt=None, ts=None):
    return {"ts": ts or now(), "libvirt": libvirt or [], "interfaces": [{
        "name": "wlan0", "category": "wifi", "gateway": "192.168.1.1", "gateway_mac": gw_mac,
        "gateway_vendor": None, "subnets": ["192.168.1.0/24"], "connection": ssid, "wifi": {"ssid": ssid},
        "network_id": networks.fingerprint({"gw_mac": gw_mac, "ssid": ssid, "subnet": ["192.168.1.0/24"]}),
        "neighbors": [{"ip": ip, "mac": mac, "vendor": None} for ip, mac in neigh],
        "stats": {"rx_bytes": 1000, "tx_bytes": 500}}]}


class NetworkTests(unittest.TestCase):
    def test_categories_and_vendor(self):
        self.assertEqual(networks.category("wg0", "wireguard"), "vpn")
        self.assertEqual(networks.category("pvpnksintrf0", "dummy"), "bloqueo")
        self.assertEqual(networks.category("virbr1", "virtual"), "máquinas virtuales")
        self.assertEqual(networks.category("br-123", "virtual"), "contenedores")
        self.assertEqual(networks.vendor("fe:f9:0f:60:dc:ce"), "MAC aleatoria/local")   # bit local

    def test_new_network_then_new_device(self):
        known = {}
        evs = networks.diff(None, inv(neigh=[("192.168.1.5", "11:22:33:44:55:66")]), known)
        self.assertEqual([e["kind"] for e in evs], ["network_new"])          # inventario inicial: sin ruido
        evs = networks.diff(inv(), inv(neigh=[("192.168.1.5", "11:22:33:44:55:66"), ("192.168.1.9", "00:00:5e:00:53:01")]), known)
        self.assertEqual([e["kind"] for e in evs], ["lan_new_device"])
        self.assertEqual(evs[0]["data"]["mac"], "00:00:5e:00:53:01")

    def test_gateway_mac_change_is_high(self):
        known = {}
        networks.diff(None, inv(), known)
        evs = networks.diff(inv(), inv(gw_mac="de:ad:be:ef:00:01"), known)
        self.assertEqual(evs[0]["kind"], "gateway_mac_change")
        self.assertEqual(evs[0]["severity"], "high")

    def test_vm_isolation(self):
        lv = [{"name": "malware-lab", "active": True, "forward": "nat", "isolation_broken": True}]
        evs = networks.diff(None, inv(libvirt=lv), {})
        self.assertIn("vm_isolation_broken", [e["kind"] for e in evs])
        from vela import leaks
        f = leaks.check_networks({"interfaces": [], "libvirt": lv})[0]
        self.assertEqual((f["check"], f["status"]), ("vm_isolation", "fail"))
        fx = remediation.fix_for(f, {})
        self.assertIn("net-edit malware-lab", " ".join(s["cmd"] or "" for s in fx["steps"]))

    def test_rates(self):
        a, b = inv(ts=100), inv(ts=110)
        b["interfaces"][0]["stats"] = {"rx_bytes": 11000, "tx_bytes": 1500}
        r = networks.rates(a, b)["wlan0"]
        self.assertAlmostEqual(r["rx_bps"], 1000)
        self.assertAlmostEqual(r["tx_bps"], 100)


class FakeTransport:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append((url, headers or {}))
        for key, resp in self.responses.items():
            if key in url:
                return resp
        return 404, "{}"


VT = json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60,
                                                                  "undetected": 20}, "reputation": -12,
                                          "as_owner": "Tor exit", "country": "DE", "tags": ["tor"]}}})
SHODAN = json.dumps({"ports": [443, 22], "org": "Hosting", "vulns": ["CVE-2023-48795"], "tags": ["vpn"]})
GN = json.dumps({"noise": True, "riot": False, "classification": "malicious", "name": "unknown"})


class IntelTests(unittest.TestCase):
    def test_parse_list(self):
        text = "185.220.101.1, 8.8.8.8\nfoo 2001:db8::1 bar\n185.220.101.1\n999.1.1.1 10.0.0.1"
        self.assertEqual(intel.parse_ip_list(text), ["185.220.101.1", "8.8.8.8", "2001:db8::1", "10.0.0.1"])
        self.assertFalse(intel.is_scannable("10.0.0.1"))
        self.assertTrue(intel.is_scannable("8.8.8.8"))

    def test_providers_and_aggregate(self):
        t = FakeTransport({"virustotal": (200, VT), "shodan": (200, SHODAN), "greynoise": (200, GN)})
        keys = {"virustotal": "k1", "shodan": "k2"}
        vt = intel.q_virustotal("1.2.3.4", keys, t)
        self.assertEqual((vt["verdict"], vt["summary"]["malicious"]), ("malicioso", 7))
        self.assertEqual(t.calls[-1][1]["x-apikey"], "k1")
        sh = intel.q_shodan("1.2.3.4", keys, t)
        self.assertEqual(sh["verdict"], "expuesto")
        self.assertIn("CVE-2023-48795", sh["summary"]["vulns"])
        gn = intel.q_greynoise("1.2.3.4", {}, t)
        self.assertEqual(gn["verdict"], "malicioso")
        self.assertEqual(intel.aggregate({"a": vt, "b": sh, "c": gn}), "malicioso")
        self.assertEqual(intel.q_censys("1.2.3.4", {}, t)["status"], "sin_clave")
        self.assertEqual(intel.q_greynoise("1.2.3.4", {}, FakeTransport({}))["verdict"], "sin_datos")

    def test_scanner_cache_and_rate_limit(self):
        st = Store(memory=True)
        t = FakeTransport({"greynoise": (429, '{"message":"quota"}')})
        sc = intel.Scanner(st, cfg(), keys={}, transport=t)
        sc._last = {}
        intel.MIN_GAP["greynoise"] = 0
        r = sc.scan(["1.1.1.1", "9.9.9.9"], ["greynoise"])
        self.assertEqual(r[0]["results"]["greynoise"]["status"], "rate_limited")
        self.assertTrue(r[1]["results"]["greynoise"].get("skipped"))     # no insiste tras un 429
        self.assertEqual(len(t.calls), 1)
        t2 = FakeTransport({"greynoise": (200, GN)})
        sc2 = intel.Scanner(st, cfg(), keys={}, transport=t2)
        sc2.scan(["5.5.5.5"], ["greynoise"])
        sc2.scan(["5.5.5.5"], ["greynoise"])
        self.assertEqual(len(t2.calls), 1)                                 # segunda vez desde caché
        self.assertEqual(sc2.results("5.5.5.5")[0]["verdict"], "malicioso")
        intel.MIN_GAP["greynoise"] = 1.0

    def test_targets_exclude_own_ips(self):
        st = Store(memory=True)
        sid = st.open_session("p", "fp", {"vpn": None, "proxy": None})
        st.open_interval(sid, "p", "public_ip", "203.0.113.50", "203.0.113.50")       # IP directa = tuya
        st.open_interval(sid, "p", "wan_ip", "203.0.113.51", "203.0.113.51")
        st.open_interval(sid, "p", "tor_exit", "F" * 40, "relay 185.220.101.7", meta={"ip": "185.220.101.7"})
        st.open_interval(sid, "p", "dns_resolver", "127.0.2.2,1.1.1.1", "x")
        tg = intel.targets(st)
        self.assertIn("185.220.101.7", tg)
        self.assertIn("Tor exit", tg["185.220.101.7"]["roles"])
        self.assertIn("1.1.1.1", tg)
        self.assertNotIn("127.0.2.2", tg)
        self.assertEqual(intel.own_ips(st), {"203.0.113.50", "203.0.113.51"})

    def test_keys_file_private(self):
        d = tempfile.mkdtemp(dir=TMP)
        old = os.environ.get("XDG_CONFIG_HOME")
        os.environ["XDG_CONFIG_HOME"] = d
        try:
            p = intel.save_key("virustotal", 'abc"123')
            intel.save_key("shodan", "zzz")
            self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            k = intel.load_keys()
            self.assertEqual((k["virustotal"], k["shodan"]), ('abc"123', "zzz"))
            self.assertEqual(intel.configured(k)["virustotal"], "API key")
            with self.assertRaises(ValueError):
                intel.save_key("otro", "x")
        finally:
            if old is None:
                del os.environ["XDG_CONFIG_HOME"]
            else:
                os.environ["XDG_CONFIG_HOME"] = old

    def test_engine_requires_consent(self):
        e = Engine(cfg(), store=Store(memory=True), track=False)
        with self.assertRaises(PermissionError):
            e.api_intel_scan(ips=["8.8.8.8"])


class RemediationAndPublicIPTests(unittest.TestCase):
    def test_proxy_fix_has_concrete_commands(self):
        f = {"check": "proxy_exposed", "status": "fail", "severity": "medium", "title": "x",
             "evidence": {"addr": "0.0.0.0", "port": 8080, "owner": "python (pid 4242)"}}
        fx = remediation.fix_for(f, {"env": {"binaries": {"firewall": {"ufw": "/usr/sbin/ufw"}}}})
        cmds = [s["cmd"] for s in fx["steps"] if s["cmd"]]
        self.assertIn("ss -ltnp 'sport = :8080'", cmds)
        self.assertTrue(any("/proc/4242/cmdline" in c for c in cmds))
        self.assertTrue(any(c.startswith("sudo ufw deny in proto tcp to any port 8080") for c in cmds))

    def test_status_fixes(self):
        out = remediation.status_fixes({"public": {"default": {"ok": False, "skipped": True, "error": "omitida"}},
                                        "wan": {"ok": False}, "net": {"gateway": "192.168.0.1"}})
        titles = [x["title"] for x in out]
        self.assertTrue(any("omitida" in t for t in titles))
        self.assertTrue(any("UPnP" in t for t in titles))
        self.assertIn("BUENO", out[1]["why"])                         # no recomendar activar UPnP

    def test_public_ip_skipped_without_tunnel(self):
        e = Engine(cfg(consent={"direct_ip_checks": True}), store=Store(memory=True), track=False)
        e.net = net(tunnel=False)
        e.env = {"tor": {"socks": []}}
        res = e.refresh_public("default", force=True)[0]
        self.assertTrue(res["skipped"])
        self.assertIn("expondría tu IP real", res["error"])


if __name__ == "__main__":
    unittest.main()
