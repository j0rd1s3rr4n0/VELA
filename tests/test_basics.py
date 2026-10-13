import os
import tempfile
import unittest
from pathlib import Path

from vela import config, discovery, dns, geo, network, worldmap
from vela.util import fmt_duration, parse_duration, redact

from .helpers import env, net


class UtilTests(unittest.TestCase):
    def test_duration_format(self):
        self.assertEqual(fmt_duration(0), "00d 00h 00m 00s")
        self.assertEqual(fmt_duration(90061), "01d 01h 01m 01s")
        self.assertEqual(fmt_duration(-5), "00d 00h 00m 00s")

    def test_parse_duration(self):
        self.assertEqual(parse_duration("45m"), 2700)
        self.assertEqual(parse_duration("1h30m"), 5400)
        self.assertEqual(parse_duration(10), 10)
        with self.assertRaises(ValueError):
            parse_duration("diez")

    def test_redact(self):
        self.assertEqual(redact("socks5://user:pw@1.2.3.4:1080"), "socks5://***@1.2.3.4:1080")
        self.assertEqual(redact({"password": "x", "host": "h"}), {"password": "***", "host": "h"})
        self.assertIn("***", redact("token=abc123"))

    def test_config_validation(self):
        with self.assertRaises(ValueError):
            config.load_text('active_profile = "nope"')
        with self.assertRaises(ValueError):
            config.load_text('[gui]\nhost = "0.0.0.0"')
        with self.assertRaises(ValueError):
            config.load_text('[rotation.tor]\nmax_ttl = "pronto"')
        c = config.load_text('[consent]\ndirect_ip_checks = true')
        self.assertTrue(c["consent"]["direct_ip_checks"])
        self.assertFalse(c["consent"]["allow_killswitch"])   # el resto de valores seguros se mantiene

    def test_safe_defaults(self):
        for k in ("direct_ip_checks", "proxy_ip_checks", "active_dns_leak_test", "allow_rotation_changes", "allow_killswitch"):
            self.assertFalse(config.DEFAULTS["consent"][k], k)


class DiscoveryTests(unittest.TestCase):
    def test_proc_addr_decode(self):
        self.assertEqual(discovery._decode_proc_addr("0100007F"), "127.0.0.1")
        self.assertEqual(discovery._decode_proc_addr("00000000000000000000000001000000"), "::1")

    def test_nm_split(self):
        self.assertEqual(discovery._nm_split(r"Mi\:VPN:wireguard:wg0:yes"), ["Mi:VPN", "wireguard", "wg0", "yes"])

    def test_torrc_ports(self):
        self.assertEqual(discovery._ports_from_torrc(["9050 IsolateSOCKSAuth", "127.0.0.1:9150", "unix:/x", "0"]), [9050, 9150])

    def test_proxychains(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False) as f:
            f.write("random_chain\n[ProxyList]\nsocks5 10.0.0.1 1080 user secreto\nhttp 10.0.0.2 3128\n# socks4 1.1.1.1 1\n")
        os.environ["PROXYCHAINS_CONF_FILE"] = f.name
        try:
            pc = discovery.detect_proxychains()
        finally:
            del os.environ["PROXYCHAINS_CONF_FILE"]
            os.unlink(f.name)
        self.assertEqual(pc["mode"], "random_chain")
        self.assertEqual([(p["host"], p["port"], p["auth"]) for p in pc["proxies"]],
                         [("10.0.0.1", 1080, True), ("10.0.0.2", 3128, False)])
        self.assertNotIn("secreto", str(pc))

    def test_capabilities_classification(self):
        caps = {c["id"]: c for c in discovery.capabilities(env())}
        self.assertEqual(caps["vpn.wireguard"]["status"], discovery.OPERATIVA)
        self.assertEqual(caps["vpn.traffic"]["status"], discovery.OPERATIVA)
        self.assertEqual(caps["vpn.networkmanager"]["status"], discovery.OPERATIVA)
        self.assertEqual(caps["tor.control"]["status"], discovery.SIN_PERMISOS)   # cookie no legible
        self.assertEqual(caps["killswitch.own"]["status"], discovery.SIN_PERMISOS)
        self.assertEqual(caps["storage.encryption"]["status"], discovery.NO_DISPONIBLE)
        self.assertEqual(caps["net.public_ip.direct"]["status"], discovery.NO_VERIFICABLE)
        e = env(interfaces=[{"name": "eth0", "kind": "ethernet", "up": True, "mac_origin": "permanente"}],
                egress={"ipv4": "eth0", "ipv6": None})
        e["vpn"]["networkmanager"] = []
        caps = {c["id"]: c for c in discovery.capabilities(e)}
        self.assertEqual(caps["vpn.wireguard"]["status"], discovery.INACTIVA)    # instalado sin config
        self.assertNotIn("vpn.traffic", caps)

    def test_recommend_warns(self):
        notes, cfg = discovery.recommend(env())
        texts = " ".join(n["text"] for n in notes)
        self.assertIn("FUGA IPv6", texts)                # IPv4 por wg0, IPv6 por eth0 con IP global
        self.assertIn("escucha en 0.0.0.0", texts)       # proxy expuesto
        self.assertIn("Posible fuga", texts)             # resolver en eth0 con el túnel activo
        self.assertEqual(cfg["rotation"]["vpn"]["driver"], "networkmanager")


class NetworkTests(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(network.classify_ip("100.70.1.1"), "cgnat")
        self.assertEqual(network.classify_ip("192.168.0.1"), "privada")
        self.assertEqual(network.classify_ip("fdc9::1"), "ula")
        self.assertEqual(network.classify_ip("8.8.8.8"), "pública")
        self.assertEqual(network.classify_ip("fe80::1%eth0"), "link-local")

    def test_diff_tunnel_drop_is_critical(self):
        evs = network.diff(net(tunnel=True), net(tunnel=False))
        kinds = {e["kind"]: e for e in evs}
        self.assertEqual(kinds["route_change"]["severity"], "critical")
        self.assertTrue(kinds["route_change"]["left_tunnel"])
        self.assertIn("interface_removed", kinds)
        self.assertEqual(kinds["interface_removed"]["severity"], "high")

    def test_no_events_when_equal(self):
        self.assertEqual(network.diff(net(), net()), [])
        self.assertEqual(network.diff(None, net()), [])

    def test_physical_iface(self):
        self.assertEqual(network.physical_iface(net(tunnel=True)), "eth0")


RESOLVECTL = """Global
         Protocols: -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
  resolv.conf mode: stub

Link 2 (enp34s0)
    Current Scopes: DNS
         Protocols: +DefaultRoute -LLMNR -mDNS -DNSOverTLS DNSSEC=no/unsupported
Current DNS Server: 192.168.0.1
       DNS Servers: 192.168.0.1
                    fdcb::1
        DNS Domain: ~.

Link 5 (wg0)
    Current Scopes: DNS
         Protocols: -DefaultRoute +DNSOverTLS DNSSEC=no/unsupported
       DNS Servers: 10.64.0.1#dns.example
        DNS Domain: ~corp.example
"""


class DNSTests(unittest.TestCase):
    def test_parse_resolvectl(self):
        sec = dns.parse_resolvectl_status(RESOLVECTL)
        self.assertEqual(sec["enp34s0"]["DNS Servers"], ["192.168.0.1", "fdcb::1"])   # continuación con IPv6
        self.assertEqual(sec["wg0"]["DNS Domain"], ["~corp.example"])
        self.assertEqual(sec["Global"]["resolv.conf mode"], "stub")
        flags = dns._proto_flags(sec["wg0"]["Protocols"])
        self.assertTrue(flags["DNSOverTLS"])
        self.assertFalse(flags["DefaultRoute"])

    def test_classify_server(self):
        self.assertEqual(dns.classify_server("10.64.0.1#dns.example"), "lan")
        self.assertEqual(dns.classify_server("127.0.0.53"), "local")
        self.assertEqual(dns.classify_server("[2606:4700::1111]:53"), "pública")


class GeoMapTests(unittest.TestCase):
    def test_tor_geoip(self):
        d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
        p4, p6 = Path(d, "geoip"), Path(d, "geoip6")
        p4.write_text("# comentario\n16777216,16777471,AU\n134744064,134744319,US\n")
        p6.write_text("2001:db8::,2001:db8::ffff,NL\n")
        g = geo.Geo(str(p4), str(p6))
        self.assertEqual(g.lookup("8.8.8.8")["country"], "US")
        self.assertEqual(g.lookup("1.0.0.5")["country"], "AU")
        self.assertIsNone(g.lookup("9.9.9.9")["country"])
        self.assertEqual(g.lookup("192.168.1.1")["scope"], "local")
        self.assertIsNotNone(g.lookup("8.8.8.8")["lat"])

    def test_iso6709(self):
        self.assertEqual(geo._parse_iso6709("+4024-00341"), (40 + 24 / 60, -(3 + 41 / 60)))

    def test_coords_not_merged(self):
        coords = geo.load_country_coords()
        if "SE" in coords and "DE" in coords:
            self.assertNotEqual(coords["SE"], coords["DE"])   # zone1970 agrupa SE con Berlín

    def test_worldmap(self):
        self.assertTrue(worldmap.is_land(-3.7, 40.4))       # Madrid
        self.assertTrue(worldmap.is_land(-100, 40))         # EEUU
        self.assertTrue(worldmap.is_land(134, -25))         # Australia
        self.assertFalse(worldmap.is_land(-30, 30))         # Atlántico
        self.assertFalse(worldmap.is_land(-140, 0))         # Pacífico
        m = worldmap.ascii_map(80, 20, [(40.4, -3.7, "X")])
        self.assertEqual(len(m), 20)
        self.assertTrue(all(len(r) == 80 for r in m))
        self.assertIn("X", "".join(m))


if __name__ == "__main__":
    unittest.main()


class ShortDurationTests(unittest.TestCase):
    def test_keeps_days(self):
        from vela.util import fmt_duration_short
        self.assertEqual(fmt_duration_short(86400 + 19 * 3600 + 53 * 60), "01d 19h 53m")
        self.assertEqual(fmt_duration_short(19 * 3600 + 50 * 60 + 53), "19h 50m 53s")


class TildeTests(unittest.TestCase):
    def test_hides_username(self):
        import os
        from vela.util import tilde
        home = os.path.expanduser("~")
        self.assertEqual(tilde(f"{home}/.config/vela/secrets.toml"), "~/.config/vela/secrets.toml")
        self.assertEqual(tilde("/etc/tor/torrc"), "/etc/tor/torrc")
        self.assertEqual(tilde(home + "x/otro"), home + "x/otro")
