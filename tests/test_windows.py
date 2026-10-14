"""Capa de Windows (vela/winsys.py) con datos SIMULADOS: tablas TCP binarias y JSON de PowerShell.
No sustituye a una prueba en un Windows real."""

import socket
import struct
import unittest

from vela import winsys


def row4(state, la, lp, ra, rp, pid):
    ip = lambda a: struct.unpack("<I", socket.inet_aton(a))[0]  # noqa: E731
    return struct.pack("<IIIIII", state, ip(la), socket.htons(lp), ip(ra), socket.htons(rp), pid)


class TcpTableTests(unittest.TestCase):
    def test_tcp4(self):
        buf = struct.pack("<I", 2) + row4(5, "10.0.0.2", 50000, "198.51.100.7", 443, 1234) + \
            row4(2, "127.0.0.1", 9050, "0.0.0.0", 0, 88)
        rows = winsys.parse_tcp4(buf)
        self.assertEqual(rows[0], {"proto": "tcp", "state": "ESTABLISHED", "local": "10.0.0.2", "lport": 50000,
                                   "remote": "198.51.100.7", "rport": 443, "pid": 1234})
        self.assertEqual(rows[1]["state"], "LISTEN")
        socks = winsys.read_sockets(rows)
        self.assertEqual(len(socks), 1)                 # solo las activas, como leakwatch en Linux
        self.assertEqual(socks[0]["inode"], 1234)       # el «inodo» es el PID
        self.assertEqual(winsys.listening(rows), [("127.0.0.1", 9050, 88)])

    def test_tcp6_and_mapped_ipv4(self):
        import ipaddress
        la = ipaddress.IPv6Address("2001:db8::5").packed
        ra = ipaddress.IPv6Address("::ffff:198.51.100.9").packed
        buf = struct.pack("<I", 1) + la + struct.pack("<II", 0, socket.htons(51000)) + ra + \
            struct.pack("<IIII", 0, socket.htons(443), 5, 77)
        r = winsys.parse_tcp6(buf)[0]
        self.assertEqual((r["local"], r["lport"], r["remote"], r["rport"], r["pid"]),
                         ("2001:db8::5", 51000, "198.51.100.9", 443, 77))


class NetworkTests(unittest.TestCase):
    PS = {
        "adapters": [{"Name": "Wi-Fi", "InterfaceDescription": "Intel(R) Wi-Fi 6 AX201", "Status": "Up",
                      "PhysicalMediaType": "Native 802.11"},
                     {"Name": "ProtonVPN", "InterfaceDescription": "WireGuard Tunnel", "Status": "Up"},
                     {"Name": "vEthernet (WSL)", "InterfaceDescription": "Hyper-V Virtual Ethernet Adapter",
                      "Status": "Up", "Virtual": True}],
        "addresses": [{"InterfaceAlias": "Wi-Fi", "IPAddress": "192.168.1.20", "PrefixLength": 24, "Family": "IPv4"},
                      {"InterfaceAlias": "ProtonVPN", "IPAddress": "10.2.0.2", "PrefixLength": 32, "Family": "IPv4"},
                      {"InterfaceAlias": "Loopback Pseudo-Interface 1", "IPAddress": "127.0.0.1", "PrefixLength": 8,
                       "Family": "IPv4"}],
        "routes": [{"InterfaceAlias": "ProtonVPN", "NextHop": "0.0.0.0", "RouteMetric": 1, "Family": "IPv4"},
                   {"InterfaceAlias": "Wi-Fi", "NextHop": "192.168.1.1", "RouteMetric": 25, "Family": "IPv4"}],
        "egress4": {"dev": "ProtonVPN", "src": "10.2.0.2", "gateway": "0.0.0.0"},
    }

    def test_classify(self):
        kinds = {a["Name"]: winsys.classify_adapter(a) for a in self.PS["adapters"]}
        self.assertEqual(kinds, {"Wi-Fi": "wifi", "ProtonVPN": "wireguard", "vEthernet (WSL)": "virtual"})

    def test_build_network_matches_linux_schema(self):
        n = winsys.build_network(self.PS)
        for key in ("interfaces", "routes", "policy_rules", "egress", "egress_kind", "local_ip", "gateway",
                    "tunnels", "via_tunnel", "ipv6_internet"):
            self.assertIn(key, n)
        self.assertEqual(n["tunnels"], ["ProtonVPN"])
        self.assertEqual(n["via_tunnel"]["ipv4"], True)
        self.assertEqual(n["egress"]["ipv4"]["gateway"], None)          # 0.0.0.0 = enlace directo
        self.assertEqual(n["routes"]["ipv4_default"][0]["dev"], "ProtonVPN")
        self.assertNotIn("Loopback Pseudo-Interface 1", [i["name"] for i in n["interfaces"]])

    def test_single_object_from_convertto_json(self):
        n = winsys.build_network({"adapters": self.PS["adapters"][0], "addresses": self.PS["addresses"][0],
                                  "routes": self.PS["routes"][1],
                                  "egress4": {"dev": "Wi-Fi", "src": "192.168.1.20", "gateway": "192.168.1.1"}})
        self.assertEqual(n["via_tunnel"]["ipv4"], False)
        self.assertEqual(n["gateway"], "192.168.1.1")

    def test_empty_powershell_output(self):
        n = winsys.build_network(None)
        self.assertEqual(n["interfaces"], [])
        self.assertIsNone(n["egress"]["ipv4"])


class DnsTests(unittest.TestCase):
    def test_doh_encrypted(self):
        d = winsys.build_dns({"servers": {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["1.1.1.1"]},
                              "doh": {"ServerAddress": "1.1.1.1", "AutoUpgrade": True, "AllowFallbackToUdp": False,
                                      "DohTemplate": "https://cloudflare-dns.com/dns-query"}}, "Wi-Fi")
        self.assertTrue(d["encrypted"])
        self.assertEqual(d["encryption"]["resolvers"][0]["transport"], "DoH")

    def test_fallback_to_udp_is_not_called_encrypted(self):
        d = winsys.build_dns({"servers": {"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["1.1.1.1"]},
                              "doh": {"ServerAddress": "1.1.1.1", "AutoUpgrade": True, "AllowFallbackToUdp": True}})
        self.assertIsNone(d["encrypted"])

    def test_plain_dns(self):
        d = winsys.build_dns({"servers": [{"InterfaceAlias": "Wi-Fi", "ServerAddresses": ["192.168.1.1"]}]}, "Wi-Fi")
        self.assertFalse(d["encrypted"])
        self.assertEqual(d["effective_servers"], ["192.168.1.1"])


class WlanTests(unittest.TestCase):
    def test_parse_netsh_es_and_en(self):
        es = "    Nombre                 : Wi-Fi\n    SSID                   : MiRed\n    Autenticación          : WPA2-Personal\n    Señal                  : 87%\n"
        en = "    Name                   : Wi-Fi 2\n    SSID                   : Office\n    Authentication         : WPA3-Personal\n    Signal                 : 61%\n"
        w = winsys.parse_wlan(es + "\n" + en)
        self.assertEqual(w["Wi-Fi"], {"ssid": "MiRed", "security": "WPA2-Personal", "signal": 87})
        self.assertEqual(w["Wi-Fi 2"]["signal"], 61)


if __name__ == "__main__":
    unittest.main()
