"""Detección de IPs de Tor (consenso local, lista de salidas, ExoneraTor)."""

import unittest

from opsectools import torcheck

NS = """r hai IKi8juoSX+aFLP2FJDjK4UgmlPo AAAA 2038-01-01 00:00:00 109.70.100.13 443 0
a [2a03:e600:100::13]:443
s Exit Fast Running Stable Valid
w Bandwidth=1000
r midnode BBBBBBBBBBBBBBBBBBBBBBBBBBB BBBB 2038-01-01 00:00:00 5.6.7.8 9001 0
s Fast Guard Running Valid
"""

POS = """<h3 class="panel-title">Result is positive</h3><table><tr><td>2026-10-07 00:00:00</td>
<td>109.70.100.13</td><td>20A8BC8EE8125FE6852C85FD2438CAE1482694FA</td><td>hai</td><td>Yes</td></tr></table>
<p>Result is positive We found one or more Tor relays</p>"""
NEG = "<h3 class='panel-title'>Result is negative</h3><p>Result is negative We did not find</p>"
ERR = '<h3 class="panel-title">Server problem</h3><div class="panel-body"> The database appears to be empty.</div>'


class TorCheckTests(unittest.TestCase):
    def test_parse_consensus(self):
        by_ip = torcheck.parse_ns_all(NS)
        self.assertEqual(by_ip["109.70.100.13"][0]["nick"], "hai")
        self.assertIn("Exit", by_ip["109.70.100.13"][0]["flags"])
        self.assertIn("2a03:e600:100::13", by_ip)                   # también por IPv6
        self.assertEqual(len(by_ip["109.70.100.13"][0]["fp"]), 40)

    def test_classify(self):
        cons = {"by_ip": torcheck.parse_ns_all(NS), "count": 2}
        exits = {"ips": {"185.220.101.1"}}
        self.assertEqual(torcheck.classify("109.70.100.13", cons, exits)["verdict"], "exit")
        self.assertEqual(torcheck.classify("5.6.7.8", cons, exits)["verdict"], "relay")
        self.assertEqual(torcheck.classify("185.220.101.1", cons, exits)["verdict"], "exit")    # solo en la lista
        self.assertEqual(torcheck.classify("8.8.8.8", cons, exits)["verdict"], "no")
        self.assertEqual(torcheck.classify("8.8.8.8", {"by_ip": {}}, {"ips": set()})["verdict"], "desconocido")
        exo = {"status": "ok", "result": "positivo", "exit": True}
        self.assertEqual(torcheck.classify("9.9.9.9", cons, exits, exo)["verdict"], "exit")   # histórico

    def test_parse_exonerator(self):
        p = torcheck.parse_exonerator(POS)
        self.assertEqual((p["result"], p["exit"], p["relays"][0]["nick"]), ("positivo", True, "hai"))
        self.assertEqual(torcheck.parse_exonerator(NEG)["result"], "negativo")
        e = torcheck.parse_exonerator(ERR)
        self.assertEqual(e["status"], "no_disponible")                # nunca se inventa un resultado
        self.assertIn("database", e["detail"])

    def test_exonerator_requires_tor(self):
        self.assertEqual(torcheck.exonerator("1.2.3.4", None)["status"], "no_disponible")


if __name__ == "__main__":
    unittest.main()
