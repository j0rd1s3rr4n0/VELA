"""Rutas del tráfico (programa → proxy/Tor/directo → VPN → destino) y detección proxy vs servidor web."""

import socket
import threading
import unittest

from vela import discovery, routes


def flow(proc, pid, remote, iface="wg0", kind="wireguard", rport=443):
    return {"process": proc, "pid": pid, "remote": remote, "rport": rport, "iface": iface, "iface_kind": kind,
            "verdict": "protegida" if kind == "wireguard" else "directa"}


def loop(inode, port):
    return {"remote": "127.0.0.1", "rport": port, "inode": inode, "local": "127.0.0.1", "lport": 40000 + inode}


class RoutesTests(unittest.TestCase):
    def build(self, flows, tunnels=("wg0",)):
        return routes.build(
            flows, [loop(1, 8080), loop(2, 8080), loop(3, 9050)], {1: (10, "curl"), 2: (11, "firefox"), 3: (12, "torsocks")},
            [{"port": 8080, "kind": "http"}, {"port": 9050, "kind": "tor-socks"}], list(tunnels),
            {"default": {"ok": True, "ip": "185.65.135.1", "via_tunnel": True}}, [9050], {8080: 500})

    def test_local_proxy_over_vpn(self):
        r = self.build([flow("mitmdump", 500, "93.184.216.34"), flow("brave", 20, "1.2.3.4"),
                        flow("[debian-tor]", None, "192.42.116.96")])
        L = {(l["source"], l["target"]): l["value"] for l in r["links"]}
        self.assertEqual(L[("app:curl", "proxy:8080")], 1)
        self.assertEqual(L[("app:firefox", "proxy:8080")], 1)
        self.assertEqual(L[("proxy:8080", "net:wg0")], 1)                 # el proxy sale por la VPN
        self.assertEqual(L[("app:torsocks", "tor:9050")], 1)
        self.assertEqual(L[("tor:9050", "net:wg0")], 1)
        self.assertEqual(L[("net:wg0", "dst:tor")], 1)
        self.assertEqual(L[("app:brave", "direct")], 1)
        text = " ".join(r["explain"])
        self.assertIn("un proxy LOCAL no cambia tu IP de salida", text)
        self.assertIn("Tor sobre VPN", text)
        self.assertNotIn("Red Tor →", text)

    def test_without_vpn(self):
        r = self.build([flow("mitmdump", 500, "93.184.216.34", "eth0", "ethernet")], tunnels=())
        text = " ".join(r["explain"])
        self.assertIn("sin túnel: los destinos ven tu IP real aunque uses el proxy", text)
        self.assertIn("No hay VPN conectada", text)
        self.assertIn("dst:real", {n["id"] for n in r["nodes"]})

    def test_chained_remote_proxy_hint(self):
        r = self.build([flow("mitmdump", 500, "203.0.113.7"), flow("mitmdump", 500, "203.0.113.7")])
        self.assertIn("encadenado a otro proxy remoto", " ".join(r["explain"]))


def serve(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def loop_():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            c.recv(1024)
            c.sendall(reply)
            c.close()
    threading.Thread(target=loop_, daemon=True).start()
    return srv


class ProxyDetectTests(unittest.TestCase):
    def test_web_server_is_not_proxy(self):
        s = serve(b"HTTP/1.0 405 Method Not Allowed\r\n\r\n")
        self.assertFalse(discovery.is_http_proxy(s.getsockname()[1]))
        s.close()

    def test_real_proxy(self):
        s = serve(b"HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: test\r\n\r\n")
        self.assertTrue(discovery.is_http_proxy(s.getsockname()[1]))
        s.close()


if __name__ == "__main__":
    unittest.main()
