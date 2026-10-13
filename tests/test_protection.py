"""Kill-switches de terceros, DNS cifrado y generación de perfiles."""

import os
import tempfile
import unittest
from pathlib import Path

from vela import config, leaks, profiles, protection

from .helpers import dns, env, net

TMP = os.environ.get("TMPDIR") or None
KINDS = {"enp34s0": "ethernet", "proton0": "wireguard", "pvpnksintrf0": "dummy", "lo": "loopback"}


def routes(v4, v6=()):
    mk = lambda rs: [{"dev": d, "gateway": "gw", "metric": m, "type": t} for d, m, t in rs]  # noqa: E731
    return {"ipv4": mk(v4), "ipv6": mk(v6)}


class RouteProtectionTests(unittest.TestCase):
    def test_proton_dummy_blocks(self):
        rp = protection.route_protection(routes([("pvpnksintrf0", 98, "unicast"), ("enp34s0", 100, "unicast")],
                                                [("pvpnksintrf0", 95, "unicast")]), KINDS)
        self.assertEqual(rp["ipv4"]["state"], "bloqueado")
        self.assertIn("pvpnksintrf0", rp["ipv4"]["detail"])
        self.assertEqual(rp["ipv6"]["state"], "bloqueado")

    def test_physical_fallback_is_exposed(self):
        rp = protection.route_protection(routes([("proton0", 50, "unicast"), ("enp34s0", 100, "unicast")]), KINDS)
        self.assertEqual(rp["ipv4"]["state"], "expuesto")
        self.assertEqual(rp["ipv6"]["state"], "bloqueado")        # sin ruta IPv6 fuera del túnel

    def test_blackhole(self):
        rp = protection.route_protection(routes([(None, 10, "blackhole"), ("enp34s0", 100, "unicast")]), KINDS)
        self.assertEqual(rp["ipv4"]["state"], "bloqueado")

    def test_metric_order_matters(self):
        rp = protection.route_protection(routes([("pvpnksintrf0", 200, "unicast"), ("enp34s0", 100, "unicast")]), KINDS)
        self.assertEqual(rp["ipv4"]["state"], "expuesto")         # el dummy con más métrica no protege

    def test_proton_server_names(self):
        f = protection.proton_exit_country
        self.assertEqual(f("ProtonVPN CH-DE#2"), "DE")
        self.assertEqual(f("ProtonVPN ES#12"), "ES")
        self.assertEqual(f("ProtonVPN US-NY#5"), "US")
        self.assertIsNone(f("Wired connection 1"))


WARP = {"provider": "Cloudflare WARP", "connected": True, "status": "Connected", "mode": "DnsOverHttps",
        "doh_host": "cloudflare-dns.com", "upstream_ips": ["162.159.36.1"]}


class DNSEncryptionTests(unittest.TestCase):
    def test_attribution(self):
        r = protection.attribute_resolvers(["127.0.2.2", "192.168.0.1", "127.0.0.99"], WARP, [], False, False, False)
        self.assertEqual((r[0]["provider"], r[0]["transport"], r[0]["encrypted"]), ("Cloudflare WARP", "DoH", True))
        self.assertFalse(r[1]["encrypted"])
        self.assertIsNone(r[2]["encrypted"])                     # resolver local desconocido: no se inventa
        cfd = [{"address": "127.0.0.1", "port": 53, "upstreams": ["https://1.1.1.1/dns-query"]}]
        r = protection.attribute_resolvers(["127.0.0.1"], None, cfd, False, False, False)
        self.assertEqual((r[0]["provider"], r[0]["encrypted"]), ("cloudflared proxy-dns", True))
        r = protection.attribute_resolvers(["127.0.2.2"], None, [], False, False, False)
        self.assertNotEqual(r[0]["provider"], "Cloudflare WARP")  # sin WARP instalado no se atribuye

    def test_warp_doh_through_tunnel(self):
        res = protection.attribute_resolvers(["127.0.2.2"], WARP, [], False, False, False)
        d = dns(default_links=(), servers=("127.0.2.2",), encrypted=True, resolvers=res,
                upstream_route={"ip": "162.159.36.1", "dev": "wg0"}, effective_source="resolv.conf (modo foreign)")
        found = {f["check"]: f for f in leaks.check_dns(net(tunnel=True), d)}
        self.assertEqual(found["dns_leak_config"]["status"], "pass")
        self.assertEqual(found["dns_plaintext"]["status"], "pass")
        self.assertEqual(found["dns_third_party"]["status"], "warn")
        self.assertIn("Cloudflare WARP", found["dns_third_party"]["observed"])

    def test_doh_outside_tunnel_is_leak(self):
        res = protection.attribute_resolvers(["127.0.2.2"], WARP, [], False, False, False)
        d = dns(default_links=(), servers=("127.0.2.2",), encrypted=True, resolvers=res,
                upstream_route={"ip": "162.159.36.1", "dev": "eth0"}, effective_source="resolv.conf")
        f = leaks.check_dns(net(tunnel=True), d)[0]
        self.assertEqual((f["check"], f["status"]), ("dns_leak_config", "fail"))

    def test_plain_resolver_outside_tunnel(self):
        d = dns(default_links=(), servers=("192.168.1.1",), encrypted=False, server_routes={"192.168.1.1": "eth0"},
                effective_source="resolv.conf")
        found = {f["check"]: f for f in leaks.check_dns(net(tunnel=True), d)}
        self.assertEqual(found["dns_leak_config"]["status"], "fail")
        self.assertEqual(found["dns_plaintext"]["status"], "warn")

    def test_firefox_doh(self):
        home = tempfile.mkdtemp(dir=TMP)
        prof = Path(home, ".mozilla/firefox/abc.default")
        prof.mkdir(parents=True)
        (prof / "prefs.js").write_text('user_pref("network.trr.mode", 3);\nuser_pref("network.trr.uri", "https://dns.example/q");\n')
        old = os.environ["HOME"]
        os.environ["HOME"] = home
        try:
            found = protection.browser_doh()
        finally:
            os.environ["HOME"] = old
        self.assertEqual(found[0]["mode"], "solo DoH")
        self.assertEqual(found[0]["uri"], "https://dns.example/q")


def ks_ext(v4, v6, declared=("ProtonVPN",), mode=1):
    st = lambda ok: {"state": "bloqueado" if ok else "expuesto", "detail": "x"}  # noqa: E731
    return {"verified_ipv4": v4, "verified_ipv6": v6, "declared_by": list(declared),
            "route_protection": {"ipv4": st(v4), "ipv6": st(v6)},
            "clients": [{"client": c, "declared": {"killswitch": mode, "killswitch_mode": "estándar"}} for c in declared]}


class KillSwitchCheckTests(unittest.TestCase):
    def test_verified(self):
        f = leaks.check_killswitch(net(tunnel=True), {}, ks_ext(True, True))
        self.assertEqual(f["status"], "pass")
        self.assertIn("ProtonVPN", f["title"])
        self.assertIn("modo permanente", f["recommendation"])     # modo estándar → aviso de limitación

    def test_ipv4_only(self):
        f = leaks.check_killswitch(net(tunnel=True, v6_dev="eth0"), {}, ks_ext(True, False))
        self.assertEqual((f["status"], f["severity"]), ("warn", "medium"))

    def test_declared_not_verified(self):
        f = leaks.check_killswitch(net(tunnel=True), {}, ks_ext(False, False))
        self.assertIn("no verificado", f["title"])

    def test_none(self):
        f = leaks.check_killswitch(net(tunnel=True), {}, ks_ext(False, False, declared=()))
        self.assertEqual(f["title"], "Túnel sin kill-switch")

    def test_ipv6_dummy_is_blocked(self):
        n = net(tunnel=True, v6_dev="eth0")
        n["egress"]["ipv6"]["dev"] = "pvpnksintrf0"
        n["egress_kind"]["ipv6"] = "dummy"
        self.assertEqual(leaks.check_ipv6(n)["title"], "IPv6 bloqueado por el kill-switch")

    def test_profile_policy(self):
        ctx = {"profile": {"require_killswitch": True, "dns_policy": "encrypted"}, "profile_name": "privado",
               "net": net(tunnel=True), "dns": dns(encrypted=False), "killswitch": {}, "killswitch_ext": ks_ext(False, False, ())}
        checks = {f["check"] for f in leaks.check_profile_policy(ctx)}
        self.assertEqual(checks, {"profile_killswitch", "profile_dns"})
        ctx.update(dns=dns(encrypted=True), killswitch_ext=ks_ext(True, True))
        self.assertEqual(leaks.check_profile_policy(ctx), [])

    def test_tor_exit_counts_for_tor_profiles(self):
        obs = {"tor": {"exit": {"country": "US"}}}
        self.assertEqual(leaks.check_profile(obs, {"forbidden_countries": ["US"]}, None), [])
        found = leaks.check_profile(obs, {"use_tor": True, "forbidden_countries": ["US"]}, None)
        self.assertEqual(found[0]["check"], "profile_geo")


class ProfileGenerationTests(unittest.TestCase):
    def test_generate_adapts_to_system(self):
        e = env()
        e["killswitch"] = ks_ext(True, True)
        e["killswitch"]["clients"][0]["vpn_connections"] = []
        e["dns_effective"] = {"encrypted": True}
        p = profiles.generate(e)
        self.assertEqual(set(p), {"diario", "privado", "anonimo", "alto_riesgo", "laboratorio"})
        self.assertIn("ES", p["privado"]["forbidden_countries"])      # país por zona horaria (Europe/Madrid)
        self.assertTrue(p["diario"]["require_killswitch"])
        self.assertEqual(p["diario"]["dns_policy"], "encrypted")
        self.assertEqual(p["anonimo"]["dns_policy"], "tor")
        self.assertTrue(set(profiles.FOURTEEN_EYES) <= set(p["alto_riesgo"]["forbidden_countries"]))
        self.assertEqual(p["laboratorio"]["allowed_proxies"], ["http://127.0.0.1:8080"])

    def test_no_tor_no_tor_profiles(self):
        e = env()
        e["tor"] = {**e["tor"], "control": [], "socks": []}
        e["proxy"] = {**e["proxy"], "local": []}
        self.assertEqual(set(profiles.generate(e)), {"diario", "privado"})

    def test_write_never_overwrites(self):
        d = tempfile.mkdtemp(dir=TMP)
        path = Path(d, "config.toml")
        path.write_text('[profiles.privado]\ndescription = "mío"\n')
        os.environ["VELA_CONFIG"] = str(path)
        try:
            p = profiles.generate(env())
            res = profiles.write(p, config.load())
            self.assertNotIn("privado", res["written"])
            self.assertIn("diario", res["written"])
            cfg = config.load()
            self.assertEqual(cfg["profiles"]["privado"]["description"], "mío")
            self.assertIn("anonimo", cfg["profiles"])
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            self.assertEqual(profiles.write(p, cfg)["written"], [])     # idempotente
        finally:
            del os.environ["VELA_CONFIG"]


if __name__ == "__main__":
    unittest.main()


class GuardChurnTests(unittest.TestCase):
    def test_primary_guards_are_not_churn(self):
        from vela.store import Store
        from vela.util import now
        st = Store(memory=True)
        for i, fp in enumerate(("G1", "G2", "G3")):
            st.open_interval("s", "p", "tor_guard", fp, ts=now() - 100 * (i + 1))
        tor = {"guards": [{"fp": "G1"}, {"fp": "G2"}, {"fp": "G3"}]}
        self.assertIsNone(leaks.check_guard_churn(st, tor))           # todos son guards actuales de Tor
        tor = {"guards": [{"fp": "G3"}]}
        self.assertEqual(leaks.check_guard_churn(st, tor)["check"], "tor_guard_churn")
        self.assertIsNone(leaks.check_guard_churn(st, None))          # sin lista de guards no se acusa
