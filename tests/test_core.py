import hashlib
import hmac
import os
import random
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path

from vela import analytics, killswitch, leaks, torctl
from vela.forwarder import ProxyForwarder, parse_proxy
from vela.publicip import PublicIPChecker, extract_ip, open_socks5
from vela.rotation import Policy, RotationEngine, SimulatedAdapter, Target, choose
from vela.sessions import SessionTracker, needs_new_session
from vela.store import Store
from vela.util import now

from .helpers import cfg, dns, env, net

TMP = os.environ.get("TMPDIR") or None


# ── servidor de control de Tor falso ────────────────────────────────────────

CIRCS = ("1 BUILT $" + "A" * 40 + "~guard1,$" + "B" * 40 + "~mid1,$" + "C" * 40 + "~exit1 BUILD_FLAGS=NEED_CAPACITY "
         "PURPOSE=GENERAL TIME_CREATED=2026-10-09T10:00:00.000000\n"
         "2 BUILT $" + "A" * 40 + "~guard1,$" + "D" * 40 + "~mid2 PURPOSE=HS_CLIENT_INTRO\n"
         "3 LAUNCHED BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL")


class FakeTor(threading.Thread):
    def __init__(self, path, cookie, bad_hash=False):
        super().__init__(daemon=True)
        self.path, self.cookie, self.bad_hash = path, cookie, bad_hash
        self.srv = socket.socket(socket.AF_UNIX)
        self.srv.bind(path)
        self.srv.listen(5)
        self.signals = []

    def run(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, conn):
        try:
            self._handle(conn)
        except OSError:
            pass  # el cliente cerró la conexión (p. ej. tras rechazar el SERVERHASH)
        finally:
            conn.close()

    def _handle(self, conn):
        f = conn.makefile("rwb")
        authed = False
        cnonce = snonce = None
        for raw in f:
            line = raw.decode().strip()
            out = "250 OK\r\n"
            if line.startswith("PROTOCOLINFO"):
                out = (f'250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="{self.cookie_path}"\r\n'
                       f'250-VERSION Tor="0.4.9.99"\r\n250 OK\r\n')
            elif line.startswith("AUTHCHALLENGE"):
                cnonce = bytes.fromhex(line.split()[2])
                snonce = os.urandom(32)
                sh = hmac.new(torctl.SERVER_KEY, self.cookie + cnonce + snonce, hashlib.sha256).hexdigest()
                if self.bad_hash:
                    sh = "00" * 32
                out = f"250 AUTHCHALLENGE SERVERHASH={sh} SERVERNONCE={snonce.hex()}\r\n"
            elif line.startswith("AUTHENTICATE"):
                expected = hmac.new(torctl.CLIENT_KEY, self.cookie + cnonce + snonce, hashlib.sha256).hexdigest()
                authed = line.split()[1].lower() == expected
                out = "250 OK\r\n" if authed else "515 Authentication failed\r\n"
            elif not authed:
                out = "514 Authentication required.\r\n"
            elif line.startswith("GETINFO"):
                parts = []
                for key in line.split()[1:]:
                    if key == "circuit-status":
                        parts.append("250+circuit-status=\r\n" + CIRCS.replace("\n", "\r\n") + "\r\n.\r\n")
                    elif key == "stream-status":
                        parts.append("250+stream-status=\r\n10 SUCCEEDED 1 example.org:443\r\n.\r\n")
                    elif key.startswith("ns/id/"):
                        fp = key[6:]
                        ip = {"A": "1.1.1.1", "B": "2.2.2.2", "C": "3.3.3.3"}.get(fp[0], "4.4.4.4")
                        parts.append(f"250+{key}=\r\nr nick{fp[0]} AAAA BBBB 2038-01-01 00:00:00 {ip} 9001 0\r\n"
                                     f"s Exit Fast Running Valid\r\nw Bandwidth=1000\r\n.\r\n")
                    elif key == "version":
                        parts.append("250-version=0.4.9.99\r\n")
                    elif key == "status/bootstrap-phase":
                        parts.append('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done\r\n')
                    elif key == "status/circuit-established":
                        parts.append("250-status/circuit-established=1\r\n")
                    elif key == "network-liveness":
                        parts.append("250-network-liveness=up\r\n")
                    elif key == "entry-guards":
                        parts.append("250+entry-guards=\r\n$" + "A" * 40 + "~guard1 up\r\n.\r\n")
                    else:
                        parts.append(f"552 Unrecognized key \"{key}\"\r\n")
                        break
                out = "".join(parts)
                if not out.startswith("552"):
                    out += "250 OK\r\n"
            elif line.startswith("SIGNAL"):
                self.signals.append(line.split()[1])
            elif line == "QUIT":
                f.write(b"250 closing connection\r\n")
                f.flush()
                break
            f.write(out.encode())
            f.flush()
        conn.close()


class TorTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(dir=TMP)
        self.cookie = os.urandom(32)
        cp = Path(self.dir, "cookie")
        cp.write_bytes(self.cookie)
        self.sock = str(Path(self.dir, "control"))
        self.fake = FakeTor(self.sock, self.cookie)
        self.fake.cookie_path = str(cp)
        self.fake.start()

    def tearDown(self):
        self.fake.srv.close()

    def test_reply_parsing(self):
        r = torctl.parse_reply_lines(["250+k=", "a", "..b", ".", "250 OK"])
        self.assertEqual(r[0][3], ["a", ".b"])
        c = torctl.parse_circuit_line(CIRCS.splitlines()[0])
        self.assertEqual([h["nick"] for h in c["path"]], ["guard1", "mid1", "exit1"])
        self.assertEqual(c["purpose"], "GENERAL")
        self.assertIsNone(torctl.parse_circuit_line("x"))

    def test_safecookie_and_queries(self):
        with torctl.TorControl(self.sock) as ctl:
            self.assertEqual(ctl.protocolinfo["version"], "0.4.9.99")
            self.assertEqual(len(ctl.circuits()), 3)
            self.assertEqual(ctl.relay("C" * 40)["ip"], "3.3.3.3")
            ctl.signal("NEWNYM")
        self.assertEqual(self.fake.signals, ["NEWNYM"])

    def test_bad_server_hash_rejected(self):
        bad = Path(self.dir, "bad")
        fake = FakeTor(str(bad), self.cookie, bad_hash=True)
        fake.cookie_path = self.fake.cookie_path
        fake.start()
        with self.assertRaises(torctl.TorControlError):
            torctl.TorControl(str(bad)).connect()
        fake.srv.close()

    def test_observer_status_and_newnym_rate_limit(self):
        obs = torctl.TorObserver(self.sock)
        st = obs.status()
        self.assertTrue(st["available"])
        self.assertEqual(len(st["circuits"]), 1)          # descarta HS y LAUNCHED
        self.assertEqual(st["exit"]["ip"], "3.3.3.3")
        self.assertEqual(st["guard"]["role"], "guard")
        self.assertEqual(st["active"]["streams"], 1)
        self.assertTrue(obs.newnym()["ok"])
        second = obs.newnym()
        self.assertFalse(second["ok"])
        self.assertIn("rate-limit", second["error"])

    def test_unavailable(self):
        st = torctl.TorObserver(str(Path(self.dir, "nope"))).status()
        self.assertFalse(st["available"])


# ── sesiones y persistencia ─────────────────────────────────────────────────

def obs(**kw):
    base = {"profile": "default", "egress_iface": "eth0", "local_ip": "192.168.1.10", "wan_ip": None,
            "public_ip": None, "vpn": None, "proxy": None, "tor": None, "dns": ["192.168.1.1"], "chain": []}
    base.update(kw)
    return base


class SessionTests(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(needs_new_session(None, {}), (True, "inicio"))
        a = {"profile": "p", "egress_iface": "eth0", "vpn": None, "proxy": None, "wan_ip": None, "public_ip": "1.1.1.1"}
        self.assertFalse(needs_new_session(a, {**a, "wan_ip": "5.5.5.5"})[0])          # None → valor: enriquece
        self.assertTrue(needs_new_session(a, {**a, "public_ip": "2.2.2.2"})[0])        # valor → otro valor
        self.assertFalse(needs_new_session(a, {**a, "public_ip": None})[0])            # se pierde el dato
        self.assertTrue(needs_new_session(a, {**a, "vpn": "wg0"})[0])
        self.assertTrue(needs_new_session(a, {**a, "profile": "q"})[0])

    def test_lifecycle_counters_and_persistence(self):
        path = Path(tempfile.mkdtemp(dir=TMP), "t.db")
        st = Store(path)
        tr = SessionTracker(st)
        t0 = now() - 1000
        exit1 = {"fp": "E1", "nick": "e1", "ip": "3.3.3.3", "country": "DE"}
        evs = tr.update(obs(tor={"exit": exit1, "guard": {"fp": "G"}, "circuit": "1"}), ts=t0)
        self.assertEqual(evs[0]["kind"], "session_opened")
        sid = tr.session_id
        evs = tr.update(obs(tor={"exit": {**exit1, "fp": "E2"}, "guard": {"fp": "G"}, "circuit": "2"}), ts=t0 + 600)
        self.assertEqual(tr.session_id, sid)                                           # Tor no abre sesión nueva
        self.assertIn("tor_exit_change", [e["kind"] for e in evs])
        tr.update(obs(vpn={"id": "wg0"}, egress_iface="wg0"), ts=t0 + 900)
        self.assertNotEqual(tr.session_id, sid)
        st.close()
        st = Store(path)                                                               # reabrir: persistencia
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o600")
        sessions = st.sessions()
        self.assertEqual(len(sessions), 2)
        closed = [s for s in sessions if s["ended"]][0]
        self.assertAlmostEqual(closed["duration"], 900, delta=1)
        self.assertEqual(closed["end_reason"], "cambio de egress_iface")
        c = {(r["layer"], r["key"]): r for r in st.counters()}
        self.assertAlmostEqual(c[("tor_exit", "E1")]["total"], 600, delta=1)
        self.assertAlmostEqual(c[("tor_exit", "E2")]["total"], 300, delta=1)
        self.assertEqual(c[("egress_iface", "eth0")]["uses"], 1)
        # recuperación tras parada brusca: cierra lo abierto en el último latido
        SessionTracker(st).recover(t0 + 950)
        self.assertEqual(st.open_sessions(), [])
        self.assertEqual(st.open_intervals(), [])
        res = st.purge(now() + 10)
        self.assertGreaterEqual(res["sessions"], 2)


# ── rotación ────────────────────────────────────────────────────────────────

class FakeKS:
    def __init__(self, ok=True):
        self.ok, self.state, self.calls = ok, {"active": False}, []

    def can_apply(self):
        return (self.ok, "" if self.ok else "sin privilegios")

    def engage(self, endpoints=(), reason=""):
        self.calls.append("engage")
        self.state["active"] = True
        return {"ok": True}

    def release(self):
        self.calls.append("release")
        self.state["active"] = False
        return {"ok": True}


def engine_with(adapter, ks=None, **pol):
    c = cfg(consent={"allow_rotation_changes": True})
    c["rotation"]["sim"] = {"enabled": True, "max_ttl": "45m", "min_ttl": "0", "jitter": "0", "no_repeat": 3,
                            "cooldown": "0", "max_per_hour": 10, **pol}
    st = Store(memory=True)
    eng = RotationEngine(st, c, ks or FakeKS(), emit=lambda *a, **k: None)
    eng.register(adapter)
    return eng, st


class RotationTests(unittest.TestCase):
    def test_policy_ttl_bounds(self):
        p = Policy(max_ttl=2700, min_ttl=300, jitter=600)
        vals = [p.ttl(random.Random(i)) for i in range(200)]
        self.assertTrue(all(2100 <= v <= 2700 for v in vals))
        self.assertGreater(max(vals) - min(vals), 300)

    def test_choose_no_repeat_and_exclusions(self):
        cands = [Target(x, x, country=c) for x, c in (("A", "SE"), ("B", "NL"), ("C", "DE"), ("D", "CH"), ("E", "ES"))]
        hist = [{"target": t, "ts": now() - i * 10} for i, t in enumerate("CBA")]
        p = Policy(no_repeat=3, exclude_countries=["ES"])
        for i in range(30):
            t, rej = choose(cands, hist, p, current="C", rng=random.Random(i))
            self.assertEqual(t.id, "D")                       # A, B, C recientes; E país excluido
        self.assertIn("país excluido", rej["E"])

    def test_cooldown_and_asn(self):
        cands = [Target("A", asn="1"), Target("B", asn="2"), Target("C")]
        hist = [{"target": "A", "ts": now() - 100}]
        pol = Policy(no_repeat=0, cooldown=3600, exclude_asn=["AS2"])
        # sin alternativas verificadas (C no tiene ASN conocido) la exclusión por ASN no se aplica
        t, rej = choose(cands, hist, pol, rng=random.Random(1))
        self.assertIn(t.id, ("B", "C"))
        self.assertIn("cooldown", rej["A"])
        # con una alternativa verificada (D, ASN 3) sí se aplica: "AS2" y "2" son el mismo ASN
        for i in range(20):
            t, rej = choose(cands + [Target("D", asn="3")], hist, pol, rng=random.Random(i))
            self.assertEqual(t.id, "D")
        self.assertIn("ASN", rej["B"])

    def test_success_records_history(self):
        a = SimulatedAdapter("sim", ["A", "B", "C"])
        eng, st = engine_with(a)
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "ok")
        self.assertEqual(a.cur.id, r["to"]["id"])
        self.assertEqual(eng.history("sim")[0]["target"], a.cur.id)
        names = [s["name"] for s in r["steps"]]
        for n in ("destino alternativo", "compatibilidad", "protección contra fugas", "rotación", "verificación",
                  "validación de política"):
            self.assertIn(n, names)

    def test_consent_required(self):
        a = SimulatedAdapter("sim", ["A", "B"])
        eng, _ = engine_with(a)
        eng.cfg["consent"]["allow_rotation_changes"] = False
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "aborted")
        self.assertEqual(a.calls, [])
        self.assertEqual(eng.rotate("sim", dry_run=True)["result"], "dry_run_ok")
        self.assertEqual(a.calls, [])

    def test_rate_limits(self):
        a = SimulatedAdapter("sim", ["A", "B", "C", "D"])
        eng, _ = engine_with(a, max_per_hour=1, no_repeat=0)
        self.assertEqual(eng.rotate("sim", force=True)["result"], "ok")
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "aborted")
        self.assertIn("máximo", r["steps"][0]["detail"])
        eng2, _ = engine_with(SimulatedAdapter("sim", ["A", "B"]), min_ttl="1h")
        self.assertIn("mínimo", eng2.rotate("sim")["steps"][0]["detail"])

    def test_switch_failure_rolls_back(self):
        a = SimulatedAdapter("sim", ["A", "B"], fail_switch=["B"])
        eng, _ = engine_with(a)
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "rolled_back")
        self.assertEqual(a.cur.id, "A")
        self.assertIn(("rollback", "A"), a.calls)

    def test_verify_failure_rolls_back(self):
        a = SimulatedAdapter("sim", ["A", "B"], fail_verify=["B"])
        eng, _ = engine_with(a)
        self.assertEqual(eng.rotate("sim", force=True)["result"], "rolled_back")
        self.assertEqual(a.cur.id, "A")

    def test_failed_rollback_keeps_traffic_blocked(self):
        a = SimulatedAdapter("sim", ["A", "B"], fail_switch=["B"], fail_rollback=True)
        a.needs_killswitch = True
        a.endpoints = lambda t: ["198.51.100.1:51820"]
        ks = FakeKS()
        eng, _ = engine_with(a, ks, require_killswitch=True)
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "failed_closed")
        self.assertEqual(ks.calls, ["engage"])                 # nunca se libera el tráfico
        self.assertTrue(ks.state["active"])

    def test_killswitch_required_but_unavailable(self):
        a = SimulatedAdapter("sim", ["A", "B"])
        a.needs_killswitch = True
        eng, _ = engine_with(a, FakeKS(ok=False), require_killswitch=True)
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "aborted")
        self.assertEqual(a.calls, [])

    def test_killswitch_engaged_and_released(self):
        a = SimulatedAdapter("sim", ["A", "B"])
        a.needs_killswitch = True
        a.endpoints = lambda t: ["198.51.100.1:51820"]
        ks = FakeKS()
        eng, _ = engine_with(a, ks, require_killswitch=True)
        self.assertEqual(eng.rotate("sim", force=True)["result"], "ok")
        self.assertEqual(ks.calls, ["engage", "release"])

    def test_country_policy_violation(self):
        a = SimulatedAdapter("sim", [Target("A"), Target("B", country="RU")])
        eng, _ = engine_with(a, exclude_countries=["RU"])
        a.targets = lambda: [Target("A"), Target("B")]        # el país solo se conoce tras verificar
        a._targets = [Target("A"), Target("B")]
        orig = a.verify
        a.verify = lambda t, timeout=30: {"ok": True, "observed": {"target": t.id, "country": "RU"}} if t.id == "B" else orig(t)
        r = eng.rotate("sim", force=True)
        self.assertEqual(r["result"], "rolled_back")

    def test_due_and_pause(self):
        a = SimulatedAdapter("sim", ["A", "B"])
        eng, _ = engine_with(a)
        eng.state["sim"]["deadline"] = now() - 1
        self.assertEqual(eng.due(), ["sim"])
        eng.paused = True
        self.assertEqual(eng.due(), [])
        self.assertEqual(eng.rotate("sim", force=True)["result"], "aborted")


# ── fugas, analítica, kill-switch ───────────────────────────────────────────

class LeakTests(unittest.TestCase):
    def ctx(self, n, d, profile=None, o=None):
        return {"net": n, "dns": d, "tor": None, "env": env(), "profile": profile or {}, "obs": o or {},
                "store": None, "killswitch": {"active": False}, "timezone": "Europe/Madrid"}

    def test_ipv6_leak(self):
        f = leaks.check_ipv6(net(tunnel=True, v6_dev="eth0", v6_public=True))
        self.assertEqual((f["status"], f["severity"]), ("fail", "high"))
        self.assertEqual(leaks.check_ipv6(net(tunnel=True))["status"], "pass")

    def test_dns_leak_config(self):
        found = leaks.check_dns(net(tunnel=True), dns(default_links=("eth0", "wg0"), tunnel_servers=("10.64.0.1",)))
        self.assertEqual(found[0]["status"], "fail")
        self.assertIn("eth0", found[0]["observed"])
        ok = leaks.check_dns(net(tunnel=True), dns(default_links=("wg0",), tunnel_servers=("10.64.0.1",)))
        self.assertEqual(ok[0]["status"], "pass")

    def test_country_alone_is_not_leak(self):
        r = leaks.check_active_dns({"ok": True, "service": "x", "resolvers": [{"ip": "9.9.9.9", "country": "Lejanía"}],
                                    "service_conclusion": "DNS may be leaking. Some of your DNS servers are from other country"},
                                   net(tunnel=False))
        self.assertEqual(r["status"], "pass")      # sin túnel no hay fuga posible aunque el país difiera

    def test_profile_requires_vpn(self):
        f = leaks.check_tunnel_route(net(tunnel=False), {"require_vpn": True})
        self.assertEqual((f["status"], f["severity"]), ("fail", "high"))

    def test_tz_mismatch(self):
        found = leaks.check_profile({"public_ip": {"geo": {"country": "SE"}}}, {"forbidden_countries": ["SE"]}, "Europe/Madrid")
        checks = {f["check"] for f in found}
        self.assertIn("profile_geo", checks)
        if leaks.tz_country("Europe/Madrid"):
            self.assertIn("tz_mismatch", checks)

    def test_every_finding_is_complete(self):
        for f in leaks.run_passive(self.ctx(net(tunnel=True, v6_dev="eth0", v6_public=True), dns())):
            for k in ("check", "title", "severity", "status", "mode", "method", "evidence", "observed",
                      "limitations", "confidence", "recommendation", "ts"):
                self.assertIn(k, f)

    def test_webrtc(self):
        f = leaks.webrtc_finding(["candidate:1 1 udp 2122260223 192.168.1.10 50000 typ host"], ["192.168.1.10"], [], False)
        self.assertEqual(f["status"], "fail")
        f = leaks.webrtc_finding(["candidate:1 1 udp 2122260223 abcd.local 50000 typ host"], ["192.168.1.10"], [], False)
        self.assertEqual(f["status"], "pass")

    def test_exposure_score_explainable(self):
        found = leaks.run_passive(self.ctx(net(tunnel=False), dns()))
        sc = analytics.exposure_score({"net": net(tunnel=False), "findings": found})
        self.assertTrue(0 <= sc["score"] <= 100)
        self.assertTrue(any(i["present"] for i in sc["indicators"] if i["id"] == "direct_route"))
        self.assertIn("No mide ni garantiza", sc["disclaimer"])


class CorrelationTests(unittest.TestCase):
    def test_shared_ip_between_profiles(self):
        st = Store(memory=True)
        t = now() - 5000
        for prof, start in (("trabajo", t), ("anon", t + 2000)):
            st.open_interval("s", prof, "profile", prof, ts=start)
            st.open_interval("s", prof, "public_ip", "203.0.113.7", ts=start)
        r = analytics.correlation(st, cfg())
        pair = r["pairs"][0]
        self.assertEqual(pair["level"], "high")
        types = {x["type"] for x in pair["risks"]}
        self.assertIn("shared_public_ip", types)
        self.assertIn("simultaneous", types)
        self.assertIn("cookies", r["note"])

    def test_stats_and_timeline(self):
        st = Store(memory=True)
        st.open_interval("s", "p", "country", "SE", "Sweden", ts=now() - 3600)
        st.add_rotation("tor", "x", False, "a", "b", "ok", {})
        s = analytics.stats(st, "day")
        self.assertAlmostEqual(s["time_by_country"][0]["seconds"], 3600, delta=2)
        self.assertEqual(s["rotations"]["total"], 1)
        self.assertTrue(analytics.timeline(st))


class KillSwitchTests(unittest.TestCase):
    def test_ruleset(self):
        rs = killswitch.build_ruleset(["wg0"], ["198.51.100.1:51820", "vpn.example:443", "[2001:db8::1]:1194"], True, ["root"])
        self.assertIn("table inet vela_ks", rs)
        self.assertIn("policy drop", rs)
        self.assertIn('oifname { "wg0" } accept', rs)
        self.assertIn("ip daddr 198.51.100.1 udp dport 51820 accept", rs)
        self.assertIn("ip6 daddr 2001:db8::1 udp dport 1194 accept", rs)
        self.assertNotIn("vpn.example", rs)                    # nunca nombres: requerirían DNS
        self.assertIn("meta skuid 0 accept", rs)
        self.assertNotIn("192.168.0.0/16", killswitch.build_ruleset([], [], allow_lan=False))

    def test_requires_consent(self):
        ks = killswitch.KillSwitch(cfg())
        ok, why = ks.can_apply()
        self.assertFalse(ok)
        self.assertIn("allow_killswitch", why)
        self.assertFalse(ks.engage()["ok"])


# ── red: IP pública, SOCKS5, forwarder ──────────────────────────────────────

def _serve_once(handler):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()
    return srv


class NetIOTests(unittest.TestCase):
    def test_extract_ip(self):
        self.assertEqual(extract_ip('{"IsTor":true,"IP":"185.220.101.1"}'), "185.220.101.1")
        self.assertEqual(extract_ip("203.0.113.9\n"), "203.0.113.9")
        self.assertEqual(extract_ip("2001:db8::1"), "2001:db8::1")
        self.assertIsNone(extract_ip("nada"))

    def test_consent_and_rate_limit(self):
        chk = PublicIPChecker(cfg())
        r = chk.check("default")
        self.assertTrue(r["consent_required"])
        c = cfg(consent={"proxy_ip_checks": True})
        chk = PublicIPChecker(c)
        chk._last["proxy:x"] = now()
        r = chk.check("proxy:x", http_proxy=("127.0.0.1", 1))
        self.assertIn("límite de frecuencia", r["error"])

    def test_socks5_remote_dns(self):
        seen = {}

        def handler(c):
            c.recv(3)
            c.sendall(b"\x05\x00")
            head = c.recv(5)
            name = c.recv(head[4])
            port = struct.unpack(">H", c.recv(2))[0]
            seen.update(atyp=head[3], name=name.decode(), port=port)
            c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00")
            c.sendall(c.recv(100))
            c.close()
        srv = _serve_once(handler)
        s = open_socks5(srv.getsockname(), "check.example", 443, 5)
        s.sendall(b"ping")
        self.assertEqual(s.recv(4), b"ping")
        s.close()
        srv.close()
        self.assertEqual(seen, {"atyp": 3, "name": "check.example", "port": 443})   # dominio, sin DNS local

    def test_forwarder_switch(self):
        def tag(t):
            def handler(c):
                c.recv(100)
                c.sendall(t)
                c.close()
            return handler
        a, b = _serve_once(tag(b"A")), _serve_once(tag(b"B"))
        fw = ProxyForwarder("127.0.0.1:0", f"http://127.0.0.1:{a.getsockname()[1]}").start()
        try:
            for expected, srv in ((b"A", a), (b"B", b)):
                fw.set_upstream(f"http://127.0.0.1:{srv.getsockname()[1]}")
                s = socket.create_connection(fw.addr, timeout=5)
                s.sendall(b"hola")
                self.assertEqual(s.recv(10), expected)
                s.close()
            self.assertTrue(fw.probe_upstream(fw.upstream)[0])
            self.assertFalse(fw.probe_upstream("http://127.0.0.1:1")[0])
        finally:
            fw.stop()
            a.close()
            b.close()
        with self.assertRaises(ValueError):
            ProxyForwarder("0.0.0.0:1088")
        self.assertEqual(parse_proxy("socks5://u:p@10.0.0.1:1080"), ("socks5", "10.0.0.1", 1080))


if __name__ == "__main__":
    unittest.main()
