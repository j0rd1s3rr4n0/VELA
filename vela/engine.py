"""Motor central de VELA.

Una única clase compartida por el daemon (`velad`) y por la CLI cuando el daemon no está en
marcha. Es síncrona y thread-safe; el daemon la ejecuta en hilos y la expone por IPC.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import threading
import time

from . import (analytics, anomaly, config as config_mod, discovery, dns as dns_mod, leaks, network, profiles as profiles_mod,
               protection, worldmap)
from .geo import Geo
from .killswitch import KillSwitch
from .publicip import PublicIPChecker, router_wan_ip
from .rotation import (MullvadAdapter, NetworkManagerAdapter, ProxyAdapter, RotationEngine, TorAdapter,
                       WgQuickAdapter)
from .sessions import SessionTracker, connection_fingerprint
from .store import Store
from .torctl import TorObserver
from .util import fmt_duration, now, parse_duration, redact


class Engine:
    def __init__(self, cfg: dict | None = None, store: Store | None = None, actor: str = "cli", track: bool = True):
        self.track = track      # solo el daemon registra sesiones/intervalos
        self.cfg = cfg or config_mod.load()
        st = self.cfg["storage"]
        self.store = store or Store(st["path"] or None, memory=st["mode"] == "memory")
        self.actor = actor
        self.lock = threading.RLock()
        prof = self.store.get("active_profile")
        if prof in self.cfg["profiles"]:
            self.cfg["active_profile"] = prof
        self.env: dict | None = None
        self.caps: list[dict] = []
        self.notes: list[dict] = []
        geo_cfg = discovery.detect_geoip()
        self.geo = Geo(mmdb_city=next((p for p in geo_cfg["mmdb"] if "City" in p or "city" in p), None),
                       mmdb_asn=next((p for p in geo_cfg["mmdb"] if "ASN" in p or "asn" in p), None))
        self.tor_obs = TorObserver(self.cfg["tor"]["control"], geo=self.geo)
        self.pubip = PublicIPChecker(self.cfg)
        self.ks = KillSwitch(self.cfg, tunnels_fn=lambda: (self.net or {}).get("tunnels", []))
        self.forwarder = None
        self.rot = RotationEngine(self.store, self.cfg, self.ks, emit=self.emit)
        self.rot.external_ks = lambda: self.ks_ext
        self.tracker = SessionTracker(self.store)
        self.net: dict | None = None
        self.ks_ext: dict | None = None      # kill-switches de terceros (ProtonVPN, Mullvad…)
        self.networks: dict | None = None    # inventario de todas las redes
        self.net_rates: dict = {}
        self._vm_alerted: set[str] = set()
        self.dns: dict | None = None
        self.tor: dict | None = None
        self.wan: dict | None = None
        self.public: dict[str, dict] = {}
        self.findings: list[dict] = []
        # último estado guardado por diagnóstico: evita repetir el mismo hallazgo en cada arranque
        self._finding_state: dict[str, tuple[str, float]] = {}
        for f in reversed(self.store.findings(limit=500)):
            self._finding_state[f["check_id"] + f["title"]] = (f["status"], f["ts"])
        self.obs: dict | None = None
        self.timers: dict[str, float] = {}
        self.dirty: set[str] = set()
        self.subscribers: list = []
        self.emergency = self.store.get("emergency", False)
        self.rot.paused = self.emergency
        self.started = now()
        self.revision = 0            # sube con cada invalidación para que la UI detecte cambios

    # ── eventos ──
    def emit(self, kind: str, severity: str = "info", data: dict | None = None) -> dict:
        ev = self.store.add_event(kind, severity, data, session_id=self.tracker.session_id,
                                  profile=self.cfg["active_profile"])
        for q in list(self.subscribers):
            try:
                q.put_nowait(ev)
            except Exception:  # noqa: BLE001
                pass
        return ev

    @property
    def profile(self) -> dict:
        return self.cfg["profiles"][self.cfg["active_profile"]]

    # ── descubrimiento ──
    def discover(self) -> dict:
        with self.lock:
            self.env = discovery.discover()
            self.notes, rec_cfg = discovery.recommend(self.env)
            self.caps = discovery.capabilities(self.env)
            self._register_adapters()
            # Perfiles automáticos adaptados a lo que hay en ESTE sistema (VPN/Tor/proxies/DNS).
            profiles_mod.merge_adaptive(self.cfg, self.env)
            stored = self.store.get("active_profile")
            if stored in self.cfg["profiles"]:
                self.cfg["active_profile"] = stored
            return {"environment": self.env, "capabilities": self.caps, "notes": self.notes, "suggested_config": rec_cfg}

    def _register_adapters(self):
        env = self.env
        if env["tor"]["control"] or env["tor"]["socks"]:
            self.rot.register(TorAdapter(self.tor_obs))
        pool = self.cfg["rotation"]["proxy"].get("pool") or []
        if pool and self.forwarder:
            self.rot.register(ProxyAdapter(self.forwarder, pool, self.geo))
        vpn_pref = self.cfg["rotation"]["vpn"].get("adapter", "auto")
        if vpn_pref in ("auto", "mullvad") and "mullvad" in env["vpn"]["providers"]:
            self.rot.register(MullvadAdapter())
        elif vpn_pref in ("auto", "networkmanager") and any(
                c["type"] in ("vpn", "wireguard") for c in env["vpn"]["networkmanager"] or []):
            self.rot.register(NetworkManagerAdapter(self.cfg["rotation"]["vpn"].get("endpoints", {})))
        elif vpn_pref in ("auto", "wg-quick") and env["vpn"]["wireguard"]["configs"]:
            self.rot.register(WgQuickAdapter())

    def start_forwarder(self):
        from .forwarder import ProxyForwarder
        pc = self.cfg["rotation"]["proxy"]
        pool = pc.get("pool") or []
        if pc.get("enabled") and pool:
            self.forwarder = ProxyForwarder(pc.get("listen", "127.0.0.1:1088"), pool[0]).start()
            self.rot.register(ProxyAdapter(self.forwarder, pool, self.geo))

    # ── observación ──
    def refresh_network(self):
        snap = network.snapshot()
        kinds = {i["name"]: i["kind"] for i in snap["interfaces"]}
        ks_ext = protection.detect_killswitches(kinds)
        with self.lock:
            for ev in network.diff(self.net, snap):
                kind = ev.pop("kind")
                sev = ev.pop("severity")
                self.emit(kind, sev, ev)
            prev = self.ks_ext
            if prev is not None and (prev["verified_ipv4"], prev["verified_ipv6"]) != (ks_ext["verified_ipv4"],
                                                                                    ks_ext["verified_ipv6"]):
                lost = (prev["verified_ipv4"] and not ks_ext["verified_ipv4"]) or \
                       (prev["verified_ipv6"] and not ks_ext["verified_ipv6"])
                self.emit("killswitch_change", "high" if lost and snap["tunnels"] else "info",
                          {"ipv4": ks_ext["route_protection"]["ipv4"]["detail"],
                           "ipv6": ks_ext["route_protection"]["ipv6"]["detail"], "declared_by": ks_ext["declared_by"]})
            self.ks_ext = ks_ext
            self.net = snap

    def refresh_networks(self):
        from . import networks as networks_mod
        inv = networks_mod.inventory(self.net, self.dns)
        known = self.store.get("networks_known", {}) or {}
        evs = networks_mod.diff(self.networks, inv, known)
        with self.lock:
            self.net_rates = networks_mod.rates(self.networks, inv)
            for ev in evs:
                if ev["kind"] == "vm_isolation_broken":
                    if ev["data"]["network"] in self._vm_alerted:
                        continue
                    self._vm_alerted.add(ev["data"]["network"])
                self.emit(ev["kind"], ev["severity"], ev["data"])
            self.networks = inv
        self.store.put("networks_known", known)

    def refresh_dns(self):
        snap = dns_mod.snapshot()
        with self.lock:
            if self.dns and self.dns.get("all_servers") != snap.get("all_servers"):
                self.emit("dns_change", "warning", {"before": self.dns.get("all_servers"), "after": snap.get("all_servers")})
            if self.dns and self.dns.get("encrypted") != snap.get("encrypted"):
                self.emit("dns_encryption_change", "high" if snap.get("encrypted") is False else "info",
                          {"before": self.dns.get("encrypted"), "after": snap.get("encrypted"),
                           "resolvers": [f"{r['addr']} {r['provider']} {r['transport']}"
                                         for r in snap["encryption"]["resolvers"]]})
            if self.dns and self.dns.get("default_links") != snap.get("default_links"):
                self.emit("dns_route_change", "info", {"before": self.dns.get("default_links"),
                                                       "after": snap.get("default_links")})
            self.dns = snap

    def refresh_tor(self):
        st = self.tor_obs.status()
        with self.lock:
            prev = self.tor or {}
            if prev.get("available") and not st.get("available"):
                self.emit("tor_unavailable", "high", {"error": st.get("error")})
            elif not prev.get("available") and st.get("available") and prev:
                self.emit("tor_available", "info", {"version": st.get("version")})
            self.tor = st

    def refresh_wan(self):
        if not self.cfg["router"].get("upnp"):
            return
        res = router_wan_ip(local_ip=(self.net or {}).get("local_ip"))
        with self.lock:
            if res.get("ok"):
                res["geo"] = self.geo.lookup(res["ip"])
                if self.wan and self.wan.get("ok") and self.wan["ip"] != res["ip"]:
                    self.emit("wan_ip_change", "warning", {"before": self.wan["ip"], "after": res["ip"]})
                if res.get("cgnat") or res.get("double_nat"):
                    self.emit("cgnat_detected", "info", {"wan_ip": res["ip"], "cgnat": res["cgnat"]})
            self.wan = res

    def refresh_public(self, route: str | None = None, force: bool = False) -> list[dict]:
        """route: 'default' (ruta por defecto: directa o VPN), 'tor', o None = todas las permitidas."""
        results = []
        routes = [route] if route else ["default", "tor"]
        for r in routes:
            if r == "tor":
                socks = (self.env or {}).get("tor", {}).get("socks") or []
                if not socks:
                    continue
                res = self.pubip.check("tor", socks=("127.0.0.1", socks[0]), force=force)
            else:
                via = ((self.net or {}).get("via_tunnel") or {}).get("ipv4")
                learn = self.cfg["public_ip"].get("learn_real_ip") and now() - self.timers.get("learn_real", 0) > 3600
                if self.cfg["public_ip"].get("require_tunnel", True) and self.net is not None and not via and learn:
                    self.timers["learn_real"] = now()
                    res = self.pubip.check("default", force=True)
                    res["learned_real_ip"] = True
                elif self.cfg["public_ip"].get("require_tunnel", True) and self.net is not None and not via:
                    res = {"route": "default", "ts": now(), "ok": False, "skipped": True,
                           "error": _("omitida: sin túnel, la consulta expondría tu IP real "
                                    "(public_ip.require_tunnel = true)")}
                else:
                    res = self.pubip.check("default", force=force)
            if res.get("ok"):
                res["geo"] = self.geo.lookup(res["ip"])
                if r == "default":
                    self._verify_public(res)
                prev = self.public.get(r)
                if prev and prev.get("ok") and prev["ip"] != res["ip"]:
                    self.emit("public_ip_change", "warning" if r == "default" else "info",
                              {"route": r, "before": prev["ip"], "after": res["ip"],
                               "country": res["geo"].get("country")})
                if r == "tor" and res.get("is_tor") is False:
                    self.emit("tor_check_failed", "critical", {"detail": _("check.torproject.org dice que NO sales por Tor")})
            if res.get("ok") or res.get("consent_required") or r not in self.public:
                self.public[r] = res
            results.append(res)
        return results

    def _verify_public(self, res: dict):
        """¿La IP que ve Internet es la de la VPN? Compara con tus IPs reales conocidas y con el país del servidor."""
        from . import intel
        via = ((self.net or {}).get("via_tunnel") or {}).get("ipv4")
        res["via_tunnel"] = bool(via)
        own = intel.own_ips(self.store, self)
        res["is_real_ip"] = res["ip"] in own
        res["own_known"] = bool(own)
        if via and res["is_real_ip"]:
            res["leak"] = "IP real"
            self.emit("public_ip_is_real", "critical", {"ip": res["ip"], "detail": _("Con la VPN activa, Internet ve tu "
                                                        "IP real: el tráfico no está saliendo por el túnel")})
        vpn = (self.obs or {}).get("vpn") or {}
        exp_cc = ((vpn.get("geo") or {}).get("source") == "nombre del servidor") and (vpn.get("geo") or {}).get("country")
        got_cc = (res.get("geo") or {}).get("country")
        if via and exp_cc and got_cc and exp_cc != got_cc:
            res["country_mismatch"] = {"expected": exp_cc, "observed": got_cc}
            self.emit("public_ip_country_mismatch", "warning", {"expected": exp_cc, "observed": got_cc, "ip": res["ip"],
                                                                "note": _("la GeoIP local puede estar desactualizada")})
        if not via:
            # sin túnel la IP vista es la real: se recuerda para detectar fugas futuras
            sid = self.tracker.session_id
            if sid:
                self.store.open_interval(sid, self.cfg["active_profile"], "real_ip", res["ip"], res["ip"])

    def build_obs(self) -> dict:
        net = self.net or {}
        tor = self.tor or {}
        egress = (net.get("egress") or {}).get("ipv4") or {}
        pub = self.public.get("default") if (self.public.get("default") or {}).get("ok") else None
        vpn = None
        if net.get("via_tunnel", {}).get("ipv4"):
            vpn = {"id": egress.get("dev"), "label": f"túnel {egress.get('dev')}", "server": None, "geo": {}}
            providers = (self.env or {}).get("vpn", {}).get("providers", {})
            for name, info in providers.items():
                if info.get("status") and name not in ("cloudflare-warp", "tailscale", "zerotier"):
                    vpn["label"] = f"{name}: {info['status']}"
            # Conexión VPN activa de NetworkManager sobre la interfaz de salida (p. ej. "ProtonVPN CH-XX#2")
            for c in (self.ks_ext or {}).get("clients", []):
                for vc in c.get("vpn_connections", []):
                    if vc["active"] and vc["device"] == egress.get("dev"):
                        vpn.update(id=f"{c['client']}:{egress.get('dev')}", label=vc["name"], server=vc["name"],
                                   provider=c["client"])
                        cc = protection.proton_exit_country(vc["name"])
                        if cc:
                            vpn["geo"] = {**self.geo.country_info(cc), "source": "nombre del servidor"}
            if pub:
                vpn["geo"] = pub.get("geo") or {}
        proxy = None
        if self.forwarder and self.forwarder.upstream:
            proxy = {"id": self.forwarder.upstream, "label": self.forwarder.upstream}
        tor_part = None
        if tor.get("available") and tor.get("active"):
            act = tor["active"]
            tor_part = {"exit": tor.get("exit"), "guard": tor.get("guard"),
                        "middle": act["path"][1] if len(act["path"]) > 2 else None,
                        "circuit": act["id"], "circuit_created": act.get("created")}
        wan = self.wan if (self.wan or {}).get("ok") else None
        home = self.home_location()
        chain = [{"type": "device", "label": os.uname().nodename, "ip": net.get("local_ip"),
                  "iface": egress.get("dev"), **home}]
        if net.get("gateway"):
            chain.append({"type": "router", "label": net["gateway"], "ip": wan["ip"] if wan else None,
                          "note": _("IP WAN por UPnP") if wan else _("IP WAN desconocida"), **home})
        if vpn:
            chain.append({"type": "vpn", "label": vpn["label"], "ip": vpn.get("server"), **_geo(vpn.get("geo"))})
        if proxy:
            chain.append({"type": "proxy", "label": proxy["label"]})
        why_not = (self.public.get("default") or {}).get("error") or _("pendiente de la primera comprobación")
        chain.append({"type": "internet", "label": pub["ip"] if pub else _("IP pública no comprobada"),
                      "note": None if pub else why_not,
                      "ip": pub["ip"] if pub else None, **_geo((pub or {}).get("geo"))})
        tor_chain = []
        if tor_part:
            for role in ("guard", "middle", "exit"):
                hop = tor_part.get(role)
                if hop:
                    tor_chain.append({"type": f"tor-{role}", "label": f"{hop.get('nick')} ({hop.get('ip')})",
                                      "ip": hop.get("ip"), "fp": hop.get("fp"), **_geo(hop)})
        obs = {
            "profile": self.cfg["active_profile"], "egress_iface": egress.get("dev"), "local_ip": net.get("local_ip"),
            "gateway": net.get("gateway"), "wan_ip": wan["ip"] if wan else None,
            "wan_geo": (wan or {}).get("geo"), "public_ip": pub, "vpn": vpn, "proxy": proxy, "tor": tor_part,
            "dns": (self.dns or {}).get("all_servers", []), "chain": chain, "tor_chain": tor_chain,
        }
        obs["fingerprint"] = connection_fingerprint(obs)
        obs["chain_label"] = " → ".join(h["type"] for h in chain)
        return obs

    def home_location(self) -> dict:
        if (self.wan or {}).get("ok") and (self.wan.get("geo") or {}).get("lat") is not None:
            g = self.wan["geo"]
            return {"lat": g["lat"], "lon": g["lon"], "country": g["country"], "geo_source": "IP WAN (GeoIP)"}
        pub = self.public.get("default") or {}
        if pub.get("ok") and not pub.get("via_tunnel") and (pub.get("geo") or {}).get("lat") is not None:
            g = pub["geo"]
            return {"lat": g["lat"], "lon": g["lon"], "country": g["country"], "geo_source": "tu IP pública real (GeoIP)"}
        tz = discovery.detect_identity().get("timezone")
        cc = leaks.tz_country(tz)
        info = self.geo.country_info(cc)
        return {"lat": info["lat"], "lon": info["lon"], "country": cc, "geo_source": f"zona horaria {tz}"}

    def update_sessions(self):
        with self.lock:
            self.obs = self.build_obs()
            if not self.track:
                return
            for ev in self.tracker.update(self.obs):
                self.emit(ev["kind"], ev["severity"], ev["data"])

    def run_leaks(self, active: bool = False) -> list[dict]:
        with self.lock:
            if self.env is None:
                self.discover()
            if self.net is None:
                self.refresh_network()
            if self.dns is None:
                self.refresh_dns()
            obs = self.obs or self.build_obs()
            ctx = {"net": self.net, "dns": self.dns, "tor": self.tor, "env": self.env, "profile": self.profile,
                   "profile_name": self.cfg["active_profile"], "obs": obs, "store": self.store,
                   "killswitch": self.ks.state, "killswitch_ext": self.ks_ext, "networks": self.networks,
                   "leakwatch": getattr(self, "leakwatcher", None) and self.leakwatcher.state,
                   "public": self.public,
                   "timezone": self.env["identity"]["timezone"]}
            found = leaks.run_passive(ctx)
        if active:
            if self.cfg["consent"].get("active_dns_leak_test"):
                res = dns_mod.active_leak_test(self.cfg["dns"]["leak_test_url"])
                found.append(leaks.check_active_dns(res, self.net))
            else:
                found.append(leaks.finding("dns_leak_active", _("Test activo de fugas DNS no ejecutado"), "info",
                                           "unknown", "activa", "—", None, _("sin consentimiento"),
                                           _("Requiere consent.active_dns_leak_test = true (el servicio verá tu IP)."),
                                           "—", _("Actívalo si quieres confirmar la configuración observada.")))
        with self.lock:
            self.findings = found
            for f in found:
                prev = self._finding_state.get(f["check"] + f["title"])
                if not prev or prev[0] != f["status"] or now() - prev[1] > 3600:
                    self.store.add_finding(f, self.cfg["active_profile"])
                    self._finding_state[f["check"] + f["title"]] = (f["status"], now())
                    if f["status"] == "fail" and (not prev or prev[0] != "fail"):
                        self.emit("finding", f["severity"], {"check": f["check"], "title": f["title"]})
        return found

    # ── ciclo ──
    def _due(self, name: str, interval_key: str) -> bool:
        iv = parse_duration(self.cfg["monitor"][interval_key])
        if name in self.dirty or now() - self.timers.get(name, 0) >= iv:
            self.dirty.discard(name)
            self.timers[name] = now()
            return True
        return False

    def tick(self):
        """Una iteración del bucle de monitorización (el daemon la llama cada segundo)."""
        changed = False
        if self.env is None:
            self.discover()
        if self._due("network", "network_interval"):
            self.refresh_network()
            changed = True
        if self._due("dns", "dns_interval"):
            self.refresh_dns()
            changed = True
        if self._due("networks", "network_interval"):
            try:
                self.refresh_networks()
            except Exception as e:  # noqa: BLE001 — docker/virsh pueden fallar sin afectar al resto
                self.emit("networks_error", "info", {"error": str(e)})
        if self._due("tor", "tor_interval"):
            self.refresh_tor()
            changed = True
        if self._due("wan", "router_wan_interval"):
            self.refresh_wan()
            changed = True
        via = ((self.net or {}).get("via_tunnel") or {}).get("ipv4")
        pub_key = "realtime_interval" if via else "public_ip_interval"
        iv = parse_duration(self.cfg["public_ip"][pub_key] if via else self.cfg["monitor"]["public_ip_interval"])
        if "public" in self.dirty or now() - self.timers.get("public", 0) >= iv:
            forced = "public" in self.dirty
            self.dirty.discard("public")
            self.timers["public"] = now()
            self.refresh_public(force=forced)
            changed = True
        if changed:
            self.update_sessions()
        if self._due("leaks", "leak_interval"):
            self.run_leaks()
        try:                                   # línea base de anomalías (cada minuto)
            anomaly.maybe_emit(self, interval=parse_duration(self.cfg["anomaly"].get("interval", "60s")))
        except Exception as e:  # noqa: BLE001 — una anomalía no debe parar el daemon
            self.emit("anomaly_error", "info", {"error": str(e)})
        # Redescubrimiento: cada 10 min o tras un cambio de red (nuevo túnel, Tor Browser abierto…)
        if "rediscover" in self.dirty or now() - self.timers.setdefault("rediscover", now()) >= 600:
            self.dirty.discard("rediscover")
            self.timers["rediscover"] = now()
            self.discover()
        for layer in self.rot.due():
            res = self.rotate(layer, reason=_("tiempo máximo alcanzado"))
            if res["result"] not in ("ok", "dry_run_ok"):
                # evita reintentar cada segundo: reprograma según la política
                st = self.rot.state[layer]
                st["deadline"] = now() + max(60, self.rot.policy(layer).min_ttl)
        self.store.put("heartbeat", now())

    def mark_dirty(self, *names):
        self.dirty.update(names)

    # ── invalidación inmediata del estado ──
    # Las acciones que cambian el sistema (DNS, MAC, kill-switch, perfil, ajustes…) deben
    # tirar las caches; si no, la UI sigue pintando el estado anterior hasta el siguiente
    # temporizador (DNS 2m, fugas 5m…). `invalidate` refresca ya y vuelve a calcular fugas.
    DOMAIN_CACHES = {
        "network": ("net", "ks_ext", "obs", "findings"),
        "networks": ("networks", "net_rates", "findings"),
        "dns": ("dns", "obs", "findings"),
        "tor": ("tor", "obs", "findings"),
        "leaks": ("findings", "obs"),
        "profiles": ("obs", "findings"),
        "anomalies": (),
        "public": ("findings",),
        "all": ("net", "ks_ext", "networks", "net_rates", "dns", "tor", "findings", "obs"),
    }

    def invalidate(self, *domains, run_leaks: bool = True) -> dict:
        """Olvida las caches de los dominios indicados y las reconstruye ahora."""
        wanted = {str(d) for d in domains if d} or {"all"}
        unknown = wanted - set(self.DOMAIN_CACHES)
        if unknown:
            raise ValueError(_("dominio de refresco desconocido: {names}", names=", ".join(sorted(unknown))))
        if "all" in wanted:
            wanted = {k for k in self.DOMAIN_CACHES if k != "all"}
        refreshed: set[str] = set()
        with self.lock:
            for domain in wanted:
                for attr in self.DOMAIN_CACHES.get(domain, ()):
                    if attr == "net_rates":
                        self.net_rates = {}
                    elif attr == "findings":
                        self.findings = []
                    elif attr == "net":
                        self.net = None
                    elif attr == "networks":
                        self.networks = None
                    elif attr == "dns":
                        self.dns = None
                    elif attr == "tor":
                        self.tor = None
                    elif attr == "ks_ext":
                        self.ks_ext = None
                    elif attr == "obs":
                        self.obs = None
        # Orden importante: red → DNS/Tor → inventario de redes → fugas → sesión.
        if wanted & {"network", "networks"}:
            self.refresh_network()
            refreshed.add("network")
        if "dns" in wanted:
            self.refresh_dns()
            refreshed.add("dns")
        if "tor" in wanted:
            self.refresh_tor()
            refreshed.add("tor")
        if wanted & {"networks", "network", "dns"}:
            self.refresh_networks()
            refreshed.add("networks")
        if "public" in wanted:
            self.mark_dirty("public")
            refreshed.add("public")
        if "anomalies" in wanted:
            try:
                anomaly.maybe_emit(self, interval=0)
                refreshed.add("anomalies")
            except Exception as e:  # noqa: BLE001
                self.emit("anomaly_error", "info", {"error": str(e)})
        if run_leaks:
            self.run_leaks()
            refreshed.add("leaks")
        if self.obs is None:
            self.obs = self.build_obs()
        self.update_sessions()
        with self.lock:
            self.revision += 1
            revision = self.revision
        self.emit("state_refresh", "info", {"domains": sorted(refreshed), "revision": revision})
        return {"revision": revision, "domains": sorted(refreshed)}

    def reload_config(self) -> dict:
        """Recarga config.toml + app-settings.toml en caliente (tras importar o borrar datos)."""
        new = config_mod.load()
        with self.lock:
            self.cfg.clear()
            self.cfg.update(new)
            if self.env is not None:
                profiles_mod.merge_adaptive(self.cfg, self.env)
            stored = self.store.get("active_profile")
            if stored in self.cfg["profiles"]:
                self.cfg["active_profile"] = stored
        return {"profile": self.cfg["active_profile"], "revision": self.revision}

    # ── API (la misma para IPC, CLI local, TUI y GUI) ──
    def ensure_fresh(self):
        if self.env is None:
            self.discover()
        if self.net is None:
            self.refresh_network()
        if self.dns is None:
            self.refresh_dns()
        if self.tor is None:
            self.refresh_tor()
        if self.obs is None:
            self.obs = self.build_obs()

    def api_status(self) -> dict:
        self.ensure_fresh()
        with self.lock:
            sess = self.store.sessions(limit=1)
            cur = sess[0] if sess and sess[0]["ended"] is None else None
            counters = self.store.counters()
            live = {c["layer"]: c for c in counters if c["active"]}
            findings = self.findings or []
            score = analytics.exposure_score({"net": self.net, "findings": findings,
                                              "proxy_active": bool(self.obs and self.obs.get("proxy")),
                                              "session_age": cur["duration"] if cur else 0})
            return {
                "ts": now(), "revision": self.revision,
                "profile": self.cfg["active_profile"], "emergency": self.emergency,
                "obs": self.obs, "session": cur, "live_counters": live,
                "tor": _tor_summary(self.tor), "wan": self.wan, "public": self.public, "dns": self.dns,
                "net": {"egress": self.net["egress"], "tunnels": self.net["tunnels"], "via_tunnel": self.net["via_tunnel"],
                        "local_ip": self.net["local_ip"], "gateway": self.net["gateway"]},
                "rotation": self.rot.status(), "killswitch": {**self.ks.status(), "external": self.ks_ext},
                "forwarder": self.forwarder.status() if self.forwarder else None,
                "findings": [f for f in findings if f["status"] in ("fail", "warn")],
                "exposure": score, "uptime": now() - self.started, "consent": self.cfg["consent"],
            }

    def api_refresh(self, domains: list[str] | None = None) -> dict:
        """Fuerza la invalidación y devuelve estado + recomendaciones ya recalculados."""
        self.invalidate(*(domains or ["all"]))
        return {"revision": self.revision, "status": self.api_status(), "fixes": self.api_fixes()}

    def api_discover(self) -> dict:
        return self.discover()

    def api_network(self) -> dict:
        self.refresh_network()
        return self.net

    def api_networks(self) -> dict:
        self.ensure_fresh()
        if self.networks is None or now() - self.networks["ts"] > 10:
            self.refresh_networks()
        known = self.store.get("networks_known", {}) or {}
        return {**self.networks, "rates": self.net_rates,
                "known": [{"id": k, "label": v.get("label"), "gateway": v.get("gw_ip"), "gateway_mac": v.get("gw_mac"),
                           "subnet": v.get("subnet"), "first": v.get("first"), "last": v.get("last"),
                           "devices": len(v.get("devices") or {})} for k, v in known.items() if v.get("gw_mac")]}

    def api_leakwatch(self) -> dict:
        """Estado en tiempo real: IP pública, túnel y conexiones clasificadas (fugas)."""
        from . import leakwatch
        self.ensure_fresh()
        st = self.leakwatcher.state if getattr(self, "leakwatcher", None) and self.leakwatcher.state else None
        if st is None or now() - st["ts"] > 10:
            self.refresh_network()
            st = leakwatch.classify(leakwatch.read_sockets(), self.net,
                                    set(self.cfg["leakwatch"].get("allow") or []), leakwatch.owners())
        from . import intel
        ips = list(dict.fromkeys(f["remote"] for f in st["flows"]))
        vt = intel.cached_many(self.store, ips)
        from . import torcheck
        cons, exits = self._tor_sources()
        flows = []
        for f in st["flows"]:
            g = self.geo.lookup(f["remote"])
            tc = torcheck.classify(f["remote"], cons, exits)
            f = {**f, "tor": tc["verdict"] if tc["verdict"] in ("exit", "relay") else None,
                 "tor_nick": (tc["relays"][0]["nick"] if tc["relays"] else None)}
            score = intel.vt_score(vt.get(f["remote"]))
            flows.append({**f, "country": g.get("country"), "country_name": g.get("country_name"),
                          "city": g.get("city"), "asn": g.get("asn"), "org": g.get("org"), "vt": score,
                          "lat": g.get("lat"), "lon": g.get("lon")})
        live = getattr(self, "intel_live", None)
        return {**st, "flows": flows, "public": self.public, "egress": self.net["egress"], "killswitch": self.ks_ext,
                "profile_requires_vpn": bool(self.profile.get("require_vpn")),
                "intel_live": live.state if live else {"status": "solo con el daemon"},
                "vt_flagged": sum(1 for f in flows if f["vt"] and (f["vt"]["malicious"] or f["vt"]["suspicious"]))}

    def api_routes(self) -> dict:
        """Cómo viaja el tráfico: programa → directo/proxy/Tor → VPN o no → lo que ve el destino."""
        import re
        from . import leakwatch, routes
        lw = self.api_leakwatch()
        env = self.env
        local = env["proxy"]["local"]
        tor_ports = env["tor"]["socks"]
        ports = {p["port"] for p in local if p["kind"] in ("http", "socks5")} | set(tor_ports)
        loop = [s for s in leakwatch.read_sockets() if s["remote"] in ("127.0.0.1", "::1") and s["rport"] in ports]
        loop_owners = leakwatch.owners({s["inode"] for s in loop}, cache=False)
        pids = {}
        for l in env.get("listening", []):
            m = re.search(r"pid (\d+)", l.get("owner") or "")
            if m and l["port"] in ports:
                pids[l["port"]] = int(m.group(1))
        res = routes.build(lw["flows"], loop, loop_owners, local, lw["tunnels"], self.public, tor_ports, pids)
        res["proxies"] = local
        return res

    def api_vpn_list(self) -> dict:
        self.ensure_fresh()
        env = self.env
        return {"capabilities": [c for c in self.caps if c["area"] == "VPN"],
                "networkmanager": [c for c in env["vpn"]["networkmanager"] or [] if c["type"] in ("vpn", "wireguard")],
                "wireguard": env["vpn"]["wireguard"], "openvpn_configs": env["vpn"]["openvpn_configs"],
                "providers": env["vpn"]["providers"], "tunnels": self.net["tunnels"],
                "via_tunnel": self.net["via_tunnel"], "adapter": getattr(self.rot.adapters.get("vpn"), "name", None)}

    def api_proxy_list(self) -> dict:
        self.ensure_fresh()
        px = self.env["proxy"]
        listening = {l["port"]: l for l in self.env.get("listening", [])}
        local = []
        for p in px["local"]:
            l = listening.get(p["port"], {})
            ok, err = (True, None)
            try:
                import socket
                socket.create_connection(("127.0.0.1", p["port"]), timeout=1).close()
            except OSError as e:
                ok, err = False, str(e)
            local.append({**p, "bind": l.get("addr"), "owner": l.get("owner"), "reachable": ok, "error": err})
        return {"local": local, "ssh_tunnels": px["ssh_tunnels"], "proxychains": redact(px["proxychains"]),
                "env": px["env"], "desktop": px["desktop"], "pool": self.cfg["rotation"]["proxy"].get("pool", []),
                "forwarder": self.forwarder.status() if self.forwarder else None}

    def api_tor_status(self) -> dict:
        self.refresh_tor()
        return {**(self.tor or {}), "rotation": self.rot.status().get("tor"),
                "tor_check": self.public.get("tor")}

    def api_dns_check(self, active: bool = False) -> dict:
        self.refresh_dns()
        self.obs = None
        self.ensure_fresh()
        found = [f for f in self.run_leaks(active=active) if f["check"].startswith("dns")]
        return {"snapshot": self.dns, "findings": found}

    def api_public_ip(self, route: str | None = None, force: bool = True) -> list[dict]:
        self.ensure_fresh()
        res = self.refresh_public(route, force=force)
        self.update_sessions()
        return res

    def api_router(self) -> dict:
        self.ensure_fresh()
        self.refresh_wan()
        return self.wan

    def api_sessions(self, limit: int = 50, since: float | None = None, profile: str | None = None) -> list[dict]:
        return self.store.sessions(limit, since, profile)

    def api_counters(self, layer: str | None = None, since: float | None = None, profile: str | None = None):
        rows = self.store.counters(layer, since, profile)
        for r in rows:
            r["total_fmt"] = fmt_duration(r["total"])
            r["current_fmt"] = fmt_duration(r["current"]) if r["current"] else None
        return rows

    def api_events(self, limit: int = 100, since: float | None = None, min_severity: str | None = None):
        return self.store.events(limit, since, min_severity=min_severity)

    def api_leaks(self, active: bool = False) -> list[dict]:
        self.ensure_fresh()
        return self.run_leaks(active=active)

    def api_rotate(self, layer: str, dry_run: bool = True, force: bool = False) -> dict:
        self.ensure_fresh()
        res = self.rotate(layer, reason="manual", dry_run=dry_run, force=force)
        self.store.audit(self.actor, f"rotate {layer}", {"dry_run": dry_run, "result": res["result"]})
        if not dry_run:
            self.invalidate("network", "tor", "leaks")
        return res

    def rotate(self, layer: str, reason: str, dry_run: bool = False, force: bool = False) -> dict:
        res = self.rot.rotate(layer, reason=reason, dry_run=dry_run, force=force)
        if not dry_run:
            self.emit("rotation", "info" if res["result"] == "ok" else "warning",
                      {"layer": layer, "result": res["result"], "to": res.get("to"), "reason": reason})
            self.mark_dirty("tor" if layer == "tor" else "network", "public")
        return res

    def api_rotation_status(self) -> dict:
        self.ensure_fresh()
        return {"status": self.rot.status(), "history": self.store.rotations(limit=30),
                "policies": {k: v for k, v in self.cfg["rotation"].items()}}

    def api_profiles(self) -> dict:
        if self.env is None:
            self.discover()
        return {"active": self.cfg["active_profile"], "profiles": self.cfg["profiles"]}

    def api_profile_activate(self, name: str) -> dict:
        if self.env is None:
            self.discover()
        if name not in self.cfg["profiles"]:
            raise ValueError(_("perfil desconocido: {name}", name=name))
        with self.lock:
            old = self.cfg["active_profile"]
            self.cfg["active_profile"] = name
            self.store.put("active_profile", name)
            self.store.audit(self.actor, "profile_activate", {"from": old, "to": name})
            self.emit("profile_change", "info", {"from": old, "to": name})
            self.update_sessions()
        self.invalidate("profiles", "leaks")
        return {"active": name}

    def api_profiles_generate(self, write: bool = False) -> dict:
        """Propone perfiles adaptados al sistema; con write=True los añade al config.toml (sin sobrescribir)."""
        from . import profiles as profiles_mod
        if self.env is None:
            self.discover()
        proposals = profiles_mod.generate(self.env)
        explicit = {n for n, p in self.cfg["profiles"].items() if not p.get("_auto")}
        res = {"profiles": proposals, "toml": profiles_mod.to_toml(proposals, explicit),
               "existing": sorted(set(proposals) & explicit)}
        if write:
            w = profiles_mod.write(proposals, self.cfg)
            new_cfg = config_mod.load()
            with self.lock:
                self.cfg["profiles"] = new_cfg["profiles"]
            profiles_mod.merge_adaptive(self.cfg, self.env)
            self.store.audit(self.actor, "profiles_generate", w)
            self.emit("profiles_generated", "info", w)
            res["written"] = w
            self.invalidate("profiles", "leaks")
        return res

    def api_fixes(self) -> list[dict]:
        """Pasos concretos (con comandos) para corregir lo detectado. No ejecuta nada."""
        from . import remediation
        self.ensure_fresh()
        found = self.run_leaks()          # siempre desde el estado actual, nunca una lista vieja
        ctx = {"env": self.env, "net": self.net, "dns": self.dns, "ks_ext": self.ks_ext, "public": self.public,
               "wan": self.wan, "profile_name": self.cfg["active_profile"]}
        return remediation.plan(found, ctx)

    # ── threat intel ──
    def _intel_scanner(self, progress=None):
        from . import intel
        return intel.Scanner(self.store, self.cfg, progress=progress)

    def api_intel_keys(self) -> dict:
        from . import intel
        return {"providers": intel.configured(), "secrets_file": str(intel.secrets_path()),
                "consent": self.cfg["consent"].get("threat_intel_lookups", False)}

    def api_intel_targets(self, since: float | None = None, include_own: bool | None = None) -> dict:
        from . import intel
        self.ensure_fresh()
        tg = intel.targets(self.store, self, since)
        own = intel.own_ips(self.store, self)
        inc = self.cfg["intel"].get("include_own") if include_own is None else include_own
        excluded = set(self.cfg["intel"].get("exclude") or []) | (set() if inc else own)
        return {"targets": {ip: v for ip, v in tg.items() if ip not in excluded},
                "excluded": sorted(set(tg) & excluded), "own": sorted(own)}

    def api_intel_scan(self, ips: list | None = None, history: bool = True, current: bool = True,
                       providers: list | None = None, include_own: bool | None = None, refresh: bool = False,
                       background: bool = False) -> dict:
        from . import intel
        if not self.cfg["consent"].get("threat_intel_lookups"):
            raise PermissionError(_("activa consent.threat_intel_lookups = true: los servicios sabrán qué IPs consultas"))
        self._intel_route_ok()
        tg = self.api_intel_targets(include_own=include_own) if (history or current) and not ips else {"targets": {}, "excluded": []}
        own = set() if include_own else intel.own_ips(self.store, self)
        lst = [ip for ip in (ips or list(tg["targets"])) if intel.is_scannable(ip) and ip not in own
               and ip not in set(self.cfg["intel"].get("exclude") or [])]
        providers = providers or self.cfg["intel"]["providers"]
        self.store.audit(self.actor, "intel_scan", {"count": len(lst), "providers": providers})
        if background:
            def work():
                res = self._intel_scanner().scan(lst, providers, refresh, tg["targets"])
                try:
                    self.api_intel_tor_check(lst, background=False)
                except PermissionError:
                    pass
                bad = [r["ip"] for r in res if r["verdict"] in ("malicioso", "sospechoso", "expuesto")]
                self.emit("intel_scan_done", "warning" if bad else "info", {"scanned": len(res), "flagged": bad[:20]})
            threading.Thread(target=work, daemon=True, name="intel").start()
            return {"started": True, "count": len(lst), "excluded": tg.get("excluded", [])}
        return {"results": self._intel_scanner().scan(lst, providers, refresh, tg["targets"]),
                "excluded": tg.get("excluded", [])}

    def _intel_route_ok(self):
        self.ensure_fresh()
        if not self.cfg["intel"].get("via_tor") and not self.net["via_tunnel"].get("ipv4") \
                and not self.cfg["intel"].get("allow_direct"):
            raise PermissionError(_("sin VPN la consulta saldría desde tu IP real: conecta la VPN, activa «consultas por "
                                  "Tor» o «permitir consultas sin VPN» en Ajustes"))

    def api_intel_test(self, provider: str) -> dict:
        """Prueba una clave con una IP neutra (8.8.8.8). Respeta la regla de VPN/Tor."""
        from . import intel
        if provider not in intel.QUERY:
            raise ValueError(_("proveedor desconocido: {provider}", provider=provider))
        self._intel_route_ok()
        sc = intel.Scanner(self.store, self.cfg)
        res = sc.lookup("8.8.8.8", provider, refresh=True)
        ok = res["status"] == "ok"
        return {"ok": ok, "status": res["status"], "provider": provider,
                "detail": _("clave válida") if ok else res["status"]}

    def api_settings_get(self) -> dict:
        from . import autostart
        vals = {}
        for k in config_mod.SETTINGS_KEYS:
            try:
                vals[k] = config_mod.get_key(self.cfg, k)
            except KeyError:
                vals[k] = None
        return {"values": vals, "path": str(config_mod.settings_path()), "autostart": autostart.status()}

    def api_settings_set(self, changes: dict) -> dict:
        """Cambia ajustes permitidos, los guarda en app-settings.toml y los aplica en caliente."""
        overlay = config_mod.load_overlay()
        clean = {k: config_mod.coerce_setting(k, v) for k, v in changes.items()}
        trial = config_mod.deep_merge(self.cfg, {})
        for k, v in clean.items():
            config_mod.set_key(trial, k, v)
            config_mod.set_key(overlay, k, v)
        errors = config_mod.validate(trial)
        if errors:
            raise ValueError("; ".join(errors))
        path = config_mod.save_overlay(overlay)
        with self.lock:
            for k, v in clean.items():
                config_mod.set_key(self.cfg, k, v)    # en el mismo dict: todos los módulos lo ven al momento
        self.store.audit(self.actor, "settings_set", clean)
        self.emit("settings_change", "info", {"changed": sorted(clean)})
        domains: set[str] = set()
        if "ui.language" in clean:                    # los mensajes nuevos del daemon salen ya en ese idioma
            from . import i18n
            i18n.set_language(None if clean["ui.language"] == "auto" else clean["ui.language"])
            self.mark_dirty("leaks", "rediscover", "dns", "networks", "network")    # recalcular ya los avisos en el idioma nuevo
            domains |= {"leaks", "network", "networks", "dns"}
        for key in clean:
            if key.startswith("dns."):
                domains |= {"dns", "leaks"}
            elif key.startswith("leakwatch."):
                domains |= {"leaks", "networks"}
            elif key.startswith("consent."):
                domains |= {"leaks", "public"}
                if key in ("consent.active_dns_leak_test", "consent.direct_ip_checks",
                           "consent.allow_killswitch"):
                    domains.add("dns")
            elif key.startswith("public_ip."):
                domains.add("public")
            elif key.startswith("anomaly."):
                domains.add("anomalies")
            elif key.startswith("intel."):
                domains.add("leaks")
        if domains:
            self.invalidate(*domains)
        return {"saved": str(path), "changed": clean}

    # ── ¿es de Tor? ──
    def _tor_socks(self):
        socks = ((self.env or {}).get("tor") or {}).get("socks") or []
        return ("127.0.0.1", socks[0]) if socks else None

    def _tor_sources(self):
        from . import torcheck
        return torcheck.consensus(self.tor_obs), torcheck.exit_list(self._tor_socks())

    def _exonerator_cached(self, ips) -> dict:
        from . import intel
        rows = intel.cached_many(self.store, list(ips), "exonerator")
        return {ip: {**r["summary"], "ts": r["ts"]} for ip, r in rows.items()
                if r["status"] == "ok" and now() - r["ts"] < 7 * 86400}

    def api_intel_tor_check(self, ips: list | None = None, background: bool = True) -> dict:
        """Consulta ExoneraTor (por Tor) para las IPs dadas o las de los resultados de threat intel."""
        from . import intel, torcheck
        if not self.cfg["consent"].get("threat_intel_lookups"):
            raise PermissionError(_("activa el consentimiento de threat intel: ExoneraTor recibe la IP consultada"))
        self.ensure_fresh()
        socks = self._tor_socks()
        if not socks:
            raise PermissionError(_("ExoneraTor solo se consulta a través de Tor y no hay SocksPort disponible"))
        ips = [ip for ip in (ips or [r["ip"] for r in self._intel_scanner().results()]) if intel.is_scannable(ip)]
        todo = [ip for ip in ips if ip not in self._exonerator_cached(ips)]

        def work():
            sc = self._intel_scanner()
            pos = []
            for ip in todo:
                res = torcheck.exonerator(ip, socks)
                status = "ok" if res["status"] == "ok" else "no_disponible"
                sc._save(ip, "exonerator", {"status": status, "verdict": res.get("result"), "summary": res})
                if res.get("result") == "positivo":
                    pos.append(ip)
                time.sleep(2)                      # amable con el servicio
            self.emit("intel_tor_check_done", "info", {"checked": len(todo), "tor": pos[:30]})
            return pos
        if background:
            threading.Thread(target=work, daemon=True, name="exonerator").start()
            return {"started": True, "count": len(todo)}
        return {"tor": work(), "count": len(todo)}

    def api_intel_results(self, ip: str | None = None) -> list[dict]:
        """Resultados en caché + geolocalización local + resumen (organización, VT x/y, puertos) + ¿Tor?"""
        from . import intel, torcheck
        rows = self._intel_scanner().results(ip)
        rows = [r for r in rows if set(r["results"]) - {"exonerator"}]
        cons, exits = self._tor_sources()
        exo = self._exonerator_cached([r["ip"] for r in rows])
        for r in rows:
            r["results"].pop("exonerator", None)
            r["tor"] = torcheck.classify(r["ip"], cons, exits, exo.get(r["ip"]))
            g = self.geo.lookup(r["ip"])
            res = r["results"]
            vt = intel.vt_score(res.get("virustotal"))
            vts = (res.get("virustotal") or {}).get("summary") or {}
            sh = (res.get("shodan") or {}).get("summary") or {}
            cz = (res.get("censys") or {}).get("summary") or {}
            gn = (res.get("greynoise") or {}).get("summary") or {}
            cc = g.get("country") or vts.get("country") or sh.get("country")
            r["geo"] = {**self.geo.country_info(cc), "city": g.get("city"),
                        "source": g.get("source") or ("virustotal" if vts.get("country") else None)}
            r["org"] = vts.get("as_owner") or sh.get("org") or cz.get("as_name") or g.get("org") or gn.get("name")
            r["asn"] = vts.get("asn") or sh.get("asn") or cz.get("asn") or g.get("asn")
            r["vt"] = vt
            r["shodan_ports"] = sh.get("ports") or []
            r["shodan_vulns"] = sh.get("vulns") or []
        return rows

    def api_correlation(self) -> dict:
        return analytics.correlation(self.store, self.cfg)

    def api_stats(self, period: str = "week", profile: str | None = None) -> dict:
        return analytics.stats(self.store, period, profile)

    def api_anomalies(self) -> list[dict]:
        try:
            if (self.cfg.get("anomaly") or {}).get("enabled", True):
                anomaly.maybe_emit(self, interval=parse_duration(self.cfg["anomaly"].get("interval", "60s")))
        except Exception:  # noqa: BLE001
            pass
        return analytics.anomalies(self.store)

    def api_timeline(self, since: float | None = None, limit: int = 300) -> list[dict]:
        return analytics.timeline(self.store, since, limit)

    def api_map(self, since: float | None = None) -> dict:
        self.ensure_fresh()
        since = since or now() - 7 * 86400
        hist = []
        for layer in ("public_ip", "tor_exit", "tor_guard", "vpn_server", "proxy", "wan_ip"):
            for i in self.store.intervals(layer, since=since, limit=2000):
                if i["lat"] is not None:
                    hist.append({"layer": layer, "key": i["key"], "label": i["label"], "country": i["country"],
                                 "asn": i["asn"], "lat": i["lat"], "lon": i["lon"], "started": i["started"],
                                 "ended": i["ended"], "session": i["session_id"]})
        heat = {}
        for c in self.store.counters("country", since) + self.store.counters("tor_exit_country", since):
            info = self.geo.country_info(c["key"])
            h = heat.setdefault(c["key"], {"country": c["key"], "name": info["country_name"], "lat": info["lat"],
                                           "lon": info["lon"], "seconds": 0})
            h["seconds"] += c["total"] or 0
        obs = self.obs or {}
        return {"home": self.home_location(), "chain": obs.get("chain", []), "tor_chain": obs.get("tor_chain", []),
                "tor_circuits": [{"id": c["id"], "streams": c.get("streams"),
                                  "path": [{"role": h.get("role"), "nick": h.get("nick"), "ip": h.get("ip"),
                                            "country": h.get("country"), "lat": h.get("lat"), "lon": h.get("lon")}
                                           for h in c["path"]]} for c in (self.tor or {}).get("circuits", [])],
                "history": hist, "heat": list(heat.values()),
                "note": _("Ubicaciones estimadas por GeoIP local (precisión de país salvo base .mmdb); "
                        "no son la ubicación física real de los servidores.")}

    def api_worldmap(self) -> dict:
        return worldmap.as_json()

    def api_capabilities(self) -> list[dict]:
        if self.env is None:
            self.discover()
        return self.caps

    def api_config_get(self) -> dict:
        path = config_mod.config_path()
        text = path.read_text() if path.exists() else ""
        return {"path": str(path), "text": text, "effective": redact(self.cfg)}

    def api_config_set(self, text: str) -> dict:
        new = config_mod.load_text(text)
        path = config_mod.save_text(text)
        with self.lock:
            changed = _diff_keys(self.cfg, new)
            self.cfg.clear()
            self.cfg.update(new)
            self.store.audit(self.actor, "config_set", {"changed": changed})
            self.emit("config_change", "info", {"changed": changed})
        self.discover()
        self.invalidate("all")
        return {"saved": str(path), "changed": changed}

    def api_panic(self) -> dict:
        """Emergencia: detiene rotaciones, intenta bloquear conexiones no verificadas y notifica.
        No borra datos ni toca configuraciones."""
        with self.lock:
            self.emergency = True
            self.rot.paused = True
            self.store.put("emergency", True)
            ks = self.ks.engage(reason="emergencia") if self.ks.can_apply()[0] else \
                {"ok": False, "error": self.ks.can_apply()[1]}
            self.store.audit(self.actor, "panic", {"killswitch": ks})
            self.emit("emergency", "critical", {"rotations": "detenidas", "killswitch": ks})
        _notify(_("VELA: modo de emergencia"), _("Rotaciones detenidas. Kill-switch: ") +
                ("activo" if ks.get("ok") else _("NO aplicado ({v1})", v1=ks.get('error'))))
        self.invalidate("network", "leaks")
        return {"emergency": True, "killswitch": ks}

    def api_resume(self) -> dict:
        with self.lock:
            self.emergency = False
            self.rot.paused = False
            self.store.put("emergency", False)
            ks = self.ks.release() if self.ks.state["active"] else {"ok": True}
            self.store.audit(self.actor, "resume", {"killswitch": ks})
            self.emit("emergency_end", "warning", {"killswitch_release": ks})
        self.invalidate("network", "leaks")
        return {"emergency": False, "killswitch": ks}

    def api_killswitch(self, action: str = "status") -> dict:
        if action == "apply":
            res = self.ks.engage(reason="manual")
        elif action == "release":
            res = self.ks.release()
        elif action == "preview":
            return {"ruleset": self.ks.ruleset(), **self.ks.status()}
        else:
            return self.ks.status()
        self.store.audit(self.actor, f"killswitch {action}", res)
        self.emit(f"killswitch_{action}", "warning", res)
        if action in ("apply", "release"):
            self.invalidate("network", "leaks")
        return res

    def api_audit(self) -> dict:
        from . import report
        self.ensure_fresh()
        return report.privacy_audit(self)

    def api_audit_log(self, limit: int = 100) -> list[dict]:
        return self.store.audit_log(limit)

    def api_logs(self, kind: str = "all", limit: int = 200) -> dict:
        from . import logs
        data = logs.read(kind, limit)
        if kind in ("all", "audit"):
            # El fichero solo tiene acciones desde que se activó el log; la base de datos
            # conserva el histórico anterior. Se combinan sin duplicar.
            seen = {(round(float(x.get("ts") or 0), 1), x.get("actor"), x.get("action"))
                    for x in data.get("audit") or []}
            rows = []
            for row in self.store.audit_log(limit):
                try:
                    detail = json.loads(row.get("detail") or "null")
                except (TypeError, ValueError):
                    detail = row.get("detail")
                rec = {"ts": row.get("ts"), "actor": row.get("actor"), "action": row.get("action"),
                       "detail": detail}
                key = (round(float(rec["ts"] or 0), 1), rec["actor"], rec["action"])
                if key not in seen:
                    rows.append(rec)
            data["audit"] = sorted((data.get("audit") or []) + rows, key=lambda x: x.get("ts") or 0,
                                   reverse=True)[:max(1, int(limit))]
        return data

    def api_logs_clear(self, kind: str = "all") -> dict:
        from . import logs
        res = logs.clear(kind)
        if kind in ("audit", "all"):
            res["audit_db_deleted"] = self.store.clear_audit()
        return res

    def api_log_action(self, action: str, detail=None) -> dict:
        """Registra una acción de la UI que no pasa por el motor (DNS, MAC, dependencias…)."""
        self.store.audit(self.actor, action, detail)
        self.emit("audit_action", "info", {"action": action})
        return {"ok": True, "action": action}

    def api_doctor(self) -> list[dict]:
        from . import report
        return report.doctor(self)

    def api_purge(self, days: float) -> dict:
        res = self.store.purge(now() - days * 86400)
        self.store.audit(self.actor, "purge", {"days": days, **res})
        return res

    # ── exportar / importar / borrar datos ──
    def api_data_info(self) -> dict:
        from . import backup
        return backup.info(self)

    def api_data_export(self, path: str, include: dict | None = None) -> dict:
        from . import backup
        return backup.export_bundle(self, path, include)

    def api_data_import(self, path: str, mode: str = "merge", include: dict | None = None) -> dict:
        from . import backup
        res = backup.import_bundle(self, path, mode=mode, include=include)
        self.reload_config()
        self.invalidate("all")
        return res

    def api_data_reset(self, scope: str = "history", keep_backup: bool = False,
                       backup_path: str | None = None) -> dict:
        from . import backup
        res = backup.reset(self, scope=scope, keep_backup=keep_backup, backup_path=backup_path)
        self.reload_config()
        self.invalidate("all")
        return res

    def api_webrtc_report(self, candidates: list[str], used_stun: bool = False) -> dict:
        self.ensure_fresh()
        local_ips = [a["addr"] for i in self.net["interfaces"] for a in i["addrs"]]
        public_ips = [r["ip"] for r in self.public.values() if r.get("ok")]
        if (self.wan or {}).get("ok"):
            public_ips.append(self.wan["ip"])
        f = leaks.webrtc_finding(candidates, local_ips, public_ips, used_stun)
        self.store.add_finding(f, self.cfg["active_profile"])
        return f

    def retention(self):
        days = self.cfg["storage"].get("retention_days") or 0
        if days:
            self.store.purge(now() - float(days) * 86400)

    def close(self):
        self.tracker.close("daemon detenido")
        self.tor_obs.stop()
        if self.forwarder:
            self.forwarder.stop()


def _geo(g: dict | None) -> dict:
    g = g or {}
    return {"lat": g.get("lat"), "lon": g.get("lon"), "country": g.get("country"), "asn": g.get("asn")}


def _tor_summary(tor: dict | None) -> dict | None:
    if not tor:
        return None
    if not tor.get("available"):
        return {"available": False, "error": tor.get("error")}
    return {k: tor.get(k) for k in ("available", "target", "observe_only", "version", "bootstrap",
                                    "circuit_established", "network_live", "circuit_count", "stream_count",
                                    "exit", "guard")} | {"active_circuit": (tor.get("active") or {}).get("id")}


def _diff_keys(a, b, prefix="") -> list[str]:
    out = []
    for k in set(a) | set(b):
        va, vb = a.get(k), b.get(k)
        if isinstance(va, dict) and isinstance(vb, dict):
            out += _diff_keys(va, vb, f"{prefix}{k}.")
        elif va != vb:
            out.append(f"{prefix}{k}")
    return sorted(out)


def _notify(title: str, body: str):
    from .util import run
    run(["notify-send", "-u", "critical", title, body], timeout=3)
