"""Sesiones operativas de salida.

Regla para abrir una sesión NUEVA (cambia la identidad de red con la que sales):
  * cambio de perfil OPSEC activo;
  * cambio de interfaz de salida (p. ej. Ethernet → WiFi, o entra/sale el túnel);
  * cambio de VPN o de servidor VPN (incluye conectar/desconectar);
  * cambio de proxy activo de la cadena;
  * cambio de IP WAN del router o de IP pública observada (de un valor conocido a otro distinto).

Cambios que solo modifican la sesión ACTUAL (se registran como evento y como intervalo):
  * circuitos y exits de Tor (Tor los renueva por diseño cada ~10 min; tienen sus propios contadores);
  * resolvers DNS, estado de interfaces, rutas sin cambio de interfaz, alertas;
  * conocer por primera vez un dato antes desconocido (None → valor) o perderlo (valor → None).
"""

from __future__ import annotations

from .util import fingerprint, now

STRUCTURAL = ("profile", "egress_iface", "vpn", "proxy")
OBSERVED = ("wan_ip", "public_ip")


def identity(obs: dict) -> dict:
    pub = obs.get("public_ip") or {}
    return {
        "profile": obs.get("profile"),
        "egress_iface": obs.get("egress_iface"),
        "vpn": (obs.get("vpn") or {}).get("id"),
        "proxy": (obs.get("proxy") or {}).get("id"),
        "wan_ip": obs.get("wan_ip"),
        "public_ip": pub.get("ip"),
    }


def connection_fingerprint(obs: dict) -> str:
    """Huella descriptiva de la configuración de salida (para detectar reutilizaciones)."""
    ident = identity(obs)
    tor = obs.get("tor") or {}
    return fingerprint({**{k: v for k, v in ident.items() if k != "profile"},
                        "tor_exit": (tor.get("exit") or {}).get("fp")})


def needs_new_session(prev: dict | None, cur: dict) -> tuple[bool, str | None]:
    if prev is None:
        return True, "inicio"
    for k in STRUCTURAL:
        if prev.get(k) != cur.get(k):
            return True, f"cambio de {k}"
    for k in OBSERVED:
        if prev.get(k) and cur.get(k) and prev[k] != cur[k]:
            return True, f"cambio de {k}"
    return False, None


def layer_keys(obs: dict) -> dict[str, tuple[str, str, dict, dict] | None]:
    """Elemento actual por capa: layer -> (key, label, geo, meta) o None."""
    out: dict = {}
    pub = obs.get("public_ip") or {}
    geo = pub.get("geo") or {}
    vpn = obs.get("vpn")
    proxy = obs.get("proxy")
    tor = obs.get("tor") or {}
    out["profile"] = (obs["profile"], obs["profile"], {}, {}) if obs.get("profile") else None
    out["egress_iface"] = (obs["egress_iface"], obs["egress_iface"], {}, {}) if obs.get("egress_iface") else None
    out["local_ip"] = (obs["local_ip"], obs["local_ip"], {}, {}) if obs.get("local_ip") else None
    out["wan_ip"] = (obs["wan_ip"], obs["wan_ip"], obs.get("wan_geo") or {}, {}) if obs.get("wan_ip") else None
    out["public_ip"] = (pub["ip"], pub["ip"], geo, {"route": pub.get("route")}) if pub.get("ip") else None
    out["country"] = (geo["country"], geo.get("country_name") or geo["country"], geo, {}) if geo.get("country") else None
    out["asn"] = (str(geo["asn"]), f"AS{geo['asn']} {geo.get('org') or ''}".strip(), geo, {}) if geo.get("asn") else None
    out["vpn"] = (vpn["id"], vpn.get("label") or vpn["id"], vpn.get("geo") or {}, {}) if vpn else None
    out["vpn_server"] = ((vpn["server"], vpn["server"], vpn.get("geo") or {}, {"vpn": vpn["id"]})
                         if vpn and vpn.get("server") else None)
    out["proxy"] = (proxy["id"], proxy.get("label") or proxy["id"], proxy.get("geo") or {}, {}) if proxy else None
    exit_ = tor.get("exit")
    out["tor_exit"] = ((exit_["fp"], f"{exit_.get('nick') or '?'} {exit_.get('ip') or ''}".strip(), exit_,
                        {"ip": exit_.get("ip")}) if exit_ else None)
    out["tor_exit_country"] = ((exit_["country"], exit_.get("country_name") or exit_["country"], exit_, {})
                               if exit_ and exit_.get("country") else None)
    guard = tor.get("guard")
    out["tor_guard"] = ((guard["fp"], f"{guard.get('nick') or '?'} {guard.get('ip') or ''}".strip(), guard, {})
                        if guard else None)
    circ = tor.get("circuit")
    out["tor_circuit"] = ((f"{circ}@{tor.get('circuit_created') or ''}", f"circuito {circ}", exit_ or {}, {})
                          if circ else None)
    out["dns_resolver"] = None
    if obs.get("dns"):
        servers = ",".join(sorted(obs["dns"]))
        out["dns_resolver"] = (servers, servers, {}, {})
    out["combination"] = (obs["fingerprint"], obs.get("chain_label") or obs["fingerprint"], geo, {})
    return out


class SessionTracker:
    def __init__(self, store):
        self.store = store
        self.session_id: str | None = None
        self.ident: dict | None = None
        self.started: float | None = None
        self.open: dict[str, tuple[str, int]] = {}   # layer -> (key, interval_id)

    def recover(self, last_seen: float | None):
        """Cierra sesiones/intervalos que quedaron abiertos si el daemon se detuvo sin cerrarlos."""
        for s in self.store.open_sessions():
            self.store.close_session(s["id"], "daemon detenido", ts=last_seen or s["started"])
        for i in self.store.open_intervals():
            self.store.close_interval(i["id"], ts=last_seen or i["started"])

    def update(self, obs: dict, ts: float | None = None) -> list[dict]:
        ts = ts or now()
        events = []
        obs = {**obs, "fingerprint": obs.get("fingerprint") or connection_fingerprint(obs)}
        cur = identity(obs)
        new, reason = needs_new_session(self.ident, cur)
        if new:
            if self.session_id:
                self.store.close_session(self.session_id, reason, ts)
                events.append({"kind": "session_closed", "severity": "info",
                               "data": {"session": self.session_id, "reason": reason}})
            self.open = {}
            self.session_id = self.store.open_session(obs.get("profile"), obs["fingerprint"], self._fields(obs), ts)
            self.started = ts
            events.append({"kind": "session_opened", "severity": "info",
                           "data": {"session": self.session_id, "reason": reason,
                                    "identity": {k: v for k, v in cur.items() if v}}})
        else:
            changed = {k: (self.ident.get(k), cur.get(k)) for k in OBSERVED if self.ident.get(k) != cur.get(k)}
            if changed:
                events.append({"kind": "session_enriched", "severity": "info",
                               "data": {k: {"before": a, "after": b} for k, (a, b) in changed.items()}})
            self.store.update_session(self.session_id, **{k: v for k, v in self._fields(obs).items()
                                                          if k in ("chain", "wan_ip", "public_ip", "tor_exit",
                                                                   "country", "asn", "dns", "local_ip")})
        self.ident = cur

        for layer, item in layer_keys(obs).items():
            prev = self.open.get(layer)
            key = item[0] if item else None
            if prev and prev[0] == key:
                continue
            if prev:
                self.store.close_interval(prev[1], ts)
                del self.open[layer]
                if layer in ("tor_exit", "tor_circuit", "dns_resolver", "tor_guard"):
                    events.append({"kind": f"{layer}_change", "severity":
                                   "warning" if layer == "tor_guard" else "info",
                                   "data": {"before": prev[0], "after": key}})
            if item:
                key, label, geo, meta = item
                iid = self.store.open_interval(self.session_id, obs.get("profile"), layer, key, label, geo, meta, ts)
                self.open[layer] = (key, iid)
        for e in events:
            e.setdefault("session_id", self.session_id)
        return events

    def close(self, reason: str, ts: float | None = None):
        if self.session_id:
            self.store.close_session(self.session_id, reason, ts or now())
            self.session_id, self.ident, self.open = None, None, {}

    @staticmethod
    def _fields(obs: dict) -> dict:
        pub = obs.get("public_ip") or {}
        geo = pub.get("geo") or {}
        tor = obs.get("tor") or {}
        return {
            "chain": obs.get("chain", []), "egress_iface": obs.get("egress_iface"), "local_ip": obs.get("local_ip"),
            "wan_ip": obs.get("wan_ip"), "public_ip": pub.get("ip"),
            "vpn": (obs.get("vpn") or {}).get("id"), "proxy": (obs.get("proxy") or {}).get("id"),
            "tor_exit": (tor.get("exit") or {}).get("fp"), "country": geo.get("country"),
            "asn": str(geo["asn"]) if geo.get("asn") else None, "dns": obs.get("dns", []),
        }
