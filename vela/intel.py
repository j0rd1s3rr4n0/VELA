"""Threat intelligence de las IPs por las que pasan tus datos: GreyNoise, VirusTotal, Shodan y Censys.

OPSEC de la propia consulta:
  * Preguntar por una IP le dice al servicio que te interesa esa IP (y desde qué IP preguntas).
    Por eso se EXCLUYEN por defecto tus IPs propias (WAN, IP pública directa, privadas) y los
    resultados se cachean para no repetir consultas.
  * Requiere consent.threat_intel_lookups = true. Opcionalmente las consultas salen por Tor
    (intel.via_tor), aunque algunos servicios bloquean o limitan Tor.
  * Las API keys se leen de variables de entorno o de ~/.config/vela/secrets.toml (0600);
    nunca se guardan en la base de datos, en logs ni en la salida.

Interpretación: los exits de Tor y muchos servidores VPN aparecen como "maliciosos" o "scanner" por el
abuso que reciben de otros usuarios. Eso no dice nada de TU tráfico, pero sí que esa salida está en
listas de bloqueo (más captchas/bloqueos) y que llama la atención: es información OPSEC útil.
"""

from __future__ import annotations

from .i18n import _

import base64
import ipaddress
import json
import os
import re
import socket
import threading
import time
import tomllib
import urllib.parse
from pathlib import Path

from .publicip import https_request, open_socks5
from .util import now, parse_duration, private_dir, xdg_dir

PROVIDERS = ("greynoise", "virustotal", "shodan", "censys")
# pausa mínima entre consultas por proveedor (planes gratuitos): VT 4/min, Shodan 1/s
MIN_GAP = {"greynoise": 1.0, "virustotal": 15.5, "shodan": 1.1, "censys": 2.5}
ENV_KEYS = {
    "greynoise": ["GREYNOISE_API_KEY"],
    "virustotal": ["VT_API_KEY", "VIRUSTOTAL_API_KEY"],
    "shodan": ["SHODAN_API_KEY"],
    "censys_token": ["CENSYS_API_TOKEN", "CENSYS_PAT"],
    "censys_org": ["CENSYS_ORG_ID"],
    "censys_id": ["CENSYS_API_ID"],
    "censys_secret": ["CENSYS_API_SECRET"],
}
SCHEMA = """
CREATE TABLE IF NOT EXISTS intel (
  ip TEXT NOT NULL, provider TEXT NOT NULL, ts REAL NOT NULL, status TEXT, verdict TEXT, summary TEXT,
  PRIMARY KEY (ip, provider)
);
"""


# ── claves ──────────────────────────────────────────────────────────────────

def secrets_path() -> Path:
    return xdg_dir("config") / "secrets.toml"


def load_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    p = secrets_path()
    if p.exists():
        try:
            with open(p, "rb") as f:
                keys.update({k: str(v) for k, v in (tomllib.load(f).get("intel") or {}).items() if v})
        except (OSError, tomllib.TOMLDecodeError):
            pass
    for name, envs in ENV_KEYS.items():
        for e in envs:
            if os.environ.get(e):
                keys[name] = os.environ[e]
    return keys


def save_key(name: str, value: str) -> Path:
    """Guarda una clave en secrets.toml (0600). Las demás claves se conservan."""
    if name not in ENV_KEYS:
        raise ValueError(_("clave desconocida: {name} (válidas: {v3})", name=name, v3=', '.join(ENV_KEYS)))
    p = secrets_path()
    private_dir(p.parent)
    current = {}
    if p.exists():
        with open(p, "rb") as f:
            current = tomllib.load(f).get("intel") or {}
    current[name] = value
    text = "# Claves de API de VELA. No compartas este fichero.\n[intel]\n" + "".join(
        f'{k} = "{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"\n'
        for k, v in sorted(current.items()))
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, p)
    return p


def delete_key(name: str) -> bool:
    p = secrets_path()
    if not p.exists():
        return False
    with open(p, "rb") as f:
        current = tomllib.load(f).get("intel") or {}
    if name not in current:
        return False
    del current[name]
    text = "# Claves de API de VELA. No compartas este fichero.\n[intel]\n" + "".join(
        f'{k} = "{str(v).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"\n'
        for k, v in sorted(current.items()))
    fd = os.open(p.with_suffix(".tmp"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(p.with_suffix(".tmp"), p)
    return True


def configured(keys: dict | None = None) -> dict[str, str]:
    keys = load_keys() if keys is None else keys
    return {
        "greynoise": _("API key") if keys.get("greynoise") else _("Community API sin clave (cuota limitada)"),
        "virustotal": _("API key") if keys.get("virustotal") else _("falta API key"),
        "shodan": _("API key") if keys.get("shodan") else _("falta API key"),
        "censys": (_("token Platform") if keys.get("censys_token") else
                   _("API ID/secret (Search v2)") if keys.get("censys_id") and keys.get("censys_secret") else _("falta API key")),
    }


# ── transporte ──────────────────────────────────────────────────────────────

class Transport:
    def __init__(self, via_tor: tuple[str, int] | None = None, timeout: float = 20):
        self.via_tor = via_tor
        self.timeout = timeout

    def get(self, url: str, headers: dict | None = None) -> tuple[int, str]:
        u = urllib.parse.urlsplit(url)
        port = u.port or 443
        if self.via_tor:
            sock = open_socks5(self.via_tor, u.hostname, port, self.timeout)
        else:
            sock = socket.create_connection((u.hostname, port), timeout=self.timeout)
        path = u.path + (f"?{u.query}" if u.query else "")
        return https_request(sock, u.hostname, path, self.timeout, headers)


# ── proveedores (cada uno devuelve {status, verdict, summary}) ──────────────

def _json(body: str) -> dict:
    try:
        d = json.loads(body)
        return d if isinstance(d, dict) else {"data": d}
    except ValueError:
        return {}


def q_greynoise(ip: str, keys: dict, t: Transport) -> dict:
    headers = {"key": keys["greynoise"]} if keys.get("greynoise") else {}
    code, body = t.get(f"https://api.greynoise.io/v3/community/{ip}", headers)
    d = _json(body)
    if code == 404:
        return {"status": "ok", "verdict": "sin_datos", "summary": {"seen": False, "message": d.get("message")}}
    if code == 429:
        return {"status": "rate_limited", "verdict": None, "summary": {"message": d.get("message") or _("cuota agotada")}}
    if code != 200:
        return {"status": f"error HTTP {code}", "verdict": None, "summary": {"message": d.get("message")}}
    cls = d.get("classification")
    verdict = {"malicious": "malicioso", "benign": "benigno"}.get(cls, "sospechoso" if d.get("noise") else "sin_datos")
    return {"status": "ok", "verdict": verdict, "summary": {
        "noise": d.get("noise"), "riot": d.get("riot"), "classification": cls, "name": d.get("name"),
        "last_seen": d.get("last_seen"), "link": d.get("link")}}


def q_virustotal(ip: str, keys: dict, t: Transport) -> dict:
    if not keys.get("virustotal"):
        return {"status": "sin_clave", "verdict": None, "summary": {}}
    code, body = t.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", {"x-apikey": keys["virustotal"]})
    if code == 429:
        return {"status": "rate_limited", "verdict": None, "summary": {}}
    if code != 200:
        return {"status": f"error HTTP {code}", "verdict": None, "summary": {"message": _json(body).get("error")}}
    a = (_json(body).get("data") or {}).get("attributes") or {}
    st = a.get("last_analysis_stats") or {}
    mal, sus = st.get("malicious", 0), st.get("suspicious", 0)
    verdict = "malicioso" if mal >= 3 else "sospechoso" if (mal or sus) else "limpio"
    return {"status": "ok", "verdict": verdict, "summary": {
        "malicious": mal, "suspicious": sus, "harmless": st.get("harmless"), "undetected": st.get("undetected"),
        "reputation": a.get("reputation"), "as_owner": a.get("as_owner"), "asn": a.get("asn"),
        "country": a.get("country"), "tags": a.get("tags") or [],
        "link": f"https://www.virustotal.com/gui/ip-address/{ip}"}}


def q_shodan(ip: str, keys: dict, t: Transport) -> dict:
    if not keys.get("shodan"):
        return {"status": "sin_clave", "verdict": None, "summary": {}}
    code, body = t.get(f"https://api.shodan.io/shodan/host/{ip}?key={urllib.parse.quote(keys['shodan'])}&minify=true")
    d = _json(body)
    if code == 404:
        return {"status": "ok", "verdict": "sin_datos", "summary": {"message": d.get("error")}}
    if code == 429:
        return {"status": "rate_limited", "verdict": None, "summary": {}}
    if code != 200:
        return {"status": f"error HTTP {code}", "verdict": None, "summary": {"message": d.get("error")}}
    vulns = d.get("vulns") or []
    tags = d.get("tags") or []
    verdict = "expuesto" if vulns else ("sospechoso" if {"malware", "c2", "compromised"} & set(tags) else "info")
    return {"status": "ok", "verdict": verdict, "summary": {
        "ports": sorted(d.get("ports") or []), "org": d.get("org"), "isp": d.get("isp"), "asn": d.get("asn"),
        "os": d.get("os"), "hostnames": (d.get("hostnames") or [])[:5], "tags": tags, "vulns": sorted(vulns)[:20],
        "country": d.get("country_code"), "last_update": d.get("last_update"),
        "link": f"https://www.shodan.io/host/{ip}"}}


def q_censys(ip: str, keys: dict, t: Transport) -> dict:
    if keys.get("censys_token"):
        headers = {"Authorization": f"Bearer {keys['censys_token']}", "Accept": "application/vnd.censys.api.v3.host.v1+json"}
        if keys.get("censys_org"):
            headers["X-Organization-ID"] = keys["censys_org"]
        code, body = t.get(f"https://api.platform.censys.io/v3/global/asset/host/{ip}", headers)
    elif keys.get("censys_id") and keys.get("censys_secret"):
        auth = base64.b64encode(f"{keys['censys_id']}:{keys['censys_secret']}".encode()).decode()
        code, body = t.get(f"https://search.censys.io/api/v2/hosts/{ip}", {"Authorization": f"Basic {auth}"})
    else:
        return {"status": "sin_clave", "verdict": None, "summary": {}}
    d = _json(body)
    if code == 404:
        return {"status": "ok", "verdict": "sin_datos", "summary": {}}
    if code == 429:
        return {"status": "rate_limited", "verdict": None, "summary": {}}
    if code != 200:
        return {"status": f"error HTTP {code}", "verdict": None, "summary": {"message": str(d.get("error") or d)[:200]}}
    res = d.get("result") or {}
    res = res.get("resource") or res          # v3 envuelve el host en result.resource
    services = res.get("services") or []
    asys = res.get("autonomous_system") or {}
    labels = [l.get("value") if isinstance(l, dict) else l for l in (res.get("labels") or [])]
    return {"status": "ok", "verdict": "info", "summary": {
        "services": sorted({f"{s.get('port')}/{s.get('service_name') or s.get('protocol') or '?'}" for s in services})[:30],
        "asn": asys.get("asn"), "as_name": asys.get("name"), "labels": labels[:15],
        "country": (res.get("location") or {}).get("country"),
        "link": f"https://search.censys.io/hosts/{ip}"}}


QUERY = {"greynoise": q_greynoise, "virustotal": q_virustotal, "shodan": q_shodan, "censys": q_censys}
RANK = {"malicioso": 5, "expuesto": 4, "sospechoso": 3, "info": 1, "limpio": 0, "benigno": 0, "sin_datos": 0, None: -1}


def aggregate(results: dict[str, dict]) -> str:
    v = max((r.get("verdict") for r in results.values()), key=lambda x: RANK.get(x, -1), default=None)
    return v or "sin_datos"


# ── objetivos: por dónde han pasado tus datos ───────────────────────────────

_IP_IN = re.compile(r"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,39})")


def _ip(text: str | None) -> str | None:
    for m in _IP_IN.finditer(text or ""):
        try:
            return str(ipaddress.ip_address(m.group(1)))
        except ValueError:
            continue
    return None


def is_scannable(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def own_ips(store, engine=None) -> set[str]:
    """IPs que te identifican: WAN del router, IP pública por ruta directa (sin VPN ni proxy)."""
    own = {i["key"] for i in store.intervals("wan_ip", limit=100000)}
    own |= {i["key"] for i in store.intervals("real_ip", limit=100000)}
    if engine is not None:
        own |= set(engine.cfg.get("public_ip", {}).get("known_real_ips") or [])
    direct_sessions = {s["id"] for s in store.sessions(limit=100000) if not s["vpn"] and not s["proxy"]}
    own |= {i["key"] for i in store.intervals("public_ip", limit=100000) if i["session_id"] in direct_sessions}
    if engine is not None:
        if (engine.wan or {}).get("ok"):
            own.add(engine.wan["ip"])
    return own


def targets(store, engine=None, since: float | None = None, history: bool = True, current: bool = True) -> dict:
    """{ip: {"roles": [...], "first": ts, "last": ts}} de todos los saltos observados."""
    out: dict[str, dict] = {}

    def add(ip, role, ts=None, end=None):
        if not ip or not is_scannable(ip):
            return
        e = out.setdefault(ip, {"roles": set(), "first": ts, "last": end or ts})
        e["roles"].add(role)
        if ts and (e["first"] is None or ts < e["first"]):
            e["first"] = ts
        if (end or ts) and (e["last"] is None or (end or ts) > e["last"]):
            e["last"] = end or ts

    if history:
        role = {"public_ip": _("IP pública de salida"), "tor_exit": _("Tor exit"), "tor_guard": _("Tor guard"),
                "proxy": "proxy", "vpn_server": _("servidor VPN"), "dns_resolver": _("resolver DNS"), "wan_ip": _("WAN router")}
        for layer, name in role.items():
            for i in store.intervals(layer, since=since, limit=100000):
                meta = json.loads(i["meta"] or "{}") if isinstance(i.get("meta"), str) else (i.get("meta") or {})
                ips = [meta.get("ip"), _ip(i["label"]), _ip(i["key"])]
                if layer == "dns_resolver":
                    ips = [x.split("#")[0] for x in i["key"].split(",")]
                for ip in dict.fromkeys(x for x in ips if x):
                    add(ip, name, i["started"], i["ended"] or now())
    if current and engine is not None:
        for c in (engine.tor or {}).get("circuits") or []:
            for h in c["path"]:
                add(h.get("ip"), f"Tor {h.get('role')}", now())
        for r, res in (engine.public or {}).items():
            if res.get("ok"):
                add(res["ip"], "IP pública vista por Tor" if r == "tor" else "IP pública de salida", res["ts"])
        enc = (engine.dns or {}).get("encryption") or {}
        for ip in (enc.get("warp") or {}).get("upstream_ips") or []:
            add(ip, "servidor DoH (WARP)", now())
        for srv in (engine.dns or {}).get("effective_servers") or []:
            add(srv.split("#")[0], "resolver DNS", now())
    for e in out.values():
        e["roles"] = sorted(e["roles"])
    return out


# ── escáner con caché ───────────────────────────────────────────────────────

class Scanner:
    def __init__(self, store, cfg: dict, keys: dict | None = None, transport: Transport | None = None, progress=None):
        self.store = store
        self.cfg = cfg
        self.keys = load_keys() if keys is None else keys
        ic = cfg.get("intel") or {}
        via = None
        if ic.get("via_tor"):
            via = ("127.0.0.1", int(ic.get("tor_socks_port", 9050)))
        self.t = transport or Transport(via_tor=via)
        self.ttl = parse_duration(ic.get("cache_ttl", "24h"))
        self.progress = progress or (lambda *_ign: None)
        self._last: dict[str, float] = {}
        self._blocked: set[str] = set()
        with store.lock:
            store.db.executescript(SCHEMA)
        self.lock = threading.Lock()

    def cached(self, ip: str, provider: str) -> dict | None:
        rows = self.store._rows("SELECT * FROM intel WHERE ip=? AND provider=?", (ip, provider))
        if rows and now() - rows[0]["ts"] < self.ttl and rows[0]["status"] == "ok":
            r = rows[0]
            return {"status": r["status"], "verdict": r["verdict"], "summary": json.loads(r["summary"] or "{}"),
                    "ts": r["ts"], "cached": True}
        return None

    def _save(self, ip, provider, res):
        self.store._x("INSERT INTO intel(ip,provider,ts,status,verdict,summary) VALUES(?,?,?,?,?,?) "
                      "ON CONFLICT(ip,provider) DO UPDATE SET ts=excluded.ts, status=excluded.status, "
                      "verdict=excluded.verdict, summary=excluded.summary",
                      (ip, provider, now(), res["status"], res["verdict"], json.dumps(res["summary"], default=str)))

    def lookup(self, ip: str, provider: str, refresh: bool = False) -> dict:
        if not refresh and (c := self.cached(ip, provider)):
            return c
        if provider in self._blocked:
            return {"status": "rate_limited", "verdict": None, "summary": {}, "skipped": True}
        gap = MIN_GAP[provider] - (time.monotonic() - self._last.get(provider, 0))
        if gap > 0:
            time.sleep(gap)
        self._last[provider] = time.monotonic()
        try:
            res = QUERY[provider](ip, self.keys, self.t)
        except Exception as e:  # noqa: BLE001
            res = {"status": f"error {type(e).__name__}: {e}", "verdict": None, "summary": {}}
        if res["status"] == "rate_limited":
            self._blocked.add(provider)      # no insistir en esta pasada
        if res["status"] in ("ok", "rate_limited") or res["status"].startswith("error HTTP"):
            self._save(ip, provider, res)
        res["ts"] = now()
        return res

    def scan(self, ips: list[str], providers=PROVIDERS, refresh: bool = False, roles: dict | None = None) -> list[dict]:
        out = []
        providers = [p for p in providers if p in QUERY]
        for n, ip in enumerate(ips, 1):
            results = {}
            for p in providers:
                if p != "greynoise" and configured(self.keys)[p].startswith("falta"):
                    results[p] = {"status": "sin_clave", "verdict": None, "summary": {}}
                    continue
                results[p] = self.lookup(ip, p, refresh)
            row = {"ip": ip, "roles": (roles or {}).get(ip, {}).get("roles", []), "verdict": aggregate(results),
                   "results": results}
            out.append(row)
            self.progress(n, len(ips), row)
        return out

    def results(self, ip: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM intel", ()
        if ip:
            q, args = q + " WHERE ip=?", (ip,)
        rows = self.store._rows(q + " ORDER BY ip, provider", args)
        by_ip: dict[str, dict] = {}
        for r in rows:
            e = by_ip.setdefault(r["ip"], {"ip": r["ip"], "results": {}})
            e["results"][r["provider"]] = {"status": r["status"], "verdict": r["verdict"], "ts": r["ts"],
                                           "summary": json.loads(r["summary"] or "{}")}
        for e in by_ip.values():
            e["verdict"] = aggregate(e["results"])
        return list(by_ip.values())


def vt_score(result: dict | None) -> dict | None:
    """Resumen corto de VirusTotal para la UI: malicious/total y veredicto."""
    if not result or result.get("status") != "ok":
        return None
    s = result.get("summary") or {}
    total = sum(int(s.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    return {"malicious": int(s.get("malicious") or 0), "suspicious": int(s.get("suspicious") or 0), "total": total,
            "verdict": result.get("verdict"), "reputation": s.get("reputation"), "as_owner": s.get("as_owner"),
            "ts": result.get("ts"), "link": s.get("link")}


def cached_many(store, ips: list[str], provider: str = "virustotal") -> dict[str, dict]:
    if not ips:
        return {}
    with store.lock:
        store.db.executescript(SCHEMA)
    out = {}
    for i in range(0, len(ips), 500):
        chunk = ips[i:i + 500]
        rows = store._rows(f"SELECT * FROM intel WHERE provider=? AND ip IN ({','.join('?' * len(chunk))})",
                           (provider, *chunk))
        for r in rows:
            out[r["ip"]] = {"status": r["status"], "verdict": r["verdict"], "ts": r["ts"],
                            "summary": json.loads(r["summary"] or "{}")}
    return out


class LiveIntel(threading.Thread):
    """Consulta en segundo plano, en VirusTotal, las IPs nuevas de las conexiones activas.

    Respeta: consentimiento + interruptor intel.auto_live, regla VPN/Tor, caché 24 h, tope diario,
    límite de 4/min de la API gratuita y exclusión de tus IPs propias. Emite `intel_live_score`."""

    def __init__(self, engine, interval: float = 5.0):
        super().__init__(daemon=True, name="intel-live")
        self.engine = engine
        self.interval = interval
        self.queue: list[str] = []
        self.done: set[str] = set()
        self.state = {"status": "inactivo", "queued": 0, "today": 0}
        self._stop = threading.Event()

    def _reason_blocked(self) -> str | None:
        cfg = self.engine.cfg
        if not cfg["intel"].get("auto_live"):
            return _("desactivado (Ajustes → consultar automáticamente en VirusTotal)")
        if not cfg["consent"].get("threat_intel_lookups"):
            return _("falta el consentimiento de threat intel")
        if not load_keys().get("virustotal"):
            return _("falta la API key de VirusTotal")
        net = self.engine.net or {}
        if not cfg["intel"].get("via_tor") and not (net.get("via_tunnel") or {}).get("ipv4") \
                and not cfg["intel"].get("allow_direct"):
            return _("en espera: sin VPN las consultas saldrían desde tu IP real")
        return None

    def _today_key(self) -> str:
        return "intel_live_count:" + time.strftime("%Y-%m-%d")

    def step(self):
        eng = self.engine
        blocked = self._reason_blocked()
        lw = getattr(eng, "leakwatcher", None)
        flows = (lw.state or {}).get("flows", []) if lw and lw.state else []
        ips = list(dict.fromkeys(f["remote"] for f in flows if is_scannable(f["remote"])))
        own = own_ips(eng.store, eng) | set(eng.cfg["intel"].get("exclude") or [])
        cached = cached_many(eng.store, ips)
        fresh = {ip for ip, r in cached.items() if r["status"] == "ok" and now() - r["ts"] < parse_duration(
            eng.cfg["intel"].get("cache_ttl", "24h"))}
        if blocked:
            self.queue.clear()               # sin permiso no se acumula nada pendiente de consultar
        else:
            for ip in ips:
                if ip not in own and ip not in fresh and ip not in self.done and ip not in self.queue:
                    self.queue.append(ip)
        today = int(eng.store.get(self._today_key(), 0) or 0)
        limit = int(eng.cfg["intel"].get("live_daily_limit", 400))
        self.state = {"status": blocked or ("tope diario alcanzado" if today >= limit else "activo"),
                      "queued": len(self.queue), "today": today, "limit": limit}
        if blocked or today >= limit or not self.queue:
            return
        ip = self.queue.pop(0)
        res = Scanner(eng.store, eng.cfg).lookup(ip, "virustotal")
        self.done.add(ip)
        if res.get("status") == "rate_limited":
            self.queue.insert(0, ip)
            self.done.discard(ip)
            self._stop.wait(60)
            return
        eng.store.put(self._today_key(), today + 1)
        score = vt_score(res)
        if not score:
            return
        flow = next((f for f in flows if f["remote"] == ip), {})
        geo = eng.geo.lookup(ip)
        flagged = score["malicious"] > 0 or score["suspicious"] > 0
        sev = "high" if score["malicious"] >= 3 else "warning" if flagged else "info"
        notify_all = eng.cfg["intel"].get("live_notify") == "all"
        eng.emit("intel_live_score", sev, {
            "ip": ip, "score": f"{score['malicious']}/{score['total']}", "malicious": score["malicious"],
            "suspicious": score["suspicious"], "process": flow.get("process"), "port": flow.get("rport"),
            "country": geo.get("country"), "country_name": geo.get("country_name"), "as_owner": score.get("as_owner"),
            "notify": flagged or notify_all})

    def run(self):
        while not self._stop.is_set():
            try:
                self.step()
            except Exception as e:  # noqa: BLE001
                self.state = {"status": f"error: {e}"}
                self._stop.wait(30)
            self._stop.wait(self.interval)

    def stop(self):
        self._stop.set()


def parse_ip_list(text: str) -> list[str]:
    """Extrae IPs de un listado libre (una por línea, CSV, logs…), sin duplicados y en orden."""
    found = []
    for m in re.finditer(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])", text):
        try:
            found.append(str(ipaddress.ip_address(m.group(1))))
        except ValueError:
            continue
    return list(dict.fromkeys(found))
