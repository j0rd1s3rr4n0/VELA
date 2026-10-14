"""Analítica: estadísticas, Network Exposure Score, correlación entre perfiles y anomalías.

El Exposure Score es un resumen EXPLICABLE de indicadores observados; no mide ni garantiza
anonimato. La separación de perfiles de red no evita la correlación por cookies, cuentas,
huella del navegador u otros identificadores de aplicación.
"""

from __future__ import annotations

from .i18n import N_, _

import math
import statistics
import time
from collections import defaultdict

from .util import now

PERIODS = {"day": 86400, "week": 7 * 86400, "month": 30 * 86400}
TECH_LAYERS = {"vpn": N_("VPN"), "proxy": N_("Proxy"), "tor_exit": N_("Tor"), "public_ip": N_("IP pública")}


def _overlap(i: dict, start: float, end: float) -> float:
    a = max(i["started"], start)
    b = min(i["ended"] or now(), end)
    return max(0.0, b - a)


def stats(store, period: str = "week", profile: str | None = None) -> dict:
    span = PERIODS.get(period, PERIODS["week"])
    t1 = now()
    t0 = t1 - span
    ivs = store.intervals(since=t0, profile=profile, limit=100000)
    by_layer: dict[str, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    labels: dict[tuple, str] = {}
    for i in ivs:
        d = _overlap(i, t0, t1)
        by_layer[i["layer"]][i["key"]] += d
        labels[(i["layer"], i["key"])] = i["label"]
    bucket = 3600 if period == "day" else 86400
    timeline: dict[int, dict[str, float]] = defaultdict(lambda: defaultdict(float))
    for i in ivs:
        if i["layer"] not in ("country", "tor_exit_country"):
            continue
        s = max(i["started"], t0)
        e = min(i["ended"] or t1, t1)
        while s < e:
            b = int(s // bucket * bucket)
            nxt = min(e, b + bucket)
            timeline[b][i["key"]] += nxt - s
            s = nxt
    rots = store.rotations(limit=10000, since=t0)
    real = [r for r in rots if not r["dry_run"]]
    reuse = {layer: [{"key": k, "label": labels[(layer, k)], "uses": n}
                     for k, n in _uses(ivs, layer).items() if n > 1]
             for layer in ("public_ip", "tor_exit", "vpn_server", "wan_ip")}
    sessions = store.sessions(limit=10000, since=t0, profile=profile)
    direct = [s for s in sessions if not s["vpn"] and not s["proxy"]]
    return {
        "period": period, "since": t0, "until": t1,
        "time_by_country": _top(by_layer.get("country", {}), labels, "country"),
        "time_by_tor_country": _top(by_layer.get("tor_exit_country", {}), labels, "tor_exit_country"),
        "time_by_technology": {_(name): sum(by_layer.get(layer, {}).values()) for layer, name in TECH_LAYERS.items()},
        "time_by_layer": {layer: _top(v, labels, layer, 10) for layer, v in by_layer.items()},
        "country_timeline": [{"t": b, **v} for b, v in sorted(timeline.items())],
        "rotations": {"total": len(real), "ok": sum(r["result"] == "ok" for r in real),
                      "failed": sum(r["result"] not in ("ok",) for r in real),
                      "per_hour": round(len(real) / (span / 3600), 3),
                      "by_layer": _count(real, "layer")},
        "connection_failures": len(store.events(limit=10000, since=t0,
                                                kinds=["connectivity_change", "interface_removed", "tor_unavailable"])),
        "reuse": reuse,
        "sessions": len(sessions),
        "direct_exposure_seconds": sum(_overlap({"started": s["started"], "ended": s["ended"]}, t0, t1) for s in direct),
    }


def _uses(ivs, layer):
    c = defaultdict(int)
    for i in ivs:
        if i["layer"] == layer:
            c[i["key"]] += 1
    return c


def _count(rows, key):
    c = defaultdict(int)
    for r in rows:
        c[r[key]] += 1
    return dict(c)


def _top(d: dict, labels: dict, layer: str, n: int = 20) -> list[dict]:
    return [{"key": k, "label": labels.get((layer, k), k), "seconds": round(v)}
            for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]


# ── Network Exposure Score ──────────────────────────────────────────────────

INDICATORS = [
    # id, peso, etiqueta, función(ctx) -> (presente: bool|None, explicación)
    ("direct_route", 25, N_("Tráfico directo sin túnel ni proxy"),
     lambda c: (not c["net"]["via_tunnel"].get("ipv4") and not c.get("proxy_active"),
                _("Los destinos ven la IP pública de tu router."))),
    ("ipv6_leak", 20, N_("Fuga IPv6"), lambda c: (_has(c, "ipv6_leak", "fail"), _("IPv6 evita el túnel."))),
    ("dns_leak", 15, N_("DNS fuera del túnel o fuga confirmada"),
     lambda c: (_has(c, "dns_leak_config", "fail") or _has(c, "dns_leak_active", "fail"), _("Resolvers fuera del túnel."))),
    ("dns_plain", 5, N_("DNS sin cifrar"), lambda c: (_has(c, "dns_plaintext", "warn"), _("El ISP/LAN ve los nombres."))),
    ("exposed_proxy", 8, N_("Proxy accesible desde la LAN"), lambda c: (_has(c, "proxy_exposed", "fail"), _("Otros equipos pueden usarlo."))),
    ("mac", 4, N_("MAC de fábrica"), lambda c: (_has(c, "mac_permanent", "warn"), _("Identificable en la red local."))),
    ("tz", 4, N_("Zona horaria incoherente con la salida"), lambda c: (_has(c, "tz_mismatch", "warn"), _("El navegador la revela."))),
    ("no_killswitch", 8, N_("Túnel sin kill-switch"), lambda c: (_has(c, "killswitch", "warn"), _("Una caída expondría la IP."))),
    ("profile_violation", 15, N_("Violación de la política del perfil"),
     lambda c: (_has(c, "profile_geo", "fail") or _has(c, "tunnel_bypass", "fail") or _has(c, "tor_required", "fail"),
                _("La salida no cumple el perfil activo."))),
    ("long_session", 5, N_("Misma salida durante mucho tiempo"),
     lambda c: ((c.get("session_age") or 0) > 6 * 3600, _("Más de 6 h con la misma identidad de red."))),
    ("correlation", 10, N_("Riesgo de correlación entre perfiles"),
     lambda c: (bool(c.get("correlation_high")), _("Perfiles comparten elementos de identidad de red."))),
]


def _has(ctx, check, status):
    return any(f["check"] == check and f["status"] == status for f in ctx.get("findings", []))


def exposure_score(ctx: dict) -> dict:
    items, total, score = [], 0, 0
    for iid, weight, label, fn in INDICATORS:
        try:
            present, why = fn(ctx)
        except Exception:  # noqa: BLE001
            present, why = None, _("no evaluable con los datos disponibles")
        total += weight
        if present:
            score += weight
        items.append({"id": iid, "label": _(label), "weight": weight, "present": present, "explanation": why})
    value = round(100 * score / total) if total else 0
    level = "baja" if value < 20 else "media" if value < 45 else "alta"
    return {"score": value, "level": level, "indicators": items,
            "disclaimer": _("Indicador orientativo de exposición observable a nivel de red. No mide ni garantiza "
                          "anonimato: no ve cookies, cuentas, huella del navegador ni comportamiento.")}


# ── Correlation Risk Engine ─────────────────────────────────────────────────

def _hour_hist(ivs) -> list[float]:
    h = [0.0] * 24
    for i in ivs:
        s, e = i["started"], i["ended"] or now()
        while s < e:
            lt = time.localtime(s)
            nxt = min(e, s + 3600 - (lt.tm_min * 60 + lt.tm_sec))
            h[lt.tm_hour] += nxt - s
            s = nxt
    return h


def _cos(a, b) -> float:
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(x * x for x in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def correlation(store, cfg: dict, since: float | None = None) -> dict:
    since = since or now() - 30 * 86400
    ivs = store.intervals(since=since, limit=200000)
    by_prof: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    prof_ivs: dict[str, list] = defaultdict(list)
    for i in ivs:
        if not i["profile"]:
            continue
        by_prof[i["profile"]][i["layer"]].add(i["key"])
        if i["layer"] == "profile":
            prof_ivs[i["profile"]].append(i)
    profiles = sorted(by_prof)
    thr = cfg.get("correlation", {}).get("time_similarity_threshold", 0.85)
    pairs = []
    for x in range(len(profiles)):
        for y in range(x + 1, len(profiles)):
            a, b = profiles[x], profiles[y]
            risks = []
            for layer, label, sev in (("public_ip", _("IP pública de salida"), "high"), ("wan_ip", _("IP WAN del router"), "medium"),
                                      ("vpn_server", _("servidor VPN"), "high"), ("tor_exit", _("exit de Tor"), "medium"),
                                      ("proxy", "proxy", "medium"), ("dns_resolver", _("resolvers DNS"), "low"),
                                      ("combination", _("configuración de salida completa"), "high")):
                shared = by_prof[a][layer] & by_prof[b][layer]
                if shared:
                    risks.append({"type": f"shared_{layer}", "severity": sev,
                                  "detail": _("comparten {label}: {n}", label=label, n=len(shared)), "items": sorted(shared)[:10]})
            sim = _cos(_hour_hist(prof_ivs[a]), _hour_hist(prof_ivs[b]))
            if sim >= thr:
                risks.append({"type": "schedule", "severity": "low",
                              "detail": _("horarios de uso similares (similitud {sim:.2f})", sim=sim)})
            overlap = sum(_overlap(i, j["started"], j["ended"] or now()) for i in prof_ivs[a] for j in prof_ivs[b])
            if overlap > 0:
                risks.append({"type": "simultaneous", "severity": "medium",
                              "detail": _("uso simultáneo durante {v1}s", v1=int(overlap))})
            pairs.append({"profiles": [a, b], "risks": risks,
                          "level": max((r["severity"] for r in risks), key=_sev, default="none")})
    return {"profiles": profiles, "pairs": pairs,
            "high": any(p["level"] == "high" for p in pairs),
            "note": _("La separación de red no impide la correlación por cookies, cuentas, huella del navegador "
                    "o patrones de escritura.")}


def _sev(s):
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(s, 0)


# ── anomalías ───────────────────────────────────────────────────────────────

def anomalies(store, window: float = 86400) -> list[dict]:
    out = []
    t = now()
    route_changes = store.events(limit=1000, since=t - 3600, kinds=["route_change"])
    if len(route_changes) >= 5:
        out.append({"type": "route_flapping", "severity": "medium",
                    "detail": _("{n} cambios de ruta en la última hora", n=len(route_changes))})
    sessions = store.sessions(limit=200, since=t - 7 * 86400)
    closed = [s["duration"] for s in sessions if s["ended"]]
    if len(closed) >= 5 and sessions and sessions[0]["ended"] is None:
        mean, sd = statistics.mean(closed), statistics.pstdev(closed) or 1
        z = (sessions[0]["duration"] - mean) / sd
        if z > 3:
            out.append({"type": "long_session", "severity": "low",
                        "detail": _("sesión actual {z:.1f}σ más larga que la media", z=z)})
    rot_ts = [r["ts"] for r in store.rotations(limit=500, since=t - window) if r["result"] == "ok"]
    for e in store.events(limit=500, since=t - window, kinds=["session_opened"]):
        reason = e["data"].get("reason") or ""
        if reason.startswith("cambio de public_ip") or reason.startswith("cambio de wan_ip"):
            if not any(abs(e["ts"] - r) < 180 for r in rot_ts):
                out.append({"type": "unexpected_ip_change", "severity": "medium", "ts": e["ts"],
                            "detail": _("{reason} sin rotación asociada", reason=reason)})
    countries = [i for i in store.intervals("country", since=t - window)]
    if len({i["key"] for i in countries}) >= 4:
        out.append({"type": "country_hopping", "severity": "low",
                    "detail": _("{n} países de salida en 24h", n=len({i['key'] for i in countries}))})
    return out


def timeline(store, since: float | None = None, limit: int = 300) -> list[dict]:
    since = since or now() - 7 * 86400
    items = [{"ts": e["ts"], "type": "event", "kind": e["kind"], "severity": e["severity"], "data": e["data"]}
             for e in store.events(limit=limit, since=since)]
    items += [{"ts": r["ts"], "type": "rotation", "kind": f"rotation:{r['layer']}",
               "severity": "info" if r["result"] in ("ok", "dry_run_ok") else "warning",
               "data": {"from": r["from_target"], "to": r["to_target"], "result": r["result"], "dry_run": r["dry_run"]}}
              for r in store.rotations(limit=limit, since=since)]
    items += [{"ts": f["ts"], "type": "finding", "kind": f["check_id"], "severity": f["severity"],
               "data": {"title": f["title"], "status": f["status"]}}
              for f in store.findings(limit=limit, since=since) if f["status"] in ("fail", "warn")]
    return sorted(items, key=lambda x: -x["ts"])[:limit]
