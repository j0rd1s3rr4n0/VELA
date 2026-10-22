"""Detección de anomalías de red con una línea base local.

VELA ya avisa de fugas y de cambios de ruta. Este módulo añade una capa estadística sobre
señales agregadas que el daemon muestrea cada minuto:

  * volumen de tráfico de la interfaz de salida (rx/tx);
  * número de conexiones a Internet y fan-out por proceso;
  * procesos, países y puertos nuevos;
  * destinos que reaparecen en muchas muestras (posible beaconing).

La línea base vive en la tabla `metrics` (SQLite, 0600). No se envía nada fuera: todo se
compara contra el propio historial. Las anomalías son indicios, no certezas; siempre se
muestran con la evidencia y la explicación.
"""

from __future__ import annotations

from .i18n import _

import statistics
from collections import Counter

from .util import now

COMMON_PORTS = {22, 53, 80, 123, 443, 465, 587, 993, 995, 5222, 5223, 8443}
COOLDOWN = 6 * 3600
METRIC_RETENTION = 35 * 86400
SENSITIVITY = {"baja": 4.0, "media": 3.0, "alta": 2.2}


def _z(value: float, values: list[float]) -> float:
    if len(values) < 8:
        return 0.0
    mean = statistics.mean(values)
    sd = statistics.pstdev(values) or 1e-9
    return (value - mean) / sd


def _flow_state(engine) -> dict:
    st = getattr(getattr(engine, "leakwatcher", None), "state", None)
    if st and now() - st.get("ts", 0) <= 15:
        return st
    # Motor local sin daemon: una lectura puntual, sin enriquecer con threat intel.
    try:
        from . import leakwatch
        if not engine.net:
            return {"flows": [], "summary": {}}
        allow = set((engine.cfg.get("leakwatch") or {}).get("allow") or [])
        socks = leakwatch.read_sockets()
        wanted = {s["inode"] for s in socks if leakwatch.is_internet(s["remote"])}
        return leakwatch.classify(socks, engine.net, allow, leakwatch.owners(wanted))
    except Exception:  # noqa: BLE001
        return {"flows": [], "summary": {}}


def collect(engine) -> dict:
    """Muestrea el estado actual y lo guarda como métricas. Devuelve el snapshot."""
    st = _flow_state(engine)
    flows = st.get("flows") or []
    remotes = [f["remote"] for f in flows]
    ports = [int(f["rport"]) for f in flows if f.get("rport")]
    procs = [f.get("process") or "desconocido" for f in flows]
    by_proc = Counter(procs)
    by_country = Counter()
    for f in flows:
        try:
            cc = (engine.geo.lookup(f["remote"]) or {}).get("country")
        except Exception:  # noqa: BLE001
            cc = None
        by_country[cc or "??"] += 1
    edges = Counter(f"{f['remote']}:{f['rport']}" for f in flows)
    rates = engine.net_rates or {}
    egress = (((engine.net or {}).get("egress") or {}).get("ipv4") or {}).get("dev") if engine.net else None
    rate = rates.get(egress) or {}
    snap = {
        "ts": now(),
        "flows": len(flows),
        "remotes": len(set(remotes)),
        "ports": len(set(ports)),
        "procs": len(set(procs)),
        "countries": len(set(by_country)),
        "max_fanout": max(by_proc.values()) if by_proc else 0,
        "rx_bps": float(rate.get("rx_bps") or 0),
        "tx_bps": float(rate.get("tx_bps") or 0),
        "meta": {
            "processes": [{"name": k, "flows": v} for k, v in by_proc.most_common(30)],
            "countries": [{"cc": k, "flows": v} for k, v in by_country.most_common(20)],
            "ports": [{"port": k, "flows": v} for k, v in Counter(ports).most_common(30)],
            "edges": [{"edge": k, "flows": v} for k, v in edges.most_common(40)],
        },
    }
    for key in ("flows", "remotes", "ports", "procs", "countries", "max_fanout", "rx_bps", "tx_bps"):
        engine.store.add_metric(key, snap[key], meta=snap["meta"] if key == "flows" else None, ts=snap["ts"])
    engine.store.put("anomaly_last", snap)
    return snap


def _values(store, key: str, since: float) -> list[float]:
    return [float(r["value"]) for r in store.metrics(key=key, since=since, limit=5000)
            if r.get("value") is not None]


def detect(store, sensitivity: str = "media", window_days: float = 14) -> list[dict]:
    """Anomalías nuevas a partir de las métricas y eventos guardados."""
    t = now()
    since = t - float(window_days) * 86400
    out: list[dict] = []
    z_limit = SENSITIVITY.get(sensitivity, 3.0)

    def add(kind, severity, detail, evidence=None, ts=None):
        out.append({"type": kind, "severity": severity, "detail": detail, "evidence": evidence or {},
                    "ts": ts or t, "source": "baseline"})

    latest = store.latest_metric("flows")
    if not latest:
        return out
    meta = latest.get("meta") or {}
    hist_flows = _values(store, "flows", since)
    hist_tx = _values(store, "tx_bps", since)
    hist_rx = _values(store, "rx_bps", since)
    hist_fan = _values(store, "max_fanout", since)

    # Volumen: pico claro frente a la media de la ventana.
    for key, label, hist in (("tx_bps", _("subida"), hist_tx), ("rx_bps", _("descarga"), hist_rx)):
        last = store.latest_metric(key)
        value = last.get("value") if last else None
        if value is None:
            continue
        z = _z(float(value), [v for v in hist if v is not None][1:])
        if z >= z_limit and value > 512 * 1024:
            add("traffic_spike", "medium",
                _("pico de {label}: {value:.1f} MB/s ({z:.1f}σ sobre la línea base)", label=label,
                  value=float(value) / 1e6, z=z),
                {"metric": key, "value": float(value), "z": round(z, 2)})

    flows = int(latest.get("value") or 0)
    z = _z(float(flows), hist_flows[1:])
    if z >= z_limit and flows >= 20:
        add("connection_spike", "medium",
            _("{n} conexiones a Internet ({z:.1f}σ sobre la línea base)", n=flows, z=z),
            {"flows": flows, "z": round(z, 2)})

    fan = int((store.latest_metric("max_fanout") or {}).get("value") or 0)
    zf = _z(float(fan), hist_fan[1:])
    if zf >= z_limit and fan >= 15:
        add("fanout", "medium",
            _("un proceso abre {n} conexiones simultáneas ({z:.1f}σ); revisa si es esperado", n=fan, z=zf),
            {"fanout": fan, "z": round(zf, 2)})

    # Procesos, países y puertos que no aparecían antes en la ventana.
    previous = store.metrics(key="flows", since=since, limit=5000)[1:]
    old_procs, old_countries, old_ports = set(), set(), set()
    for row in previous:
        m = row.get("meta") or {}
        old_procs.update(x.get("name") for x in m.get("processes") or [] if x.get("name"))
        old_countries.update(x.get("cc") for x in m.get("countries") or [] if x.get("cc"))
        old_ports.update(int(x["port"]) for x in m.get("ports") or [] if x.get("port") is not None)
    enough_baseline = len(previous) >= 5
    new_procs = ([x for x in meta.get("processes") or [] if x.get("name") not in old_procs and x.get("flows", 0) >= 3]
                 if enough_baseline else [])
    for p in new_procs[:5]:
        add("new_process", "low", _("proceso nuevo con conexiones a Internet: {name} ({n})",
                                    name=p["name"], n=p.get("flows", 0)),
            {"process": p["name"], "flows": p.get("flows", 0)})
    new_countries = ([x for x in meta.get("countries") or [] if x.get("cc") not in old_countries
                      and x.get("cc") not in ("??", None)] if enough_baseline else [])
    for c in new_countries[:5]:
        add("new_country", "low", _("país de destino nuevo en la ventana: {cc} ({n} conexiones)",
                                    cc=c["cc"], n=c.get("flows", 0)),
            {"country": c["cc"], "flows": c.get("flows", 0)})
    rare = [x for x in meta.get("ports") or [] if int(x["port"]) not in COMMON_PORTS
            and int(x["port"]) not in old_ports and int(x["port"]) > 1024 and x.get("flows", 0) >= 2]
    for p in rare[:5]:
        add("rare_port", "low", _("puerto poco habitual con varias conexiones: {port} ({n})",
                                  port=p["port"], n=p.get("flows", 0)),
            {"port": p["port"], "flows": p.get("flows", 0)})

    # Beaconing: el mismo destino aparece en casi todas las muestras recientes.
    edges: Counter = Counter()
    for row in [latest, *previous[:11]]:
        for e in (row.get("meta") or {}).get("edges") or []:
            edges[e.get("edge")] += 1
    for edge, n in edges.most_common(5):
        if n >= 6:
            add("beaconing", "low", _("conexión recurrente a {edge} en {n} de las últimas muestras", edge=edge, n=n),
                {"edge": edge, "samples": n})

    # Cambios repetidos de DNS en la ventana (señal de manipulación o apps con DoH propio).
    dns_changes = store.events(limit=200, since=t - 86400, kinds=["dns_change", "dns_encryption_change",
                                                                 "dns_route_change"])
    if len(dns_changes) >= 8:
        add("dns_churn", "medium", _("{n} cambios de DNS en 24 h", n=len(dns_changes)),
            {"events": len(dns_changes)})
    return out


def maybe_emit(engine, interval: float = 60.0) -> list[dict]:
    """Muestrea y emite eventos nuevos con enfriamiento. El daemon la llama desde `tick`."""
    cfg = (engine.cfg.get("anomaly") or {})
    if not cfg.get("enabled", True):
        return []
    if now() - float(engine.timers.get("anomaly", 0)) < interval:
        return []
    engine.timers["anomaly"] = now()
    try:
        snap = collect(engine)
        found = detect(engine.store, cfg.get("sensitivity", "media"), float(cfg.get("window_days", 14)))
    except Exception as e:  # noqa: BLE001
        engine.emit("anomaly_error", "info", {"error": str(e)})
        return []
    seen = engine.store.get("anomaly_seen", {}) or {}
    emitted = []
    for a in found:
        key = a["type"]
        if now() - float(seen.get(key, 0)) < COOLDOWN:
            continue
        seen[key] = now()
        engine.emit("anomaly_detected", a["severity"], {"type": a["type"], "detail": a["detail"],
                                                        "evidence": a.get("evidence")})
        emitted.append(a)
    engine.store.put("anomaly_seen", {k: v for k, v in seen.items() if now() - v < METRIC_RETENTION})
    if now() - float(engine.timers.get("anomaly_prune", 0)) > 86400:
        engine.timers["anomaly_prune"] = now()
        engine.store.prune_metrics(now() - METRIC_RETENTION)
    return emitted
