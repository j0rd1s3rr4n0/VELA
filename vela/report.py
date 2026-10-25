"""Privacy Audit, `doctor` y exportación (JSON / CSV / HTML autocontenido)."""

from __future__ import annotations

from .i18n import N_, _

import csv
import html
import io
import json
import os
import shutil
import stat
import sys
import tempfile

from . import analytics, config as config_mod
from .util import fmt_duration, iso, now, redact, runtime_dir

LIMITATIONS = [
    N_("La geolocalización es local y aproximada (país con la base de Tor): no es la ubicación física real."),
    N_("Sin base ASN (.mmdb) no se puede atribuir proveedor/ASN a las IPs."),
    N_("La IP pública por la ruta por defecto solo se consulta con consentimiento (consent.direct_ip_checks)."),
    N_("Los circuitos de Tor Browser solo son observables si su ControlPort (9151) está abierto y la cookie es legible."),
    N_("No se inspecciona el tráfico de aplicaciones: rutas propias, namespaces o DoH internos no son visibles."),
    N_("El estado de reglas de firewall de terceros (ufw, Docker) no se lee sin privilegios."),
    N_("El test de WebRTC solo cubre el navegador con el que se abre la GUI."),
]


def privacy_audit(engine) -> dict:
    found = engine.run_leaks(active=False)
    status = engine.api_status()
    corr = analytics.correlation(engine.store, engine.cfg)
    performed = sorted({(f["check"], f["mode"], f["method"]) for f in found})
    return {
        "generated": now(), "profile": engine.cfg["active_profile"],
        "summary": {
            "exposure": status["exposure"], "chain": (engine.obs or {}).get("chain_label"),
            "egress": (status["net"]["egress"].get("ipv4") or {}).get("dev"),
            "via_tunnel": status["net"]["via_tunnel"], "tor": status["tor"],
            "public_ip": {k: v.get("ip") if v.get("ok") else v.get("error") for k, v in engine.public.items()},
            "wan": (engine.wan or {}).get("ip") if (engine.wan or {}).get("ok") else (engine.wan or {}).get("error"),
        },
        "findings": found,
        "risks": [f for f in found if f["status"] in ("fail", "warn")],
        "tests_performed": [{"check": c, "mode": m, "method": me} for c, m, me in performed],
        "capabilities": engine.caps,
        "correlation": corr,
        "anomalies": analytics.anomalies(engine.store),
        "limitations": [_(x) for x in LIMITATIONS],
        "consent": engine.cfg["consent"],
        "storage": {"path": engine.store.path, "encrypted": engine.store.encrypted,
                    "note": _("La base NO está cifrada: solo protegida por permisos de archivo (0600).")
                    if not engine.store.encrypted else _("Cifrada con SQLCipher.")},
    }


def doctor(engine) -> list[dict]:
    checks = []

    def c(name, ok, detail, fix=""):
        checks.append({"check": name, "status": "ok" if ok is True else ("warn" if ok is None else "fail"),
                       "detail": detail, "fix": fix})

    c("python", sys.version_info >= (3, 10), sys.version.split()[0], "Python 3.10+")
    try:
        config_mod.load()
        c("config", True, str(config_mod.config_path()) + (_(" (no existe: valores por defecto)")
                                                            if not config_mod.config_path().exists() else ""))
    except Exception as e:  # noqa: BLE001
        c("config", False, str(e), _("vela config edit"))
    if engine.store.memory:
        c("almacenamiento", True, _("modo memoria (sin persistencia)"))
    else:
        mode = stat.S_IMODE(os.stat(engine.store.path).st_mode)
        dmode = stat.S_IMODE(os.stat(os.path.dirname(engine.store.path)).st_mode)
        c(_("permisos base de datos"), mode == 0o600 and dmode == 0o700,
          f"{engine.store.path} {oct(mode)} (dir {oct(dmode)})", "chmod 600 base / 700 directorio")
        c("cifrado", None if not engine.store.encrypted else True,
          _("NO cifrada (SQLCipher no disponible); protegida solo por permisos"), _("pip install sqlcipher3 (opcional)"))
    try:
        with tempfile.NamedTemporaryFile(prefix="vela-doctor-") as f:
            f.write(b"x" * 4096)
            f.flush()
        c(_("directorio temporal"), True, tempfile.gettempdir())
    except OSError as e:
        c(_("directorio temporal"), False, f"{tempfile.gettempdir()}: {e}",
          _("Libera espacio en /tmp (o exporta TMPDIR a otro directorio)"))
    usage = shutil.disk_usage(tempfile.gettempdir())
    c(_("espacio en /tmp"), usage.free / usage.total > 0.1 or None,
      _("{v0} MiB libres de {v2} MiB", v0=usage.free // 2**20, v2=usage.total // 2**20))
    from . import ipc
    sock = ipc.socket_path()
    if sock.exists():
        m = stat.S_IMODE(os.stat(sock).st_mode)
        c(_("daemon (IPC)"), ipc.ping(), f"{sock} {oct(m)}", _("vela daemon start"))
        c(_("permisos IPC"), m == 0o600 and stat.S_IMODE(os.stat(runtime_dir()).st_mode) == 0o700, oct(m))
    else:
        c(_("daemon (IPC)"), None, _("no está en marcha (las interfaces usan el motor local)"), _("vela daemon start"))
    engine.ensure_fresh()
    tor = engine.tor or {}
    c(_("Tor control"), tor.get("available") or (None if not engine.env["tor"]["installed"] else False),
      tor.get("target") or tor.get("error") or _("Tor no instalado"),
      _("sudo usermod -aG debian-tor $USER (y volver a iniciar sesión)") if not tor.get("available") else "")
    if engine.ks_ext is None and engine.net is not None:
        engine.refresh_network()
    kx = engine.ks_ext or {}
    if kx.get("declared_by"):
        c(_("kill-switch del cliente VPN"), bool(kx.get("verified_ipv4")) or None,
          _("{v0}: IPv4 {state}, IPv6 {state2} si cae el túnel", v0=', '.join(kx['declared_by']), state=kx['route_protection']['ipv4']['state'], state2=kx['route_protection']['ipv6']['state']),
          _("verifícalo desconectando la VPN de forma controlada"))
    ks = engine.ks.status()
    c(_("kill-switch propio (nftables)"), ks["can_apply"] or None, ks.get("reason_unavailable") or "aplicable",
      _("consent.allow_killswitch = true y sudo/pkexec"))
    d = engine.dns or {}
    res = (d.get("encryption") or {}).get("resolvers") or []
    c(_("DNS cifrado"), d.get("encrypted") if d.get("encrypted") is not None else None,
      ", ".join(f"{r['addr']} {r['provider'] or '?'} ({r['transport']})" for r in res) or _("sin datos"),
      _("DoT en resolved, un proxy DoH local o el DoH del navegador"))
    caps = {x["id"]: x for x in engine.caps}
    c(_("eventos netlink"), caps.get("net.events", {}).get("status") == "operativa" or None,
      caps.get("net.events", {}).get("detail", "?"))
    c("GeoIP", bool(engine.geo.sources) or None, ", ".join(engine.geo.sources) or _("sin base"),
      _("Instala GeoLite2-City/ASN .mmdb en ~/.local/share/GeoIP y `pip install geoip2` para ciudad y ASN"))
    for key, label in (("direct_ip_checks", _("IP pública por la ruta por defecto")),
                       ("tor_ip_checks", _("IP de salida de Tor")), ("active_dns_leak_test", _("test activo DNS")),
                       ("allow_rotation_changes", _("rotaciones reales")), ("allow_killswitch", "kill-switch")):
        c(f"consentimiento: {label}", None if not engine.cfg["consent"].get(key) else True,
          "activado" if engine.cfg["consent"].get(key) else "desactivado", f"consent.{key} = true")
    return checks


# ── exportación ─────────────────────────────────────────────────────────────

def export_data(engine, since: float | None = None) -> dict:
    return redact({
        "generated": now(), "profile": engine.cfg["active_profile"],
        "sessions": engine.store.sessions(limit=100000, since=since),
        "counters": engine.store.counters(since=since),
        "intervals": engine.store.intervals(since=since, limit=1000000),
        "events": engine.store.events(limit=100000, since=since),
        "findings": engine.store.findings(limit=100000, since=since),
        "rotations": engine.store.rotations(limit=100000, since=since),
        "metrics": engine.store.metrics(since=since, limit=100000),
    })


def to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    buf = io.StringIO()
    keys = list(dict.fromkeys(k for r in rows for k in r))
    w = csv.DictWriter(buf, fieldnames=keys)
    w.writeheader()
    for r in rows:
        w.writerow({k: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v for k, v in r.items()})
    return buf.getvalue()


def _table(rows: list[dict], cols: list[tuple[str, str]]) -> str:
    head = "".join(f"<th>{html.escape(t)}</th>" for _ign, t in cols)
    body = "".join("<tr>" + "".join(f"<td>{html.escape(str(r.get(k) if r.get(k) is not None else '—'))}</td>"
                                    for k, _ign in cols) + "</tr>" for r in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def to_html(engine, data: dict, audit: dict | None = None) -> str:
    sessions = [{**s, "started": iso(s["started"]), "ended": iso(s["ended"]), "duration": fmt_duration(s["duration"])}
                for s in data["sessions"][:500]]
    counters = [{**c, "total": fmt_duration(c["total"])} for c in data["counters"][:300]]
    events = [{**e, "ts": iso(e["ts"]), "data": json.dumps(e["data"], ensure_ascii=False)[:200]} for e in data["events"][:500]]
    parts = [f"<h1>VELA · informe</h1><p>Generado {iso(data['generated'])} · perfil "
             f"<b>{html.escape(data['profile'])}</b></p>"]
    if audit:
        ex = audit["summary"]["exposure"]
        parts.append(_("<h2>Auditoría de privacidad</h2><p>Exposición observable: <b>{score}/100 ({level})</b></p><p class=muted>{v5}</p>", score=ex['score'], level=ex['level'], v5=html.escape(ex['disclaimer'])))
        parts.append(_table(audit["findings"], [("severity", "Severidad"), ("status", "Estado"), ("title", "Hallazgo"),
                                                ("mode", _("Modo")), ("method", _("Método")), ("observed", _("Observado")),
                                                ("confidence", "Confianza"), ("limitations", "Limitaciones"),
                                                ("recommendation", _("Recomendación"))]))
        parts.append(_("<h3>Limitaciones de observabilidad</h3><ul>") +
                     "".join(f"<li>{html.escape(x)}</li>" for x in audit["limitations"]) + "</ul>")
        parts.append(f"<p class=muted>{html.escape(audit['storage']['note'])}</p>")
    parts.append(_("<h2>Sesiones</h2>") + _table(sessions, [("started", _("Inicio")), ("ended", _("Fin")), ("duration", _("Duración")),
                                                         ("profile", "Perfil"), ("egress_iface", "Interfaz"),
                                                         ("public_ip", _("IP pública")), ("wan_ip", _("IP WAN")), ("vpn", _("VPN")),
                                                         ("proxy", _("Proxy")), ("country", _("País")), ("end_reason", _("Cierre"))]))
    parts.append(_("<h2>Contadores</h2>") + _table(counters, [("layer", _("Capa")), ("label", _("Elemento")), ("country", _("País")),
                                                           ("uses", "Usos"), ("total", _("Tiempo total")), ("active", "Activo")]))
    parts.append("<h2>Eventos</h2>" + _table(events, [("ts", "Fecha"), ("severity", "Severidad"), ("kind", "Tipo"),
                                                      ("data", "Detalle")]))
    css = ("body{font:14px system-ui,sans-serif;margin:24px;background:#0f1216;color:#d8dee9}"
           "table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border:1px solid #2b3240;padding:4px 6px;"
           "text-align:left;vertical-align:top}th{background:#1a2029}.muted{color:#8a93a3}h1,h2{color:#e6edf3}")
    return (f"<!doctype html><html lang=es><meta charset=utf-8><title>Informe OPSEC · VELA</title><style>{css}</style>"
            f"<body>{''.join(parts)}</body></html>")
