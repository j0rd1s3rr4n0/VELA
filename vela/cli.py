"""`vela`: interfaz de línea de comandos.

Habla con el daemon por IPC si está en marcha; si no, usa el mismo motor en proceso.
`--json` en cualquier comando devuelve los datos crudos para automatización.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import TAGLINE, __version__
from .util import fmt_duration, iso, now, parse_duration

SEV_COLOR = {"critical": "1;31", "high": "31", "medium": "33", "warning": "33", "low": "36", "info": "37"}
STATUS_COLOR = {"fail": "31", "warn": "33", "pass": "32", "unknown": "90", "ok": "32",
                "operativa": "32", "detectada_inactiva": "33", "sin_permisos": "35", "no_disponible": "90",
                "no_verificable": "36"}
_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text, code):
    return f"\033[{code}m{text}\033[0m" if _COLOR and code else str(text)


def bold(t):
    return c(t, "1")


def table(rows: list[list], headers: list[str]):
    rows = [[("—" if v is None else str(v)) for v in r] for r in rows]
    strip = lambda s: __import__("re").sub(r"\033\[[\d;]*m", "", s)  # noqa: E731
    widths = [max([len(strip(h))] + [len(strip(r[i])) for r in rows]) for i, h in enumerate(headers)]
    print("  ".join(bold(h.ljust(w)) for h, w in zip(headers, widths)))
    for r in rows:
        print("  ".join(v + " " * (w - len(strip(v))) for v, w in zip(r, widths)))


def since_arg(value: str | None) -> float | None:
    return now() - parse_duration(value) if value else None


# ── comandos ────────────────────────────────────────────────────────────────

def cmd_status(b, a):
    s = b.call("status")
    if a.json:
        return s
    obs = s["obs"] or {}
    net = s["net"]
    e4 = net["egress"].get("ipv4") or {}
    print(bold(f"VELA — perfil «{s['profile']}»") +
          (c("  [MODO EMERGENCIA]", "1;31") if s["emergency"] else "") +
          ("" if b.remote else c("  (motor local: arranca `vela daemon start` para monitorizar)", "90")))
    ex = s["exposure"]
    print(f"Exposición observable: {c(str(ex['score']) + '/100 ' + ex['level'], {'baja': '32', 'media': '33', 'alta': '31'}[ex['level']])}"
          f"  (indicador orientativo, no mide anonimato)")
    print(f"\n{bold('Cadena')}: " + " → ".join(f"{h['type']}[{h.get('ip') or h.get('label')}]" for h in obs.get("chain", [])))
    print(f"  salida IPv4 por {e4.get('dev')} (gw {e4.get('gateway') or '-'}), túnel: "
          f"{'sí' if net['via_tunnel'].get('ipv4') else 'no'}, IP local {net['local_ip']}")
    wan = s["wan"] or {}
    print(f"  IP WAN router: {wan.get('ip') if wan.get('ok') else c(wan.get('error', 'no comprobada'), '90')}")
    for route, r in (s["public"] or {}).items():
        val = (f"{r['ip']} ({(r.get('geo') or {}).get('country') or '?'}) vía {r.get('endpoint')} {iso(r.get('ts'))}"
               if r.get("ok") else c(r.get("error"), "90"))
        print(f"  IP pública [{route}]: {val}")
    t = s["tor"] or {}
    if t.get("available"):
        ex_, gd = t.get("exit") or {}, t.get("guard") or {}
        print(f"\n{bold('Tor')} {t.get('version')} ({t.get('target')}): bootstrap {t.get('bootstrap')}%, "
              f"{t.get('circuit_count')} circuitos, {t.get('stream_count')} streams"
              + (c("  [Tor Browser: solo observación]", "33") if t.get("observe_only") else ""))
        print(f"  guard {gd.get('nick')} {gd.get('ip')} ({gd.get('country')}) · exit {ex_.get('nick')} "
              f"{ex_.get('ip')} ({ex_.get('country')}) · circuito {t.get('active_circuit')}")
    else:
        print(f"\n{bold('Tor')}: {c(t.get('error') or 'no disponible', '90')}")
    d = s["dns"] or {}
    enc = d.get("encryption") or {}
    print(f"\n{bold('DNS')} efectivo ({d.get('effective_source')}): " +
          (", ".join(f"{r['addr']} {r['provider'] or '?'} [{r['transport']}]" for r in enc.get("resolvers", []))
           or ", ".join(d.get("effective_servers") or []) or "-") +
          f" · cifrado: {c({True: 'sí', False: 'NO', None: '?'}[d.get('encrypted')], {True: '32', False: '31', None: '90'}[d.get('encrypted')])}"
          + (f" · DoH sale por {enc['upstream_route']['dev']}" if enc.get("upstream_route") else ""))
    kx = (s.get("killswitch") or {}).get("external") or {}
    rp = kx.get("route_protection") or {}
    if rp:
        state = lambda f: c(rp[f]["state"], "32" if rp[f]["state"] == "bloqueado" else "31")  # noqa: E731
        print(f"{bold('Kill-switch')}: {', '.join(kx.get('declared_by') or []) or 'ningún cliente'} · si cae el túnel: "
              f"IPv4 {state('ipv4')} ({rp['ipv4']['detail']}), IPv6 {state('ipv6')}")
    if s["session"]:
        print(f"\n{bold('Sesión')} {s['session']['id']}: {fmt_duration(s['session']['duration'])} "
              f"(desde {iso(s['session']['started'])})")
    if s["live_counters"]:
        print(bold("Contadores en curso:"))
        for layer, cn in s["live_counters"].items():
            print(f"  {layer:18} {cn['label'][:40]:40} actual {fmt_duration(cn['current'])}  total {fmt_duration(cn['total'])}")
    rows = []
    for layer, r in s["rotation"].items():
        rows.append([layer, r["adapter"], "sí" if r["enabled"] else "no",
                     "sí" if r["available"] else c(r["reason"], "90"),
                     fmt_duration(r["remaining"]) if r["remaining"] is not None else "—",
                     f"{r['rotations_last_hour']}/{r['max_per_hour']}"])
    if rows:
        print(f"\n{bold('Rotación')}")
        table(rows, ["capa", "adaptador", "activa", "disponible", "próxima en", "última hora"])
    if s["findings"]:
        print(f"\n{bold('Alertas')}")
        for f in s["findings"]:
            print(f"  {c(f['severity'].upper(), SEV_COLOR[f['severity']])} {f['title']} — {f['observed']}")
    return None


def cmd_discover(b, a):
    if a.write_config:
        from .discovery import discover, recommend, write_config
        _, cfg = recommend(discover())
        write_config(cfg, Path(a.write_config).expanduser(), a.force)
        print(f"configuración sugerida escrita en {a.write_config}")
    r = b.call("discover")
    if a.json:
        return r
    sysi = r["environment"]["system"]
    print(bold(f"{sysi['distro']} · kernel {sysi['kernel']} · {sysi['arch']}") +
          f" · virtualización: {sysi['virtualization'] or 'no'} · contenedor: {sysi['container'] or 'no'}"
          f"{' · WSL' if sysi['wsl'] else ''}")
    table([[cp["area"], cp["id"], c(cp["status"], STATUS_COLOR[cp["status"]]), cp["detail"]] for cp in r["capabilities"]],
          ["área", "capacidad", "estado", "detalle"])
    print()
    for n in r["notes"]:
        if n["level"] in ("warn",):
            print(f"  {c('⚠', '33')} [{n['area']}] {n['text']}")


def cmd_network(b, a):
    n = b.call("network")
    if a.json:
        return n
    rows = []
    for i in n["interfaces"]:
        addrs = ", ".join(f"{x['addr']}/{x['prefix']} ({x['class']})" for x in i["addrs"])
        rows.append([i["name"], i["kind"], c("up", "32") if i["up"] else c("down", "90"), i["mac_origin"], addrs])
    table(rows, ["interfaz", "tipo", "estado", "MAC", "direcciones"])
    print(f"\n{bold('Rutas por defecto')}")
    for fam in ("ipv4_default", "ipv6_default"):
        for r in n["routes"][fam]:
            print(f"  {fam[:4]} via {r['gateway']} dev {r['dev']} metric {r['metric']} table {r['table']}")
    for fam in ("ipv4", "ipv6"):
        e = n["egress"].get(fam)
        print(f"  salida efectiva {fam}: " + (f"{e['dev']} (src {e['src']}, gw {e['gateway']})" if e else "sin ruta"))
    if n["policy_rules"]:
        print(f"{bold('Policy routing')}: " + "; ".join(json.dumps(r) for r in n["policy_rules"]))
    print(f"túneles activos: {', '.join(n['tunnels']) or 'ninguno'}")


def _bps(v):
    if v is None:
        return "—"
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if v < 1024:
            return f"{v:.0f} {unit}" if unit == "B/s" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} TB/s"


def _bytes(v):
    if v is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024:
            return f"{v:.0f} {unit}" if unit == "B" else f"{v:.1f} {unit}"
        v /= 1024
    return f"{v:.1f} PB"


def cmd_networks(b, a):
    n = b.call("networks")
    if a.json:
        return n
    rates = n.get("rates") or {}
    order = ["wifi", "lan", "vpn", "bloqueo", "máquinas virtuales", "contenedores", "virtual", "loopback"]
    rows = []
    for i in sorted(n["interfaces"], key=lambda x: (order.index(x["category"]) if x["category"] in order else 9, x["name"])):
        if i["category"] == "loopback" or (i["name"].startswith("veth") and not a.all):
            continue
        r = rates.get(i["name"], {})
        w = i.get("wifi") or {}
        detail = []
        if w:
            detail.append(f"SSID {w['ssid']} ({w['security']}, señal {w['signal']}%, canal {w['channel']})")
        if i.get("connection"):
            detail.append(f"conexión «{i['connection']}»")
        if i["gateway"]:
            detail.append(f"gw {i['gateway']}" + (f" [{i['gateway_mac']} {i['gateway_vendor'] or ''}]".rstrip(" ]") + "]"
                                                    if i["gateway_mac"] else ""))
        rows.append([i["name"], i["category"], c("up", "32") if i["up"] else c("down", "90"),
                     ", ".join(i["subnets"]) or "—", f"↓{_bps(r.get('rx_bps'))} ↑{_bps(r.get('tx_bps'))}",
                     f"↓{_bytes(i['stats']['rx_bytes'])} ↑{_bytes(i['stats']['tx_bytes'])}", len(i["neighbors"]),
                     " · ".join(detail)])
    table(rows, ["interfaz", "red", "estado", "subred", "tráfico ahora", "total", "vecinos", "detalle"])
    if a.neighbors:
        for i in n["interfaces"]:
            if i["neighbors"] and (a.all or not i["name"].startswith("veth")):
                print(f"\n{bold('Vecinos en ' + i['name'])} (tabla ARP/NDP del kernel; no se escanea la red)")
                table([[x["ip"], x["mac"], x["vendor"] or "?", x["state"], "gateway" if x["ip"] == i["gateway"] else ""]
                       for x in sorted(i["neighbors"], key=lambda x: x["ip"])], ["IP", "MAC", "fabricante", "estado", ""])
    if n.get("libvirt") is not None:
        print(f"\n{bold('Redes de máquinas virtuales (libvirt)')}")
        table([[v["name"], c("activa", "32") if v["active"] else c("inactiva", "90"), v["forward"], v["bridge"], v["ip"],
                c("¡NO AISLADA!", "31") if v["isolation_broken"] else ("aislada" if v["forward"] == "isolated" else "")]
               for v in n["libvirt"]], ["red", "estado", "forward", "bridge", "IP", "aislamiento"])
    if n.get("docker") is not None:
        print(f"\n{bold('Redes Docker')}")
        table([[d["name"], d["driver"], d["bridge"] or "—", "interna" if d["internal"] else "con salida"] for d in n["docker"]],
              ["red", "driver", "bridge", "salida"])
    print(f"\n{bold('Redes guardadas (NetworkManager)')}")
    table([[s["name"], s["type"], iso(s["last_used"]) if s["last_used"] else "nunca", "sí" if s["autoconnect"] else "no"]
           for s in n["saved"]], ["nombre", "tipo", "último uso", "autoconexión"])
    if n.get("known"):
        print(f"\n{bold('Redes vistas por VELA')} (huella: SSID + MAC del gateway)")
        table([[k["label"], k["subnet"], k["gateway"], k["gateway_mac"], k["devices"], iso(k["first"]), iso(k["last"])]
               for k in n["known"]], ["red", "subred", "gateway", "MAC gateway", "dispositivos", "primera vez", "última vez"])
    return None


VERDICT_COLOR = {"fuga": "1;31", "directa": "33", "protegida": "32", "permitida": "36", "otra": "90"}


def _leak_screen(r, show_all):
    pub = (r.get("public") or {}).get("default") or {}
    e4 = (r.get("egress") or {}).get("ipv4") or {}
    s = r["summary"]
    lines = [bold("VELA · IP y fugas en tiempo real") + c(f"   {iso(r['ts'])}   (Ctrl-C para salir)", "90")]
    tun = c(f"túnel {', '.join(r['tunnels'])}", "32") if r["tunnel_up"] else c("SIN TÚNEL (VPN desconectada)", "1;31")
    lines.append(f"Salida: {e4.get('dev')} · {tun}")
    if pub.get("ok"):
        tag = (c("  ← ¡TU IP REAL!", "1;31") if pub.get("is_real_ip") and pub.get("via_tunnel") else
               c("  (IP de la VPN)", "32") if pub.get("via_tunnel") else c("  (tu IP real)", "33"))
        lines.append(f"IP pública: {bold(pub['ip'])} {(pub.get('geo') or {}).get('country') or ''} vía {pub.get('endpoint')} "
                     f"hace {int(r['ts'] - pub['ts'])} s{tag}")
    else:
        lines.append(f"IP pública: {c(pub.get('error') or 'pendiente', '90')}")
    kx = r.get("killswitch") or {}
    rp = kx.get("route_protection") or {}
    if rp:
        lines.append(f"Kill-switch si cae el túnel: IPv4 {rp['ipv4']['state']}, IPv6 {rp['ipv6']['state']}"
                     + (f" ({', '.join(kx.get('declared_by') or [])})" if kx.get("declared_by") else ""))
    lines.append(f"Conexiones a Internet: {c(str(s.get('fugas', 0)) + ' fugas', VERDICT_COLOR['fuga'] if s.get('fugas') else '32')}"
                 f" · {s.get('protegidas', 0)} protegidas · {c(str(s.get('directas', 0)) + ' directas', '33' if s.get('directas') else '90')}"
                 f" · {s.get('permitidas', 0)} permitidas")
    flows = sorted(r["flows"], key=lambda f: ["fuga", "directa", "otra", "permitida", "protegida"].index(f["verdict"]))
    if not show_all:
        flows = [f for f in flows if f["verdict"] in ("fuga", "directa")] or flows[:15]
    lines.append("")
    lines.append(bold(f"{'veredicto':10} {'proceso':20} {'proto':5} {'destino':28} {'país':4} {'VT':8} interfaz"))
    for f in flows[:40]:
        vt = f.get("vt")
        vt_txt = f"{vt['malicious']}/{vt['total']}" if vt else "—"
        vt_col = ("31" if vt["malicious"] >= 3 else "33" if (vt["malicious"] or vt["suspicious"]) else "32") if vt else "90"
        lines.append(f"{c(f['verdict'].ljust(10), VERDICT_COLOR[f['verdict']])} {f['process'][:20]:20} {f['proto']:5} "
                     f"{(f['remote'] + ':' + str(f['rport']))[:28]:28} {(f.get('country') or '—'):4} "
                     f"{c(vt_txt.ljust(8), vt_col)} {f['iface'] or '?'}" + (c(" DNS", "31") if f["dns"] else ""))
    live = r.get("intel_live") or {}
    lines.append(c(f"VirusTotal automático: {live.get('status', '—')} · cola {live.get('queued', 0)} · "
                   f"hoy {live.get('today', 0)}/{live.get('limit', '—')}", "90"))
    if not r["tunnel_up"] and s.get("directas"):
        lines.append(c("\nSin VPN, todas estas conexiones muestran tu IP real. Para evitarlo: `vela fix`.", "33"))
    return "\n".join(lines)


def cmd_leakwatch(b, a):
    import time as _t
    if a.once or a.json:
        r = b.call("leakwatch")
        if a.json:
            return r
        print(_leak_screen(r, a.all))
        return None
    try:
        while True:
            r = b.call("leakwatch")
            out = _leak_screen(r, a.all)
            print("\033[2J\033[H" + out if sys.stdout.isatty() else out + "\n", flush=True)
            _t.sleep(a.interval)
    except KeyboardInterrupt:
        pass
    return None


def cmd_routes(b, a):
    r = b.call("routes")
    if a.json:
        return r
    print(bold("Cómo viaja tu tráfico ahora"))
    for line in r["explain"]:
        print(f"  • {line}")
    print()
    names = {n["id"]: n["label"] for n in r["nodes"]}
    kcol = {"vpn": "32", "direct": "33", "proxy": "36", "tor": "35"}
    for l in sorted(r["links"], key=lambda l: (names[l["source"]], -l["value"])):
        print(f"  {names[l['source']][:34]:34} → {c(names[l['target']][:44].ljust(44), kcol.get(l['kind'], ''))} "
              f"{l['value']:>4} conexiones")
    return None


def cmd_vpn(b, a):
    v = b.call("vpn_list")
    if a.json:
        return v
    table([[cp["id"], c(cp["status"], STATUS_COLOR[cp["status"]]), cp["detail"]] for cp in v["capabilities"]],
          ["tecnología", "estado", "detalle"])
    print(f"túneles: {', '.join(v['tunnels']) or 'ninguno'} · tráfico IPv4 por túnel: "
          f"{'sí' if v['via_tunnel'].get('ipv4') else 'no'} · adaptador de rotación: {v['adapter'] or 'ninguno'}")


def cmd_proxy(b, a):
    p = b.call("proxy_list")
    if a.json:
        return p
    table([[f"127.0.0.1:{x['port']}", x["kind"], x.get("bind"), x.get("owner"),
            c("alcanzable", "32") if x["reachable"] else c(x["error"], "31")] for x in p["local"]],
          ["proxy", "protocolo", "escucha en", "proceso", "estado"])
    print(f"túneles ssh -D: {p['ssh_tunnels'] or 'ninguno'} · proxychains: "
          f"{(p['proxychains'] or {}).get('file', 'no')} · entorno: {p['env'] or 'ninguno'} · "
          f"escritorio: {(p['desktop'] or {}).get('mode')}")
    print(f"pool de rotación: {p['pool'] or 'vacío (rotation.proxy.pool)'} · forwarder: "
          f"{(p['forwarder'] or {}).get('listen', 'no iniciado')}")


def cmd_tor(b, a):
    if a.action == "newnym":
        return cmd_rotate(b, argparse.Namespace(layer="tor", dry_run=a.dry_run, force=a.force, json=a.json))
    t = b.call("tor_status")
    if a.json:
        return t
    if not t.get("available"):
        print(c(f"Tor no disponible: {t.get('error')}", "31"))
        return None
    print(bold(f"Tor {t['version']} vía {t['target']}") + f" · bootstrap {t['bootstrap']}% · "
          f"circuitos {t['circuit_count']} · streams {t['stream_count']}")
    for circ in t["circuits"]:
        mark = c("●", "32") if t.get("active") and circ["id"] == t["active"]["id"] else " "
        hops = " → ".join(f"{h.get('nick')}({h.get('country') or '?'})" for h in circ["path"])
        print(f" {mark} {circ['id']:>8}  streams {circ.get('streams', 0):<3} {hops}")
    if t.get("guards"):
        print(bold("Guards: ") + ", ".join(f"{g['fp'][:8]}… {g['status']}" for g in t["guards"]))
    chk = t.get("tor_check") or {}
    if chk.get("ok"):
        print(f"Comprobación externa: {chk['ip']} IsTor={chk.get('is_tor')} ({chk['endpoint']}, {iso(chk['ts'])})")
    print(c("No se fuerzan cambios de guard. NEWNYM no garantiza un exit distinto.", "90"))


def cmd_dns(b, a):
    r = b.call("dns_check", active=a.active)
    if a.json:
        return r
    s = r["snapshot"]
    print(bold(f"DNS ({s['backend']})") + f" · resolv.conf → {s['resolv_conf_target']} {s['resolv_conf']}"
          + (f" · modo {s['resolv_mode']}" if s.get("resolv_mode") else ""))
    enc = s.get("encryption") or {}
    print(bold("Resolver efectivo") + f" ({s.get('effective_source')}):")
    for res in enc.get("resolvers", []):
        col = {True: "32", False: "31", None: "90"}[res["encrypted"]]
        print(f"  {res['addr']:14} {res['provider'] or 'desconocido':24} {c(res['transport'], col)}"
              + (f" → {res['upstream']}" if res.get("upstream") else "") + c(f"  ({res['evidence']})", "90"))
    if enc.get("upstream_route"):
        print(f"  conexión DoH hacia {enc['upstream_route']['ip']} sale por {enc['upstream_route']['dev']}")
    for br in enc.get("browsers", []):
        print(f"  navegador {br['browser']}: DoH {br['mode']} → {br['uri']}")
    print(bold("Configuración de systemd-resolved:"))
    rows = [[n, ", ".join(l["servers"]) or "—", ", ".join(l["domains"]) or "—", "sí" if l["default_route"] else "no",
             "sí" if l["dot"] else "no", l["dnssec"]] for n, l in s["links"].items() if l["servers"] or l["domains"]]
    if s.get("global", {}).get("servers"):
        rows.insert(0, ["Global", ", ".join(s["global"]["servers"]), "", "", "", ""])
    table(rows, ["enlace", "servidores", "dominios", "ruta por defecto", "DoT", "DNSSEC"])
    _print_findings(r["findings"])


def _print_findings(found):
    for f in found:
        print(f"\n{c(f['severity'].upper(), SEV_COLOR[f['severity']])} {c(f['status'], STATUS_COLOR[f['status']])} "
              f"{bold(f['title'])} [{f['mode']}]")
        print(f"  método: {f['method']}\n  observado: {f['observed']}\n  limitaciones: {f['limitations']}\n"
              f"  confianza: {f['confidence']} · recomendación: {f['recommendation']}")


def cmd_leaks(b, a):
    r = b.call("leaks", active=a.active)
    if a.json:
        return r
    _print_findings(r)


def cmd_ip(b, a):
    r = b.call("public_ip", route=a.route)
    if a.json:
        return r
    for x in r:
        if x.get("ok"):
            g = x.get("geo") or {}
            print(f"[{x['route']}] {bold(x['ip'])} {g.get('country_name') or '?'} ({g.get('source')}) "
                  f"vía {x['endpoint']} en {x['rtt_ms']} ms" + (f" IsTor={x['is_tor']}" if "is_tor" in x else ""))
        else:
            print(f"[{x['route']}] {c(x['error'], '33')}")
    w = b.call("router")
    print(f"[router WAN] " + (f"{w['ip']} ({w.get('device')})" + (" CGNAT" if w.get("cgnat") else "") +
                              (" doble NAT" if w.get("double_nat") else "") if w.get("ok") else c(w.get("error"), "90")))


def cmd_sessions(b, a):
    rows = b.call("sessions", limit=a.limit, since=since_arg(a.since), profile=a.profile)
    if a.json:
        return rows
    table([[s["id"], iso(s["started"]), iso(s["ended"]) if s["ended"] else c("activa", "32"),
            fmt_duration(s["duration"]), s["profile"], s["egress_iface"], s["vpn"], s["proxy"],
            s["public_ip"], s["wan_ip"], (s["tor_exit"] or "")[:8] or None, s["end_reason"]] for s in rows],
          ["id", "inicio", "fin", "duración", "perfil", "interfaz", "vpn", "proxy", "ip pública", "ip wan",
           "tor exit", "cierre"])


def cmd_counters(b, a):
    rows = b.call("counters", layer=a.layer, since=since_arg(a.since), profile=a.profile)
    if a.json:
        return rows
    table([[r["layer"], r["label"][:46], r["country"], r["uses"], r["total_fmt"],
            c(r["current_fmt"], "32") if r["current_fmt"] else None, iso(r["last_seen"])] for r in rows],
          ["capa", "elemento", "país", "usos", "tiempo total", "en curso", "último uso"])


def cmd_history(b, a):
    rows = b.call("timeline", since=since_arg(a.since), limit=a.limit)
    if a.json:
        return rows
    for r in reversed(rows):
        if a.severity and r["severity"] not in a.severity.split(","):
            continue
        print(f"{iso(r['ts'])} {c(r['severity'][:4].upper(), SEV_COLOR.get(r['severity'], ''))} "
              f"{r['kind']:24} {json.dumps(r['data'], ensure_ascii=False)[:140]}")


def cmd_watch(b, a):
    print(c("Escuchando eventos (Ctrl-C para salir)…", "90"))
    try:
        for ev in b.subscribe():
            print(f"{iso(ev['ts'])} {c(ev['severity'][:4].upper(), SEV_COLOR.get(ev['severity'], ''))} "
                  f"{ev['kind']:24} {json.dumps(ev['data'], ensure_ascii=False)[:160]}", flush=True)
    except KeyboardInterrupt:
        pass


def cmd_rotate(b, a):
    if not a.layer:
        r = b.call("rotation_status")
        if a.json:
            return r
        for layer, st in r["status"].items():
            print(f"{bold(layer)} {st['adapter']}: activa={st['enabled']} disponible={st['available']} "
                  f"{st['reason'] or ''} próxima en {fmt_duration(st['remaining']) if st['remaining'] is not None else '—'}")
        print(bold("\nÚltimas rotaciones"))
        table([[iso(x["ts"]), x["layer"], x["adapter"], "sí" if x["dry_run"] else "no", x["from_target"],
                x["to_target"], x["result"]] for x in r["history"][:15]],
              ["fecha", "capa", "adaptador", "dry-run", "desde", "hacia", "resultado"])
        return None
    r = b.call("rotate", layer=a.layer, dry_run=a.dry_run, force=a.force)
    if a.json:
        return r
    print(bold(f"Rotación {a.layer} ({r.get('adapter', '-')}){' [dry-run]' if a.dry_run else ''}: ") +
          c(r["result"], "32" if r["result"] in ("ok", "dry_run_ok") else "31"))
    for s in r["steps"]:
        print(f"  {c('✔', '32') if s['ok'] else c('✘', '31')} {s['step']}. {s['name']} {c(s['detail'], '90')}")
    if r.get("observed"):
        print(f"  observado: {r['observed']}")
    return None


def cmd_profiles(b, a):
    if a.action == "generate":
        r = b.call("profiles_generate", write=a.write)
        if a.json:
            return r
        for name, p in r["profiles"].items():
            tag = c(" (ya existe, no se toca)", "90") if name in r["existing"] else ""
            print(bold(f"● {name}") + tag + f": {p['description']}")
            print(f"    Tor={'sí' if p['use_tor'] else 'no'} · VPN obligatoria={'sí' if p['require_vpn'] else 'no'} · "
                  f"kill-switch={'sí' if p['require_killswitch'] else 'no'} · DNS={p['dns_policy']} · "
                  f"países prohibidos={p['forbidden_countries'] or 'ninguno'} · retención {p['retention_days']} d")
            for why in p["_why"]:
                print(c(f"      · {why}", "90"))
        if r.get("written"):
            w = r["written"]
            print(f"\nAñadidos a {w['path']}: {', '.join(w['written']) or 'ninguno'}"
                  + (f" · ya existían: {', '.join(w['skipped'])}" if w["skipped"] else ""))
            print("Actívalo con: vela profiles activate <nombre>")
        else:
            print(c("\nVista previa. Repite con --write para añadirlos a tu config.toml (no sobrescribe nada).", "90"))
        return None
    if a.action == "activate":
        r = b.call("profile_activate", name=a.name)
        print(f"perfil activo: {r['active']}")
        return None
    if a.action == "correlation":
        r = b.call("correlation")
        if a.json:
            return r
        for p in r["pairs"]:
            print(bold(" ↔ ".join(p["profiles"])) + f" riesgo {p['level']}")
            for risk in p["risks"]:
                print(f"  {c(risk['severity'], SEV_COLOR.get(risk['severity'], ''))} {risk['detail']}")
        if not r["pairs"]:
            print("no hay pares de perfiles con historial")
        print(c(r["note"], "90"))
        return None
    r = b.call("profiles")
    if a.json:
        return r
    for name, p in r["profiles"].items():
        mark = c("●", "32") if name == r["active"] else " "
        print(f"{mark} {bold(name)}: {p.get('description', '')} · Tor={'sí' if p.get('use_tor') else 'no'} · "
              f"países permitidos {p.get('allowed_countries') or 'todos'} · prohibidos {p.get('forbidden_countries') or 'ninguno'}")
    return None


def cmd_audit(b, a):
    r = b.call("audit")
    if a.html:
        data = b.call("export")
        Path(a.html).write_text(_html_from(data, r))
        print(f"informe HTML: {a.html}")
        return None
    if a.json:
        return r
    ex = r["summary"]["exposure"]
    print(bold(f"Auditoría de privacidad — perfil {r['profile']}") + f" · exposición {ex['score']}/100 ({ex['level']})")
    for i in ex["indicators"]:
        mark = c("●", "31") if i["present"] else (c("○", "90") if i["present"] is False else c("?", "36"))
        print(f"  {mark} {i['label']} (peso {i['weight']}) — {i['explanation']}")
    print(c(ex["disclaimer"], "90"))
    _print_findings(r["risks"])
    print(bold("\nPruebas realizadas"))
    for t in r["tests_performed"]:
        print(f"  [{t['mode']}] {t['check']}: {t['method']}")
    print(bold("\nLimitaciones de observabilidad"))
    for l in r["limitations"]:
        print(f"  · {l}")
    print(c(r["storage"]["note"], "90"))
    return None


def _html_from(data, audit):
    from .report import to_html

    class _E:  # to_html solo usa los datos ya exportados
        pass
    return to_html(_E(), data, audit)


def cmd_doctor(b, a):
    r = b.call("doctor")
    if a.json:
        return r
    for x in r:
        print(f"{c({'ok': '✔', 'warn': '⚠', 'fail': '✘'}[x['status']], STATUS_COLOR.get(x['status'], '33'))} "
              f"{x['check']:42} {x['detail']}" + (c(f"  → {x['fix']}", "90") if x["fix"] and x["status"] != "ok" else ""))


def cmd_stats(b, a):
    r = b.call("stats", period=a.period, profile=a.profile)
    if a.json:
        return r
    print(bold(f"Estadísticas ({a.period})") + f" · sesiones {r['sessions']} · exposición directa "
          f"{fmt_duration(r['direct_exposure_seconds'])}")
    print(bold("Tiempo por tecnología: ") + ", ".join(f"{k} {fmt_duration(v)}" for k, v in r["time_by_technology"].items()))
    for key, title in (("time_by_country", "País de salida"), ("time_by_tor_country", "País del exit de Tor")):
        if r[key]:
            print(bold(title))
            for x in r[key][:10]:
                print(f"  {x['label']:30} {fmt_duration(x['seconds'])}")
    rot = r["rotations"]
    print(bold("Rotaciones: ") + f"{rot['total']} ({rot['ok']} ok, {rot['failed']} fallidas), {rot['per_hour']}/h")
    print(bold("Fallos de conexión: ") + str(r["connection_failures"]))
    for layer, items in r["reuse"].items():
        if items:
            print(bold(f"Reutilización {layer}: ") + ", ".join(f"{i['label']}×{i['uses']}" for i in items[:8]))
    an = b.call("anomalies")
    if an:
        print(bold("Anomalías"))
        for x in an:
            print(f"  {c(x['severity'], SEV_COLOR.get(x['severity'], ''))} {x['detail']}")
    return None


def cmd_export(b, a):
    data = b.call("export", since=since_arg(a.since))
    out = Path(a.out)
    from .report import to_csv
    if a.format == "json":
        out.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))
        files = [out]
    elif a.format == "csv":
        out.mkdir(parents=True, exist_ok=True)
        files = []
        for key in ("sessions", "counters", "intervals", "events", "findings", "rotations"):
            p = out / f"{key}.csv"
            p.write_text(to_csv(data[key]))
            files.append(p)
    else:
        out.write_text(_html_from(data, b.call("audit")))
        files = [out]
    for f in files:
        os.chmod(f, 0o600)
    print("exportado: " + ", ".join(map(str, files)))


def cmd_killswitch(b, a):
    if a.action == "apply" and not a.yes:
        print("Esto bloqueará toda la salida salvo túneles, Tor, LAN y loopback. Repite con --yes para confirmar.")
        return None
    r = b.call("killswitch", action=a.action)
    if a.json or a.action != "preview":
        return r
    print(r["ruleset"])
    print(c(f"aplicable: {r['can_apply']} {r.get('reason_unavailable') or ''}", "90"))
    return None


def cmd_fix(b, a):
    plan = b.call("fixes")
    if a.json:
        return plan
    if not plan:
        print(c("Nada que corregir.", "32"))
        return None
    print(c("Comandos para revisar y ejecutar TÚ. VELA no ejecuta ninguno.", "90"))
    for i, fx in enumerate(plan, 1):
        sev = fx.get("severity", "info")
        print(f"\n{bold(str(i) + '. ' + fx['title'])}  {c(sev.upper(), SEV_COLOR.get(sev, ''))}"
              + (f"  ← {fx['finding']}" if fx.get("finding") else ""))
        if fx.get("why"):
            print(c(f"   {fx['why']}", "90"))
        for s in fx["steps"]:
            flags = (" [root]" if s["root"] else "") + (c(" [corta la conexión]", "33") if s["disruptive"] else "")
            print(f"   • {s['desc']}{flags}")
            if s.get("cmd"):
                print(f"       {c('$', '90')} {c(s['cmd'], '36')}")
        if fx.get("verify") and fx["verify"] != "—":
            print(c(f"   comprobar: {fx['verify']}", "90"))
    return None


def cmd_intel(b, a):
    from . import config as cm, intel
    if a.action == "keys":
        r = b.call("intel_keys")
        if a.json:
            return r
        for p, st in r["providers"].items():
            print(f"  {p:11} {c(st, '32' if not st.startswith('falta') else '33')}")
        print(c(f"\nClaves: variables de entorno (VT_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY, CENSYS_API_TOKEN o "
                f"CENSYS_API_ID/CENSYS_API_SECRET) o {r['secrets_file']} (0600).\n"
                f"Guardar una: vela intel set-key virustotal", "90"))
        print("consentimiento threat_intel_lookups: " + (c("activado", "32") if r["consent"] else c("desactivado", "33")))
        return None
    if a.action == "set-key":
        import getpass
        if not a.targets:
            print("uso: vela intel set-key <virustotal|shodan|greynoise|censys_token|censys_id|censys_secret|censys_org>")
            return None
        value = getpass.getpass(f"Valor para {a.targets[0]} (no se muestra): ").strip()
        if not value:
            print("vacío: no se guarda nada")
            return None
        print(f"guardada en {intel.save_key(a.targets[0], value)} (permisos 0600)")
        return None
    if a.action == "targets":
        r = b.call("intel_targets", since=since_arg(a.since), include_own=a.include_own)
        if a.json:
            return r
        table([[ip, ", ".join(v["roles"]), iso(v["first"]), iso(v["last"])] for ip, v in sorted(r["targets"].items())],
              ["IP", "papel", "primera vez", "última vez"])
        print(c(f"\n{len(r['targets'])} IPs · excluidas por ser tuyas: {', '.join(r['excluded']) or 'ninguna'}", "90"))
        return None
    if a.action == "show":
        rows = b.call("intel_results", ip=a.targets[0] if a.targets else None)
        if a.json:
            return rows
        _print_intel(rows)
        return None
    # scan: se ejecuta en este proceso para mostrar el progreso (comparte la base de datos con el daemon)
    cfg = cm.load()
    if not cfg["consent"].get("threat_intel_lookups"):
        print(c("Desactivado: añade a [consent] threat_intel_lookups = true (vela config edit).\n"
                "Ten en cuenta que cada servicio sabrá qué IPs consultas y desde qué IP.", "33"))
        return None
    st_net = b.call("status")["net"]
    if not cfg["intel"].get("via_tor") and not st_net["via_tunnel"].get("ipv4") and not cfg["intel"].get("allow_direct") \
            and not a.allow_direct:
        print(c("Sin VPN: las consultas saldrían desde tu IP real y la vincularían a estas IPs.\n"
                "Conecta la VPN, usa [intel] via_tor = true, o fuerza con --allow-direct.", "33"))
        return None
    ips = list(a.targets)
    if a.file:
        ips += intel.parse_ip_list(Path(a.file).read_text() if a.file != "-" else sys.stdin.read())
    hist = a.history or not ips
    tg = b.call("intel_targets", include_own=a.include_own) if hist else {"targets": {}, "excluded": [], "own": []}
    own = set() if a.include_own else set(tg.get("own", []))
    lst = list(dict.fromkeys([ip for ip in ips if intel.is_scannable(ip)] + list(tg["targets"])))
    skipped = [ip for ip in lst if ip in own or ip in set(cfg["intel"].get("exclude") or [])]
    lst = [ip for ip in lst if ip not in skipped]
    providers = a.providers.split(",") if a.providers else cfg["intel"]["providers"]
    st = intel.configured()
    print(bold(f"Escaneando {len(lst)} IPs") + " con " + ", ".join(f"{p} ({st[p]})" for p in providers)
          + (c(" · vía Tor", "35") if cfg["intel"].get("via_tor") else ""))
    if skipped:
        print(c(f"Excluidas (tuyas o en intel.exclude): {', '.join(skipped)} — usa --include-own para incluirlas", "90"))
    if "virustotal" in providers and not st["virustotal"].startswith("falta"):
        print(c(f"VirusTotal gratuito: 4 consultas/min → ~{len(lst) * 15 // 60} min (las cacheadas no cuentan)", "90"))
    from .store import Store
    store = Store(cfg["storage"]["path"] or None, memory=cfg["storage"]["mode"] == "memory")

    def progress(n, total, row):
        col = {"malicioso": "31", "expuesto": "31", "sospechoso": "33"}.get(row["verdict"], "32")
        print(f"  [{n}/{total}] {row['ip']:39} {c(row['verdict'], col)}  "
              + " ".join(f"{p}:{(r.get('verdict') or r['status'])}" for p, r in row["results"].items()), flush=True)
    res = intel.Scanner(store, cfg, progress=progress).scan(lst, providers, a.refresh, tg["targets"])
    store.close()
    print()
    scanned = {r["ip"] for r in res}
    roles = {r["ip"]: r.get("roles") for r in res}
    enriched = [{**r, "roles": roles.get(r["ip"])} for r in b.call("intel_results") if r["ip"] in scanned]
    _print_intel(enriched or res)
    return None


def _print_intel(rows):
    order = {"malicioso": 0, "expuesto": 1, "sospechoso": 2, "info": 3, "limpio": 4, "benigno": 4, "sin_datos": 5}
    for r in sorted(rows, key=lambda x: order.get(x["verdict"], 9)):
        col = {"malicioso": "31", "expuesto": "31", "sospechoso": "33"}.get(r["verdict"], "32")
        g = r.get("geo") or {}
        cc = g.get("country")
        flag = "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc.upper()) if cc and len(cc) == 2 and cc.isalpha() else "🌐"
        tv = (r.get("tor") or {}).get("verdict")
        tor_txt = {"exit": c(" [Tor exit]", "35"), "relay": c(" [Tor relay]", "35")}.get(tv, "")
        print(f"{bold(r['ip'])} {flag} {g.get('country_name') or '?'} · {r.get('org') or ''}{tor_txt} {c(r['verdict'].upper(), col)}"
              + (f"  ({', '.join(r['roles'])})" if r.get("roles") else ""))
        for p, x in r["results"].items():
            s = x.get("summary") or {}
            if x["status"] != "ok":
                print(c(f"    {p:10} {x['status']}", "90"))
                continue
            if p == "greynoise":
                d = f"clasificación {s.get('classification') or '-'}, ruido {s.get('noise')}, RIOT {s.get('riot')} {s.get('name') or ''}"
            elif p == "virustotal":
                d = (f"{s.get('malicious')} motores maliciosos, {s.get('suspicious')} sospechosos, reputación "
                     f"{s.get('reputation')} · {s.get('as_owner') or ''} {s.get('country') or ''} {' '.join(s.get('tags') or [])}")
            elif p == "shodan":
                d = (f"puertos {s.get('ports') or s.get('message') or '-'} · {s.get('org') or ''} "
                     + (c(f"CVEs: {', '.join(s['vulns'][:6])}", "31") if s.get("vulns") else "") + " " + " ".join(s.get("tags") or []))
            else:
                d = f"servicios {s.get('services') or '-'} · {s.get('as_name') or ''} {' '.join(s.get('labels') or [])}"
            print(f"    {p:10} {x['verdict'] or '-':10} {d}")
    print(c("\nNota: los exits de Tor y servidores VPN suelen figurar como maliciosos/scanners por el abuso de otros "
            "usuarios; no implica nada de tu tráfico, pero esa salida está en listas de bloqueo.", "90"))


def cmd_panic(b, a):
    return b.call("panic")


def cmd_resume(b, a):
    return b.call("resume")


def cmd_purge(b, a):
    if not a.yes:
        print(f"Esto borrará el histórico anterior a {a.days} días. Repite con --yes para confirmar.")
        return None
    return b.call("purge", days=a.days)


def cmd_config(b, a):
    from . import config as cm
    path = cm.config_path()
    if a.action == "path":
        print(path)
    elif a.action == "show":
        r = b.call("config_get")
        print(r["text"] or c(f"# {path} no existe: se usan los valores por defecto", "90"))
    elif a.action == "init":
        if path.exists() and not a.force:
            print(f"{path} ya existe (usa --force)")
            return None
        cm.save_text(EXAMPLE_CONFIG, path)
        print(f"creado {path}")
    elif a.action == "edit":
        import shlex
        import subprocess
        import tempfile
        text = path.read_text() if path.exists() else EXAMPLE_CONFIG
        with tempfile.NamedTemporaryFile("w+", suffix=".toml", delete=False) as f:
            f.write(text)
        os.chmod(f.name, 0o600)
        subprocess.call([*shlex.split(os.environ.get("EDITOR", "nano")), f.name])
        new = Path(f.name).read_text()
        os.unlink(f.name)
        r = b.call("config_set", text=new)
        print(f"guardado {r['saved']}; cambios: {', '.join(r['changed']) or 'ninguno'}")
    return None


def cmd_daemon(b, a):
    from . import daemon
    if a.action == "run":
        return sys.exit(daemon.run())
    if a.action == "start":
        return sys.exit(daemon.start_background())
    if a.action == "stop":
        return sys.exit(daemon.stop_daemon())
    if a.action in ("enable", "disable"):
        from . import autostart
        r = autostart.enable() if a.action == "enable" else autostart.disable()
        print(("arranque con la sesión activado" if a.action == "enable" else "arranque con la sesión desactivado")
              if r["ok"] else f"systemd: {r['error']}")
        return None
    from .ipc import ping
    print("velad: " + (c("en marcha", "32") if ping() else c("detenido", "90")))


def cmd_tui(b, a):
    from .tui import run
    run(b)


def cmd_app(b, a):
    try:
        from .native import app as native
    except (ImportError, ValueError) as e:
        print(c(f"GUI nativa no disponible ({e}). Necesita GTK 4 y libadwaita: "
                "sudo apt install gir1.2-adw-1 python3-gi. Alternativa: vela gui", "31"))
        return None
    if a.install:
        print(f"lanzador instalado en {native.install_desktop()} (búscalo como «VELA»)")
        return None
    native.run(b)
    return None


def cmd_tray(b, a):
    from . import autostart
    if a.install:
        print(f"icono de bandeja al iniciar sesión: {autostart.tray_enable()}")
        return None
    if a.remove:
        autostart.tray_disable()
        print("icono de bandeja desactivado")
        return None
    try:
        from . import tray
    except (ImportError, ValueError) as e:
        print(c(f"bandeja no disponible ({e}). Necesita gir1.2-ayatanaappindicator3-0.1 y la extensión AppIndicator.", "31"))
        return None
    sys.exit(tray.run())


def cmd_map(b, a):
    """Mapa base propio a partir de OpenStreetMap (se genera una vez y se dibuja sin conexión)."""
    from . import osmmap
    if a.action == "status":
        st = osmmap.status()
        if a.json:
            return st
        if not st["installed"]:
            print(f"Mapa OSM: no instalado ({st.get('error') or 'usa: vela map build'}). La app usa el contorno básico.")
            return None
        pts = ", ".join(f"z{k}: {v}" for k, v in (st.get("points") or {}).items())
        print(f"Mapa OSM en uso ({st['source']}): {st['path']} ({st['bytes'] / 1e6:.1f} MB · {st['places']} lugares · puntos {pts})")
        print(f"Generado {iso(st['created'])} · {st['attribution']} (ODbL)")
        return None
    from . import discovery
    land = Path(a.file).expanduser() if a.file else None
    env = discovery.discover()
    say = osmmap._cli_progress if a.progress else (lambda f, m: print(f"  [{f * 100:3.0f}%] {m}", flush=True))
    try:
        res = osmmap.download_and_build(a.via, env, land_file=land, places=not a.no_places, progress=say,
                                        refresh=a.refresh)
    except (OSError, ValueError) as e:
        if a.progress:
            print(f"error {e}", flush=True)
        else:
            print(c(f"error: {e}", "31"), file=sys.stderr)
        sys.exit(1)
    if a.json or a.progress:
        print("result " + json.dumps(res, ensure_ascii=False) if a.progress else json.dumps(res, ensure_ascii=False))
        return None
    print(c(f"Mapa generado: {res['path']} ({res['bytes'] / 1e6:.1f} MB, {res['places']} lugares, {res['seconds']} s)", "32"))
    if res.get("downloaded"):
        print(f"Descargado por {res['route']}: {', '.join(res['downloaded'])}")
    else:
        print("Sin descargas: datos reutilizados de la caché (~/.cache/vela/map). Para datos nuevos de OSM: "
              "vela map build --refresh")
    if res.get("places_error"):
        print(c(f"Sin nombres de lugares: {res['places_error']}", "33"))
    print("Reabre la app para verlo. Datos © OpenStreetMap contributors (ODbL).")
    return None


def cmd_gui(b, a):
    from .gui.server import serve
    serve(b, open_browser=not a.no_browser, port=a.port)


EXAMPLE_CONFIG = """# VELA — configuración (ver config.example.toml para todas las opciones)

[consent]
direct_ip_checks = false        # consultar tu IP pública por la ruta por defecto (expone tu IP al servicio)
proxy_ip_checks = false
tor_ip_checks = true            # comprobar la IP de salida a través de Tor (no expone tu IP)
active_dns_leak_test = false
allow_rotation_changes = false  # permitir que las rotaciones cambien conexiones reales
allow_killswitch = false        # permitir aplicar el kill-switch nftables (sudo/pkexec)

[rotation.tor]
enabled = false
max_ttl = "10m"
min_ttl = "2m"
jitter = "3m"
no_repeat = 10

[profiles.default]
description = "Perfil por defecto"
use_tor = false
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vela", description=f"VELA — Vigilant Egress & Leak Analyst. {TAGLINE}")
    p.add_argument("--version", action="version", version=f"vela {__version__}")
    p.add_argument("--json", action="store_true", help="salida JSON")
    p.add_argument("--local", action="store_true", help="no usar el daemon aunque esté en marcha")
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        sp.add_argument("--json", dest="json_sub", action="store_true", help="salida JSON")
        return sp

    add("status", cmd_status, "estado actual")
    sp = add("discover", cmd_discover, "descubrir capacidades del sistema")
    sp.add_argument("--write-config", metavar="RUTA")
    sp.add_argument("--force", action="store_true")
    add("network", cmd_network, "interfaces, direcciones y rutas")
    sp = add("map", cmd_map, "mapa base propio de OpenStreetMap: estado o generarlo (descarga única por Tor/VPN)")
    sp.add_argument("action", nargs="?", default="status", choices=["status", "build"])
    sp.add_argument("--via", default="auto", choices=["auto", "tor", "vpn", "direct"],
                    help="por dónde descargar (auto: Tor si hay, si no la VPN; nunca directo salvo que lo pidas)")
    sp.add_argument("--file", metavar="ZIP", help="usar un simplified-land-polygons-complete-3857.zip ya descargado")
    sp.add_argument("--no-places", action="store_true", help="sin nombres de países y ciudades (no consulta Overpass)")
    sp.add_argument("--refresh", action="store_true", help="volver a descargar los datos de OSM en vez de usar la caché")
    sp.add_argument("--progress", action="store_true", help=argparse.SUPPRESS)
    add("routes", cmd_routes, "cómo viaja tu tráfico: programa → directo/proxy/Tor → VPN → lo que ve el destino")
    sp = add("leakwatch", cmd_leakwatch, "IP pública y fugas de IP en tiempo real (conexiones fuera del túnel)")
    sp.add_argument("--once", action="store_true", help="una sola pasada")
    sp.add_argument("--all", action="store_true", help="mostrar también las conexiones protegidas")
    sp.add_argument("--interval", type=float, default=2.0)
    sp = add("networks", cmd_networks, "todas tus redes: WiFi, LAN, VPN, Docker, VMs, vecinos y tráfico")
    sp.add_argument("--neighbors", "-n", action="store_true", help="listar los dispositivos vistos en cada red")
    sp.add_argument("--all", action="store_true", help="incluir interfaces veth de contenedores")
    sp = add("vpn", cmd_vpn, "VPN detectadas")
    sp.add_argument("action", nargs="?", default="list", choices=["list"])
    sp = add("proxy", cmd_proxy, "proxies detectados")
    sp.add_argument("action", nargs="?", default="list", choices=["list"])
    sp = add("tor", cmd_tor, "estado de Tor / nuevo circuito")
    sp.add_argument("action", nargs="?", default="status", choices=["status", "newnym"])
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true")
    sp = add("dns", cmd_dns, "DNS por enlace y fugas")
    sp.add_argument("action", nargs="?", default="check", choices=["check"])
    sp.add_argument("--active", action="store_true", help="test activo (requiere consentimiento)")
    sp = add("ip", cmd_ip, "IP pública (con consentimiento) e IP WAN del router")
    sp.add_argument("--route", choices=["default", "tor"])
    sp = add("sessions", cmd_sessions, "sesiones de salida")
    sp.add_argument("--limit", type=int, default=30)
    sp.add_argument("--since")
    sp.add_argument("--profile")
    sp = add("counters", cmd_counters, "contadores de tiempo por IP/VPN/proxy/nodo/país…")
    sp.add_argument("--layer")
    sp.add_argument("--since")
    sp.add_argument("--profile")
    sp = add("history", cmd_history, "OPSEC timeline")
    sp.add_argument("--since", default="24h")
    sp.add_argument("--limit", type=int, default=200)
    sp.add_argument("--severity")
    add("watch", cmd_watch, "eventos en tiempo real (requiere daemon)")
    sp = add("rotate", cmd_rotate, "rotar una capa (tor/proxy/vpn) o ver el estado")
    sp.add_argument("layer", nargs="?", choices=["tor", "proxy", "vpn"])
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true", help="ignorar el tiempo mínimo de uso")
    sp = add("leaks", cmd_leaks, "pruebas de fugas")
    sp.add_argument("action", nargs="?", default="check", choices=["check"])
    sp.add_argument("--active", action="store_true")
    sp = add("profiles", cmd_profiles, "perfiles OPSEC")
    sp.add_argument("action", nargs="?", default="list", choices=["list", "activate", "correlation", "generate"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("--write", action="store_true", help="con generate: añadir al config.toml")
    sp = add("audit", cmd_audit, "Privacy Audit")
    sp.add_argument("--html", metavar="FICHERO")
    add("doctor", cmd_doctor, "diagnóstico de la instalación")
    sp = add("stats", cmd_stats, "estadísticas y anomalías")
    sp.add_argument("--period", default="week", choices=["day", "week", "month"])
    sp.add_argument("--profile")
    sp = add("export", cmd_export, "exportar histórico")
    sp.add_argument("--format", default="json", choices=["json", "csv", "html"])
    sp.add_argument("--out", required=True)
    sp.add_argument("--since")
    sp = add("killswitch", cmd_killswitch, "kill-switch nftables")
    sp.add_argument("action", nargs="?", default="status", choices=["status", "preview", "apply", "release"])
    sp.add_argument("--yes", action="store_true")
    add("fix", cmd_fix, "comandos concretos para corregir lo detectado (no ejecuta nada)")
    sp = add("intel", cmd_intel, "GreyNoise/VirusTotal/Shodan/Censys sobre las IPs de tu historial o un listado")
    sp.add_argument("action", nargs="?", default="show", choices=["scan", "show", "targets", "keys", "set-key"])
    sp.add_argument("targets", nargs="*", help="IPs (scan/show) o nombre de clave (set-key)")
    sp.add_argument("--file", help="fichero con un listado de IPs (cualquier formato; '-' = stdin)")
    sp.add_argument("--history", action="store_true", help="incluir todas las IPs del historial y actuales")
    sp.add_argument("--providers", help="lista separada por comas (greynoise,virustotal,shodan,censys)")
    sp.add_argument("--include-own", action="store_true", help="incluir tus IPs propias (WAN/IP directa)")
    sp.add_argument("--refresh", action="store_true", help="ignorar la caché")
    sp.add_argument("--allow-direct", action="store_true", help="permitir consultar sin VPN (expone tu IP real)")
    sp.add_argument("--since")
    add("panic", cmd_panic, "modo de emergencia (no borra datos)")
    add("resume", cmd_resume, "salir del modo de emergencia")
    sp = add("purge", cmd_purge, "borrar histórico antiguo")
    sp.add_argument("--days", type=float, required=True)
    sp.add_argument("--yes", action="store_true")
    sp = add("config", cmd_config, "configuración")
    sp.add_argument("action", nargs="?", default="show", choices=["show", "path", "init", "edit"])
    sp.add_argument("--force", action="store_true")
    sp = add("daemon", cmd_daemon, "gestionar velad")
    sp.add_argument("action", nargs="?", default="status", choices=["status", "start", "stop", "run", "enable", "disable"])
    add("tui", cmd_tui, "interfaz de terminal")
    sp = add("tray", cmd_tray, "icono en la bandeja del sistema con estado y controles")
    sp.add_argument("--install", action="store_true", help="mostrarlo al iniciar sesión y arrancarlo ahora")
    sp.add_argument("--remove", action="store_true", help="quitarlo del inicio de sesión y cerrarlo")
    sp = add("app", cmd_app, "aplicación nativa de escritorio (GTK 4 + libadwaita)")
    sp.add_argument("--install", action="store_true", help="instalar el lanzador en el menú de aplicaciones")
    sp = add("gui", cmd_gui, "interfaz gráfica (web local)")
    sp.add_argument("--no-browser", action="store_true")
    sp.add_argument("--port", type=int, default=0)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "fn", None):
        parser.print_help()
        return 0
    a.json = a.json or getattr(a, "json_sub", False)
    if not os.environ.get("VELA_NO_MIGRATE"):
        from . import migrate
        for msg in migrate.migrate():                 # una sola vez: datos del nombre anterior (opsectools)
            print(c(f"migración a VELA: {msg}", "36"), file=sys.stderr)
    if a.cmd == "daemon":
        cmd_daemon(None, a)
        return 0
    if a.cmd == "map":
        res = cmd_map(None, a)
        if res is not None:
            print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
        return 0
    if a.cmd == "tray":
        cmd_tray(None, a)
        return 0
    from .ipc import IPCError, LocalBackend, connect
    try:
        b = LocalBackend() if a.local else connect()
        res = a.fn(b, a)
    except IPCError as e:
        print(c(f"error: {e}", "31"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    if res is not None:
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
