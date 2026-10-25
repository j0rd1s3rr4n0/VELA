"""`vela`: interfaz de línea de comandos.

Habla con el daemon por IPC si está en marcha; si no, usa el mismo motor en proceso.
`--json` en cualquier comando devuelve los datos crudos para automatización.
"""

from __future__ import annotations

from .i18n import _

import argparse
import json
import os
import sys
from pathlib import Path

from . import TAGLINE, __version__
from .util import fmt_duration, iso, now, parse_duration, tilde

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
    print(bold(_("VELA · perfil «{profile}»", profile=s['profile'])) +
          (c("  [MODO EMERGENCIA]", "1;31") if s["emergency"] else "") +
          ("" if b.remote else c(_("  (motor local: arranca `vela daemon start` para monitorizar)"), "90")))
    ex = s["exposure"]
    print(_("Exposición observable: {v1}  (indicador orientativo, no mide anonimato)", v1=c(str(ex['score']) + '/100 ' + ex['level'], {'baja': '32', 'media': '33', 'alta': '31'}[ex['level']])))
    print(f"\n{bold(_('Cadena'))}: " + " → ".join(f"{h['type']}[{h.get('ip') or h.get('label')}]" for h in obs.get("chain", [])))
    print(_("  salida IPv4 por {v1} (gw {v3}), túnel: {v5}, IP local {local_ip}", v1=e4.get('dev'), v3=e4.get('gateway') or '-', v5='sí' if net['via_tunnel'].get('ipv4') else 'no', local_ip=net['local_ip']))
    wan = s["wan"] or {}
    print(_("  IP WAN router: {v1}", v1=wan.get('ip') if wan.get('ok') else c(wan.get('error', _('no comprobada')), '90')))
    for route, r in (s["public"] or {}).items():
        val = (_("{ip} ({v2}) vía {v4} {when}", ip=r['ip'], v2=(r.get('geo') or {}).get('country') or '?', v4=r.get('endpoint'), when=iso(r.get('ts')))
               if r.get("ok") else c(r.get("error"), "90"))
        print(_("  IP pública [{route}]: {val}", route=route, val=val))
    t = s["tor"] or {}
    if t.get("available"):
        ex_, gd = t.get("exit") or {}, t.get("guard") or {}
        print(f"\n{bold(_('Tor'))} {t.get('version')} ({t.get('target')}): bootstrap {t.get('bootstrap')}%, "
              f"{t.get('circuit_count')} circuitos, {t.get('stream_count')} streams"
              + (c(_("  [Tor Browser: solo observación]"), "33") if t.get("observe_only") else ""))
        print(f"  guard {gd.get('nick')} {gd.get('ip')} ({gd.get('country')}) · exit {ex_.get('nick')} "
              f"{ex_.get('ip')} ({ex_.get('country')}) · circuito {t.get('active_circuit')}")
    else:
        print(f"\n{bold(_('Tor'))}: {c(t.get('error') or _('no disponible'), '90')}")
    d = s["dns"] or {}
    enc = d.get("encryption") or {}
    print(_("\n{v1} efectivo ({v3}): ", v1=bold('DNS'), v3=d.get('effective_source')) +
          (", ".join(f"{r['addr']} {r['provider'] or '?'} [{r['transport']}]" for r in enc.get("resolvers", []))
           or ", ".join(d.get("effective_servers") or []) or "-") +
          f" · cifrado: {c({True: 'sí', False: 'NO', None: '?'}[d.get('encrypted')], {True: '32', False: '31', None: '90'}[d.get('encrypted')])}"
          + (_(" · DoH sale por {dev}", dev=enc['upstream_route']['dev']) if enc.get("upstream_route") else ""))
    kx = (s.get("killswitch") or {}).get("external") or {}
    rp = kx.get("route_protection") or {}
    if rp:
        state = lambda f: c(rp[f]["state"], "32" if rp[f]["state"] == "bloqueado" else "31")  # noqa: E731
        print(_("{v0}: {v2} · si cae el túnel: IPv4 {v4} ({detail}), IPv6 {v8}", v0=bold('Kill-switch'), v2=', '.join(kx.get('declared_by') or []) or 'ningún cliente', v4=state('ipv4'), detail=rp['ipv4']['detail'], v8=state('ipv6')))
    if s["session"]:
        print(f"\n{bold(_('Sesión'))} {s['session']['id']}: {fmt_duration(s['session']['duration'])} "
              f"(desde {iso(s['session']['started'])})")
    if s["live_counters"]:
        print(bold(_("Contadores en curso:")))
        for layer, cn in s["live_counters"].items():
            print(f"  {layer:18} {cn['label'][:40]:40} actual {fmt_duration(cn['current'])}  total {fmt_duration(cn['total'])}")
    rows = []
    for layer, r in s["rotation"].items():
        rows.append([layer, r["adapter"], "sí" if r["enabled"] else "no",
                     "sí" if r["available"] else c(r["reason"], "90"),
                     fmt_duration(r["remaining"]) if r["remaining"] is not None else "—",
                     f"{r['rotations_last_hour']}/{r['max_per_hour']}"])
    if rows:
        print(f"\n{bold(_('Rotación'))}")
        table(rows, ["capa", "adaptador", "activa", "disponible", _("próxima en"), _("última hora")])
    if s["findings"]:
        print(f"\n{bold(_('Alertas'))}")
        for f in s["findings"]:
            print(f"  {c(f['severity'].upper(), SEV_COLOR[f['severity']])} {f['title']} · {f['observed']}")
    return None


def cmd_discover(b, a):
    if a.write_config:
        from .discovery import discover, recommend, write_config
        _ign, cfg = recommend(discover())
        write_config(cfg, Path(a.write_config).expanduser(), a.force)
        print(_("configuración sugerida escrita en {write_config}", write_config=a.write_config))
    r = b.call("discover")
    if a.json:
        return r
    sysi = r["environment"]["system"]
    print(bold(f"{sysi['distro']} · kernel {sysi['kernel']} · {sysi['arch']}") +
          _(" · virtualización: {v1} · contenedor: {v3}{v4}", v1=sysi['virtualization'] or 'no', v3=sysi['container'] or 'no', v4=' · WSL' if sysi['wsl'] else ''))
    table([[cp["area"], cp["id"], c(cp["status"], STATUS_COLOR[cp["status"]]), cp["detail"]] for cp in r["capabilities"]],
          [_("área"), _("capacidad"), _("estado"), _("detalle")])
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
    print(f"\n{bold(_('Rutas por defecto'))}")
    for fam in ("ipv4_default", "ipv6_default"):
        for r in n["routes"][fam]:
            print(f"  {fam[:4]} via {r['gateway']} dev {r['dev']} metric {r['metric']} table {r['table']}")
    for fam in ("ipv4", "ipv6"):
        e = n["egress"].get(fam)
        print(_("  salida efectiva {fam}: ", fam=fam) + (f"{e['dev']} (src {e['src']}, gw {e['gateway']})" if e else _("sin ruta")))
    if n["policy_rules"]:
        print(f"{bold(_('Policy routing'))}: " + "; ".join(json.dumps(r) for r in n["policy_rules"]))
    print(_("túneles activos: {v1}", v1=', '.join(n['tunnels']) or 'ninguno'))


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
            detail.append(_("SSID {ssid} ({security}, señal {signal}%, canal {channel})", ssid=w['ssid'], security=w['security'], signal=w['signal'], channel=w['channel']))
        if i.get("connection"):
            detail.append(_("conexión «{connection}»", connection=i['connection']))
        if i["gateway"]:
            detail.append(f"gw {i['gateway']}" + (f" [{i['gateway_mac']} {i['gateway_vendor'] or ''}]".rstrip(" ]") + "]"
                                                    if i["gateway_mac"] else ""))
        rows.append([i["name"], i["category"], c("up", "32") if i["up"] else c("down", "90"),
                     ", ".join(i["subnets"]) or "—", f"↓{_bps(r.get('rx_bps'))} ↑{_bps(r.get('tx_bps'))}",
                     f"↓{_bytes(i['stats']['rx_bytes'])} ↑{_bytes(i['stats']['tx_bytes'])}", len(i["neighbors"]),
                     " · ".join(detail)])
    table(rows, ["interfaz", "red", "estado", "subred", _("tráfico ahora"), "total", "vecinos", "detalle"])
    if a.neighbors:
        for i in n["interfaces"]:
            if i["neighbors"] and (a.all or not i["name"].startswith("veth")):
                print(_("\n{v1} (tabla ARP/NDP del kernel; no se escanea la red)", v1=bold(_('Vecinos en ') + i['name'])))
                table([[x["ip"], x["mac"], x["vendor"] or "?", x["state"], "gateway" if x["ip"] == i["gateway"] else ""]
                       for x in sorted(i["neighbors"], key=lambda x: x["ip"])], ["IP", "MAC", "fabricante", "estado", ""])
    if n.get("libvirt") is not None:
        print(f"\n{bold(_('Redes de máquinas virtuales (libvirt)'))}")
        table([[v["name"], c("activa", "32") if v["active"] else c("inactiva", "90"), v["forward"], v["bridge"], v["ip"],
                c(_("¡NO AISLADA!"), "31") if v["isolation_broken"] else (_("aislada") if v["forward"] == "isolated" else "")]
               for v in n["libvirt"]], ["red", "estado", "forward", "bridge", "IP", "aislamiento"])
    if n.get("docker") is not None:
        print(f"\n{bold(_('Redes Docker'))}")
        table([[d["name"], d["driver"], d["bridge"] or "—", "interna" if d["internal"] else _("con salida")] for d in n["docker"]],
              ["red", "driver", "bridge", "salida"])
    print(f"\n{bold(_('Redes guardadas (NetworkManager)'))}")
    table([[s["name"], s["type"], iso(s["last_used"]) if s["last_used"] else "nunca", "sí" if s["autoconnect"] else "no"]
           for s in n["saved"]], [_("nombre"), _("tipo"), _("último uso"), _("autoconexión")])
    if n.get("known"):
        print(_("\n{v1} (huella: SSID + MAC del gateway)", v1=bold(_('Redes vistas por VELA'))))
        table([[k["label"], k["subnet"], k["gateway"], k["gateway_mac"], k["devices"], iso(k["first"]), iso(k["last"])]
               for k in n["known"]], ["red", "subred", "gateway", _("MAC gateway"), "dispositivos", _("primera vez"), _("última vez")])
    return None


VERDICT_COLOR = {"fuga": "1;31", "directa": "33", "protegida": "32", "permitida": "36", "otra": "90"}


def _leak_screen(r, show_all):
    pub = (r.get("public") or {}).get("default") or {}
    e4 = (r.get("egress") or {}).get("ipv4") or {}
    s = r["summary"]
    lines = [bold(_("VELA · IP y fugas en tiempo real")) + c(_("   {when}   (Ctrl-C para salir)", when=iso(r['ts'])), "90")]
    tun = c(_("túnel {v1}", v1=', '.join(r['tunnels'])), "32") if r["tunnel_up"] else c(_("SIN TÚNEL (VPN desconectada)"), "1;31")
    lines.append(f"Salida: {e4.get('dev')} · {tun}")
    if pub.get("ok"):
        tag = (c(_("  ← ¡TU IP REAL!"), "1;31") if pub.get("is_real_ip") and pub.get("via_tunnel") else
               c(_("  (IP de la VPN)"), "32") if pub.get("via_tunnel") else c(_("  (tu IP real)"), "33"))
        lines.append(_("IP pública: {v1} {v3} vía {v5} hace {v7} s{tag}", v1=bold(pub['ip']), v3=(pub.get('geo') or {}).get('country') or '', v5=pub.get('endpoint'), v7=int(r['ts'] - pub['ts']), tag=tag))
    else:
        lines.append(_("IP pública: {v1}", v1=c(pub.get('error') or 'pendiente', '90')))
    kx = r.get("killswitch") or {}
    rp = kx.get("route_protection") or {}
    if rp:
        lines.append(_("Kill-switch si cae el túnel: IPv4 {state}, IPv6 {state2}", state=rp['ipv4']['state'], state2=rp['ipv6']['state'])
                     + (f" ({', '.join(kx.get('declared_by') or [])})" if kx.get("declared_by") else ""))
    lines.append(_("Conexiones a Internet: {v1} · {v3} protegidas · {v5} · {v7} permitidas", v1=c(str(s.get('fugas', 0)) + ' fugas', VERDICT_COLOR['fuga'] if s.get('fugas') else '32'), v3=s.get('protegidas', 0), v5=c(str(s.get('directas', 0)) + ' directas', '33' if s.get('directas') else '90'), v7=s.get('permitidas', 0)))
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
    lines.append(c(_("VirusTotal automático: {v1} · cola {v3} · hoy {v5}/{v7}", v1=live.get('status', '—'), v3=live.get('queued', 0), v5=live.get('today', 0), v7=live.get('limit', '—')), "90"))
    if not r["tunnel_up"] and s.get("directas"):
        lines.append(c(_("\nSin VPN, todas estas conexiones muestran tu IP real. Para evitarlo: `vela fix`."), "33"))
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
    print(bold(_("Cómo viaja tu tráfico ahora")))
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
          [_("tecnología"), _("estado"), _("detalle")])
    print(_("túneles: {v1} · tráfico IPv4 por túnel: {v3} · adaptador de rotación: {v5}", v1=', '.join(v['tunnels']) or 'ninguno', v3='sí' if v['via_tunnel'].get('ipv4') else 'no', v5=v['adapter'] or 'ninguno'))


def cmd_proxy(b, a):
    p = b.call("proxy_list")
    if a.json:
        return p
    table([[f"127.0.0.1:{x['port']}", x["kind"], x.get("bind"), x.get("owner"),
            c("alcanzable", "32") if x["reachable"] else c(x["error"], "31")] for x in p["local"]],
          ["proxy", "protocolo", _("escucha en"), "proceso", "estado"])
    print(_("túneles ssh -D: {v1} · proxychains: {v3} · entorno: {v5} · escritorio: {v7}", v1=p['ssh_tunnels'] or 'ninguno', v3=(p['proxychains'] or {}).get('file', 'no'), v5=p['env'] or 'ninguno', v7=(p['desktop'] or {}).get('mode')))
    print(_("pool de rotación: {v1} · forwarder: {v3}", v1=p['pool'] or 'vacío (rotation.proxy.pool)', v3=(p['forwarder'] or {}).get('listen', _('no iniciado'))))


def cmd_tor(b, a):
    if a.action == "newnym":
        return cmd_rotate(b, argparse.Namespace(layer="tor", dry_run=a.dry_run, force=a.force, json=a.json))
    t = b.call("tor_status")
    if a.json:
        return t
    if not t.get("available"):
        print(c(_("Tor no disponible: {v1}", v1=t.get('error')), "31"))
        return None
    print(bold(_("Tor {version} vía {target}", version=t['version'], target=t['target'])) + _(" · bootstrap {bootstrap}% · circuitos {circuit_count} · streams {stream_count}", bootstrap=t['bootstrap'], circuit_count=t['circuit_count'], stream_count=t['stream_count']))
    for circ in t["circuits"]:
        mark = c("●", "32") if t.get("active") and circ["id"] == t["active"]["id"] else " "
        hops = " → ".join(f"{h.get('nick')}({h.get('country') or '?'})" for h in circ["path"])
        print(f" {mark} {circ['id']:>8}  streams {circ.get('streams', 0):<3} {hops}")
    if t.get("guards"):
        print(bold(_("Guards: ")) + ", ".join(f"{g['fp'][:8]}… {g['status']}" for g in t["guards"]))
    chk = t.get("tor_check") or {}
    if chk.get("ok"):
        print(_("Comprobación externa: {ip} IsTor={v3} ({endpoint}, {when})", ip=chk['ip'], v3=chk.get('is_tor'), endpoint=chk['endpoint'], when=iso(chk['ts'])))
    print(c(_("No se fuerzan cambios de guard. NEWNYM no garantiza un exit distinto."), "90"))


def cmd_dns(b, a):
    if getattr(a, "action", "check") in ("encrypt", "restore", "status"):
        return cmd_dns_fix(b, a)
    r = b.call("dns_check", active=a.active)
    if a.json:
        return r
    s = r["snapshot"]
    print(bold(_("DNS ({backend})", backend=s['backend'])) + f" · resolv.conf → {s['resolv_conf_target']} {s['resolv_conf']}"
          + (f" · modo {s['resolv_mode']}" if s.get("resolv_mode") else ""))
    enc = s.get("encryption") or {}
    print(bold(_("Resolver efectivo")) + f" ({s.get('effective_source')}):")
    for res in enc.get("resolvers", []):
        col = {True: "32", False: "31", None: "90"}[res["encrypted"]]
        print(f"  {res['addr']:14} {res['provider'] or 'desconocido':24} {c(res['transport'], col)}"
              + (f" → {res['upstream']}" if res.get("upstream") else "") + c(f"  ({res['evidence']})", "90"))
    if enc.get("upstream_route"):
        print(_("  conexión DoH hacia {ip} sale por {dev}", ip=enc['upstream_route']['ip'], dev=enc['upstream_route']['dev']))
    for br in enc.get("browsers", []):
        print(f"  navegador {br['browser']}: DoH {br['mode']} → {br['uri']}")
    print(bold(_("Configuración de systemd-resolved:")))
    rows = [[n, ", ".join(l["servers"]) or "—", ", ".join(l["domains"]) or "—", "sí" if l["default_route"] else "no",
             "sí" if l["dot"] else "no", l["dnssec"]] for n, l in s["links"].items() if l["servers"] or l["domains"]]
    if s.get("global", {}).get("servers"):
        rows.insert(0, ["Global", ", ".join(s["global"]["servers"]), "", "", "", ""])
    table(rows, ["enlace", "servidores", "dominios", _("ruta por defecto"), "DoT", "DNSSEC"])
    _print_findings(r["findings"])


def _print_findings(found):
    for f in found:
        print(f"\n{c(f['severity'].upper(), SEV_COLOR[f['severity']])} {c(f['status'], STATUS_COLOR[f['status']])} "
              f"{bold(f['title'])} [{f['mode']}]")
        print(_("  método: {method}\n  observado: {observed}\n  limitaciones: {limitations}\n  confianza: {confidence} · recomendación: {recommendation}", method=f['method'], observed=f['observed'], limitations=f['limitations'], confidence=f['confidence'], recommendation=f['recommendation']))


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
            print(_("[{route}] {v3} {v5} ({v7}) vía {endpoint} en {rtt_ms} ms", route=x['route'], v3=bold(x['ip']), v5=g.get('country_name') or '?', v7=g.get('source'), endpoint=x['endpoint'], rtt_ms=x['rtt_ms']) + (f" IsTor={x['is_tor']}" if "is_tor" in x else ""))
        else:
            print(f"[{x['route']}] {c(x['error'], '33')}")
    w = b.call("router")
    print(f"[router WAN] " + (f"{w['ip']} ({w.get('device')})" + (" CGNAT" if w.get("cgnat") else "") +
                              (_(" doble NAT") if w.get("double_nat") else "") if w.get("ok") else c(w.get("error"), "90")))


def cmd_sessions(b, a):
    rows = b.call("sessions", limit=a.limit, since=since_arg(a.since), profile=a.profile)
    if a.json:
        return rows
    table([[s["id"], iso(s["started"]), iso(s["ended"]) if s["ended"] else c("activa", "32"),
            fmt_duration(s["duration"]), s["profile"], s["egress_iface"], s["vpn"], s["proxy"],
            s["public_ip"], s["wan_ip"], (s["tor_exit"] or "")[:8] or None, s["end_reason"]] for s in rows],
          [_("id"), _("inicio"), _("fin"), _("duración"), _("perfil"), _("interfaz"), _("vpn"), _("proxy"), _("ip pública"), _("ip wan"),
           _("tor exit"), "cierre"])


def cmd_counters(b, a):
    rows = b.call("counters", layer=a.layer, since=since_arg(a.since), profile=a.profile)
    if a.json:
        return rows
    table([[r["layer"], r["label"][:46], r["country"], r["uses"], r["total_fmt"],
            c(r["current_fmt"], "32") if r["current_fmt"] else None, iso(r["last_seen"])] for r in rows],
          [_("capa"), _("elemento"), _("país"), _("usos"), _("tiempo total"), _("en curso"), _("último uso")])


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
    print(c(_("Escuchando eventos (Ctrl-C para salir)…"), "90"))
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
            print(_("{v0} {adapter}: activa={enabled} disponible={available} {v8} próxima en {v10}", v0=bold(layer), adapter=st['adapter'], enabled=st['enabled'], available=st['available'], v8=st['reason'] or '', v10=fmt_duration(st['remaining']) if st['remaining'] is not None else '—'))
        print(bold(_("\nÚltimas rotaciones")))
        table([[iso(x["ts"]), x["layer"], x["adapter"], "sí" if x["dry_run"] else "no", x["from_target"],
                x["to_target"], x["result"]] for x in r["history"][:15]],
              ["fecha", "capa", "adaptador", "dry-run", "desde", "hacia", "resultado"])
        return None
    r = b.call("rotate", layer=a.layer, dry_run=a.dry_run, force=a.force)
    if a.json:
        return r
    print(bold(_("Rotación {layer} ({v3}){v5}: ", layer=a.layer, v3=r.get('adapter', '-'), v5=' [dry-run]' if a.dry_run else '')) +
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
            tag = c(_(" (ya existe, no se toca)"), "90") if name in r["existing"] else ""
            print(bold(f"● {name}") + tag + f": {p['description']}")
            print(_("    Tor={v1} · VPN obligatoria={v3} · kill-switch={v5} · DNS={dns_policy} · países prohibidos={v9} · retención {retention_days} d", v1='sí' if p['use_tor'] else 'no', v3='sí' if p['require_vpn'] else 'no', v5='sí' if p['require_killswitch'] else 'no', dns_policy=p['dns_policy'], v9=p['forbidden_countries'] or 'ninguno', retention_days=p['retention_days']))
            for why in p["_why"]:
                print(c(f"      · {why}", "90"))
        if r.get("written"):
            w = r["written"]
            print(_("\nAñadidos a {path}: {v3}", path=w['path'], v3=', '.join(w['written']) or 'ninguno')
                  + (_(" · ya existían: {v1}", v1=', '.join(w['skipped'])) if w["skipped"] else ""))
            print(_("Actívalo con: vela profiles activate <nombre>"))
        else:
            print(c(_("\nVista previa. Repite con --write para añadirlos a tu config.toml (no sobrescribe nada)."), "90"))
        return None
    if a.action == "activate":
        r = b.call("profile_activate", name=a.name)
        print(_("perfil activo: {active}", active=r['active']))
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
            print(_("no hay pares de perfiles con historial"))
        print(c(r["note"], "90"))
        return None
    r = b.call("profiles")
    if a.json:
        return r
    for name, p in r["profiles"].items():
        mark = c("●", "32") if name == r["active"] else " "
        print(_("{mark} {v2}: {v4} · Tor={v6} · países permitidos {v8} · prohibidos {v10}", mark=mark, v2=bold(name), v4=p.get('description', ''), v6='sí' if p.get('use_tor') else 'no', v8=p.get('allowed_countries') or 'todos', v10=p.get('forbidden_countries') or 'ninguno'))
    return None


def cmd_audit(b, a):
    r = b.call("audit")
    if a.html:
        data = b.call("export")
        Path(a.html).write_text(_html_from(data, r))
        print(_("informe HTML: {html}", html=a.html))
        return None
    if a.json:
        return r
    ex = r["summary"]["exposure"]
    print(bold(_("Auditoría de privacidad · perfil {profile}", profile=r['profile'])) + _(" · exposición {score}/100 ({level})", score=ex['score'], level=ex['level']))
    for i in ex["indicators"]:
        mark = c("●", "31") if i["present"] else (c("○", "90") if i["present"] is False else c("?", "36"))
        print(f"  {mark} {i['label']} (peso {i['weight']}) · {i['explanation']}")
    print(c(ex["disclaimer"], "90"))
    _print_findings(r["risks"])
    print(bold(_("\nPruebas realizadas")))
    for t in r["tests_performed"]:
        print(f"  [{t['mode']}] {t['check']}: {t['method']}")
    print(bold(_("\nLimitaciones de observabilidad")))
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
    print(bold(_("Estadísticas ({period})", period=a.period)) + _(" · sesiones {sessions} · exposición directa {duration}", sessions=r['sessions'], duration=fmt_duration(r['direct_exposure_seconds'])))
    print(bold(_("Tiempo por tecnología: ")) + ", ".join(f"{k} {fmt_duration(v)}" for k, v in r["time_by_technology"].items()))
    for key, title in (("time_by_country", _("País de salida")), ("time_by_tor_country", _("País del exit de Tor"))):
        if r[key]:
            print(bold(title))
            for x in r[key][:10]:
                print(f"  {x['label']:30} {fmt_duration(x['seconds'])}")
    rot = r["rotations"]
    print(bold(_("Rotaciones: ")) + f"{rot['total']} ({rot['ok']} ok, {rot['failed']} fallidas), {rot['per_hour']}/h")
    print(bold(_("Fallos de conexión: ")) + str(r["connection_failures"]))
    for layer, items in r["reuse"].items():
        if items:
            print(bold(_("Reutilización {layer}: ", layer=layer)) + ", ".join(f"{i['label']}×{i['uses']}" for i in items[:8]))
    an = b.call("anomalies")
    if an:
        print(bold(_("Anomalías")))
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


def cmd_data(b, a):
    if a.action == "info":
        r = b.call("data_info")
        if a.json:
            return r
        print(bold(_("Datos de VELA")))
        for k in ("database", "config", "settings", "secrets"):
            print(f"  {k:10} {r[k]}")
        print("  " + ", ".join(f"{k}={v}" for k, v in r["rows"].items()))
        return None
    if a.action == "export":
        include = {"history": not a.no_history, "config": a.config, "settings": a.settings, "secrets": a.secrets}
        if not any(include.values()):
            print(_("no has elegido ninguna parte para exportar"))
            return None
        r = b.call("data_export", path=a.out, include=include)
        if a.json:
            return r
        print(_("backup escrito en {path} ({size} bytes)", path=r["path"], size=r["size"]))
        return None
    if a.action == "import":
        if not a.path:
            print(_("indica el fichero de backup: vela data import FICHERO"))
            return None
        include = {"history": not a.no_history, "config": a.config, "settings": a.settings, "secrets": a.secrets}
        r = b.call("data_import", path=a.path, mode=a.mode, include=include)
        if a.json:
            return r
        print(_("importado en modo {mode}", mode=r["mode"]))
        for n in r.get("notes") or []:
            print(_("  nota: {n}", n=n))
        if r.get("restart_required"):
            print(_("  reinicia velad y la app para aplicar la configuración importada"))
        return None
    if a.action == "reset":
        if not a.yes:
            print(_("Esto borra {scope}. Repite con --yes para confirmar.", scope=_("el historial") if a.scope == "history" else _("TODOS los datos de VELA")))
            return None
        r = b.call("data_reset", scope=a.scope, keep_backup=a.backup)
        if a.json:
            return r
        print(_("borrado: {scope}", scope=r["scope"]))
        if r.get("backup"):
            print(_("  copia previa en {path}", path=r["backup"]["path"]))
        if r.get("restart_required"):
            print(_("  reinicia velad y la app para volver a los valores por defecto"))
        return None
    return None


def cmd_deps(b, a):
    from . import deps
    if a.action == "check":
        r = deps.status(a.feature) if a.feature else deps.summary()
        if a.json:
            return r
        items = [r] if a.feature else r
        for x in items:
            print(f"{'OK ' if x['ok'] else 'FALTA'} {x['title']}"
                  + (f" · faltan: {', '.join(x['missing'])}" if x["missing"] else "")
                  + (f" · {x['note']}" if x.get("note") else ""))
        return None
    if a.action == "install":
        if not a.feature:
            print(_("indica qué función instalar: --feature ocr|mac|dns|llm|capture"))
            return None
        r = deps.install(a.feature, yes=a.yes)
        if a.json:
            return r
        if r.get("plan", {}).get("command"):
            print(_("comando: {cmd}", cmd=" ".join(r["plan"]["command"])))
        print(_("instalado") if r.get("ok") else _("no instalado: {e}", e=r.get("error")))
        return None
    if a.action == "ollama":
        r = deps.install_ollama(yes=a.yes)
        if a.json:
            return r
        print(_("Ollama listo con el modelo {model}", model=r.get("model")) if r.get("ok")
              else _("no se pudo instalar Ollama: {e}", e=r.get("error")))
        return None
    return None


def cmd_translate(b, a):
    from . import translate as tr
    text = a.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        print(_("texto vacío; pasa el texto como argumento o por stdin"))
        return None
    r = tr.translate(text, target=a.to, source=a.source)
    if a.json:
        return r
    print(r["text"])
    return None


def cmd_ocr(b, a):
    from . import ocr
    if a.image:
        res = ocr.ocr_image(a.image, a.langs.split(",") if a.langs else None)
        if a.no_translate:
            return res if a.json else (print(res["text"]), None)[1]
        from . import translate as tr
        out = {"ocr": res, "translation": tr.translate(res["text"], target=a.to, source=a.source)}
        if a.json:
            return out
        print(out["translation"]["text"])
        return None
    r = ocr.scan_and_translate(target=a.to, source=a.source,
                               languages=a.langs.split(",") if a.langs else None)
    if a.json:
        return r
    if r.get("ocr", {}).get("text") and not r.get("translation"):
        print(r["ocr"]["text"])
    if r.get("error"):
        print(_("error: {e}", e=r["error"]))
    elif r.get("translation"):
        print(r["translation"]["text"])
    return None


def cmd_tz(b, a):
    from . import applaunch
    if a.action == "list":
        r = {"apps": applaunch.apps(a.query), "timezones": applaunch.timezones()}
        if a.json:
            return r
        print(bold(_("Aplicaciones ({n})", n=len(r["apps"]))))
        for app in r["apps"][:80]:
            print(f"  {app['name']:42} {app['id']}")
        print(bold(_("\nZonas horarias: {n} (ej. Europe/Madrid, UTC)", n=len(r["timezones"]))))
        return None
    if a.command:
        r = applaunch.launch_command(a.command, a.tz, dry_run=a.dry_run)
    elif a.app:
        r = applaunch.launch(a.app, a.tz, dry_run=a.dry_run)
    else:
        print(_("indica --app NOMBRE o --command «comando»"))
        return None
    if a.json:
        return r
    if r.get("dry_run"):
        print(_("plan: {cmd}", cmd=" ".join(r["command"])) + _(" · TZ={tz}", tz=a.tz))
    else:
        print(_("lanzado con TZ={tz}: {cmd}", tz=a.tz, cmd=" ".join(r["command"])))
    if r.get("warning"):
        print(_("  aviso: {w}", w=r["warning"]))
    return None


def cmd_mac(b, a):
    from . import mac
    if a.action == "list":
        r = mac.interfaces()
        if a.json:
            return r
        table([[i["name"], i["mac"], i["permanent"] or "—", i["kind"], i["state"], i["driver"] or "—"]
               for i in r], ["interfaz", "MAC", _("permanente"), _("tipo"), _("estado"), "driver"])
        return None
    if a.action in ("set", "random", "restore") and not a.iface:
        print(_("indica la interfaz con --iface (vela mac list)"))
        return None
    if a.action == "set":
        if not a.mac:
            print(_("indica la MAC con --mac o usa la acción random"))
            return None
        r = mac.set_mac(a.iface, mac=a.mac, apply=a.yes, engine=getattr(b, "engine", None))
    elif a.action == "random":
        r = mac.set_mac(a.iface, use_random=True, apply=a.yes, engine=getattr(b, "engine", None))
    elif a.action == "restore":
        r = mac.restore(a.iface, apply=a.yes, engine=getattr(b, "engine", None))
    else:
        return None
    if a.yes and not r.get("dry_run"):
        _refresh_backend(b, ["network", "networks", "leaks"])
    if a.json:
        return r
    if r.get("dry_run"):
        print(_("plan: {cmd}", cmd=" ".join(" ".join(c) for c in r["plan"]["commands"])))
        print(_("repite con --yes para aplicarlo"))
    else:
        print(_("MAC de {iface}: {mac}", iface=r.get("iface"), mac=r.get("actual") or r.get("mac"))
              if r.get("ok") else _("error: {e}", e=r.get("error")))
    return None


def cmd_notify(b, a):
    from . import notifications
    if a.action == "on":
        st = notifications.enable()
    elif a.action == "off":
        st = notifications.disable()
    elif a.action == "mute":
        seconds = parse_duration(a.for_) if a.for_ else None
        st = notifications.mute(seconds)
    else:
        st = notifications.status()
    if a.json:
        return st
    print(_("Notificaciones: {v1}", v1=notifications.describe(st)))
    if st.get("path"):
        print(_("  estado: {v1}", v1=tilde(st["path"])))
    return None


def cmd_logs(b, a):
    if a.action == "clear":
        r = b.call("logs_clear", kind=a.kind)
        if a.json:
            return r
        print(_("registro borrado: {v1}", v1=", ".join(r.get("cleared") or [])))
        return None
    r = b.call("logs", kind=a.kind, limit=a.limit)
    if a.json:
        return r
    if a.kind in ("all", "errors"):
        print(bold(_("Errores ({n})", n=len(r.get("errors") or []))))
        for e in r.get("errors") or []:
            detail = e.get("exception") or e.get("message") or ""
            print(f"  {iso(e.get('ts')) if e.get('ts') else '—'} {str(e.get('level') or 'error'):8} {detail}")
        print(bold(_("Errores: {v1}", v1=r.get("paths", {}).get("errors"))))
    if a.kind in ("all", "audit"):
        print(bold(_("Auditoría ({n})", n=len(r.get("audit") or []))))
        for x in r.get("audit") or []:
            print(f"  {iso(x.get('ts')) if x.get('ts') else '—'} {str(x.get('actor') or '-'):10} "
                  f"{str(x.get('action') or ''):24} {json.dumps(x.get('detail'), ensure_ascii=False, default=str)[:160]}")
        print(bold(_("Auditoría: {v1}", v1=r.get("paths", {}).get("audit"))))
    return None


def cmd_refresh(b, a):
    """Invalida caches y recalcula alertas/recomendaciones ahora."""
    r = b.call("refresh", domains=a.domains or None)
    if a.json:
        return r
    st = r.get("status") or {}
    print(_("estado actualizado · revisión {n} · {alerts} alertas",
            n=r.get("revision", "?"), alerts=len(st.get("findings") or [])))
    for f in st.get("findings") or []:
        print(f"  {c(f['severity'].upper(), SEV_COLOR.get(f['severity'], '37'))} {f['title']} · {f['observed']}")
    return None


def cmd_anomalies(b, a):
    r = b.call("anomalies")
    if a.json:
        return r
    if not r:
        print(_("Sin anomalías en la ventana analizada."))
        return None
    for x in r:
        print(f"  {c(x['severity'].upper(), SEV_COLOR.get(x['severity'], '37'))} {x['type']}: {x['detail']}")
    return None


def cmd_about(b, a):
    from . import about
    info = about.app_info()
    prof = about.profile(refresh=a.sync)
    r = {"app": info, "profile": prof}
    if a.json:
        return r
    print(bold(f"{info['name']} {info['version']}") + f" · {info['acronym']}\n{_(info['tagline'])}")
    print(_("\nCreador: {name} (@{login})", name=prof.get("name"), login=prof.get("login")))
    print(f"  GitHub: {prof.get('github')}\n  Web: {prof.get('blog')}\n  {prof.get('bio')}")
    if prof.get("error"):
        print(c(_("  perfil no sincronizado: {e}", e=prof["error"]), "90"))
    print("\n" + bold(_("Créditos")))
    for x in info["credits"]:
        print(f"  · {x}")
    return None


def _refresh_backend(b, domains):
    """Pide al motor que invalide y recalcule; no rompe la CLI si el backend es antiguo."""
    try:
        return b.call("refresh", domains=domains)
    except Exception:  # noqa: BLE001
        return None


def cmd_dns_fix(b, a):
    from . import dnsfix
    if a.action == "encrypt":
        if not getattr(a, "yes", False):
            p = dnsfix.plan(a.transport, a.provider)
            print(_("plan: {cmds}", cmds="; ".join(p["commands"])))
            print(_("repite con --yes para aplicar; requiere [consent] allow_dns_changes = true"))
            return p if a.json else None
        r = dnsfix.apply(a.transport, a.provider, cfg=None, engine=getattr(b, "engine", None))
        _refresh_backend(b, ["dns", "leaks"])
    elif a.action == "restore":
        r = dnsfix.restore(engine=getattr(b, "engine", None))
        _refresh_backend(b, ["dns", "leaks"])
    else:
        r = dnsfix.status()
    if a.json:
        return r
    if a.action == "encrypt":
        print(_("DNS cifrado con {transport}/{provider}: {ok}", transport=a.transport, provider=a.provider,
                ok=_("sí") if r.get("ok") else _("no")))
        if r.get("error"):
            print(c("  " + r["error"], "31"))
        if r.get("backup"):
            print(_("  backup: {backup}", backup=r["backup"]))
    elif a.action == "restore":
        print(_("DNS restaurado: {ok}", ok=_("sí") if r.get("ok") else _("no")))
    else:
        print(_("DNS cifrado: {state}", state={True: _("sí"), False: _("no"), None: "?"}[r.get("encrypted")]))
        for x in r.get("resolvers") or []:
            print(f"  {x['addr']:14} {x['provider'] or '?'} [{x['transport']}]")
    return None


def cmd_killswitch(b, a):
    if a.action == "apply" and not a.yes:
        print(_("Esto bloqueará toda la salida salvo túneles, Tor, LAN y loopback. Repite con --yes para confirmar."))
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
        print(c(_("Nada que corregir."), "32"))
        return None
    print(c(_("Comandos para revisar y ejecutar TÚ. VELA no ejecuta ninguno."), "90"))
    for i, fx in enumerate(plan, 1):
        sev = fx.get("severity", "info")
        print(f"\n{bold(str(i) + '. ' + fx['title'])}  {c(sev.upper(), SEV_COLOR.get(sev, ''))}"
              + (f"  ← {fx['finding']}" if fx.get("finding") else ""))
        if fx.get("why"):
            print(c(f"   {fx['why']}", "90"))
        for s in fx["steps"]:
            flags = (_(" [root]") if s["root"] else "") + (c(_(" [corta la conexión]"), "33") if s["disruptive"] else "")
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
        print(c(_("\nClaves: variables de entorno (VT_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY, CENSYS_API_TOKEN o CENSYS_API_ID/CENSYS_API_SECRET) o {secrets_file} (0600).\nGuardar una: vela intel set-key virustotal", secrets_file=r['secrets_file']), "90"))
        print(_("consentimiento threat_intel_lookups: ") + (c("activado", "32") if r["consent"] else c("desactivado", "33")))
        return None
    if a.action == "set-key":
        import getpass
        if not a.targets:
            print(_("uso: vela intel set-key <virustotal|shodan|greynoise|censys_token|censys_id|censys_secret|censys_org>"))
            return None
        value = getpass.getpass(_("Valor para {v1} (no se muestra): ", v1=a.targets[0])).strip()
        if not value:
            print(_("vacío: no se guarda nada"))
            return None
        print(_("guardada en {v1} (permisos 0600)", v1=intel.save_key(a.targets[0], value)))
        return None
    if a.action == "targets":
        r = b.call("intel_targets", since=since_arg(a.since), include_own=a.include_own)
        if a.json:
            return r
        table([[ip, ", ".join(v["roles"]), iso(v["first"]), iso(v["last"])] for ip, v in sorted(r["targets"].items())],
              ["IP", "papel", _("primera vez"), _("última vez")])
        print(c(_("\n{n} IPs · excluidas por ser tuyas: {v3}", n=len(r['targets']), v3=', '.join(r['excluded']) or 'ninguna'), "90"))
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
        print(c(_("Desactivado: añade a [consent] threat_intel_lookups = true (vela config edit).\n"
                "Ten en cuenta que cada servicio sabrá qué IPs consultas y desde qué IP."), "33"))
        return None
    st_net = b.call("status")["net"]
    if not cfg["intel"].get("via_tor") and not st_net["via_tunnel"].get("ipv4") and not cfg["intel"].get("allow_direct") \
            and not a.allow_direct:
        print(c(_("Sin VPN: las consultas saldrían desde tu IP real y la vincularían a estas IPs.\n"
                "Conecta la VPN, usa [intel] via_tor = true, o fuerza con --allow-direct."), "33"))
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
          + (c(_(" · vía Tor"), "35") if cfg["intel"].get("via_tor") else ""))
    if skipped:
        print(c(_("Excluidas (tuyas o en intel.exclude): {v1} · usa --include-own para incluirlas", v1=', '.join(skipped)), "90"))
    if "virustotal" in providers and not st["virustotal"].startswith("falta"):
        print(c(_("VirusTotal gratuito: 4 consultas/min → ~{v1} min (las cacheadas no cuentan)", v1=len(lst) * 15 // 60), "90"))
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
                d = _("clasificación {v1}, ruido {v3}, RIOT {v5} {v7}", v1=s.get('classification') or '-', v3=s.get('noise'), v5=s.get('riot'), v7=s.get('name') or '')
            elif p == "virustotal":
                d = (_("{v0} motores maliciosos, {v2} sospechosos, reputación {v4} · {v6} {v8} {v10}", v0=s.get('malicious'), v2=s.get('suspicious'), v4=s.get('reputation'), v6=s.get('as_owner') or '', v8=s.get('country') or '', v10=' '.join(s.get('tags') or [])))
            elif p == "shodan":
                d = (f"puertos {s.get('ports') or s.get('message') or '-'} · {s.get('org') or ''} "
                     + (c(f"CVEs: {', '.join(s['vulns'][:6])}", "31") if s.get("vulns") else "") + " " + " ".join(s.get("tags") or []))
            else:
                d = f"servicios {s.get('services') or '-'} · {s.get('as_name') or ''} {' '.join(s.get('labels') or [])}"
            print(f"    {p:10} {x['verdict'] or '-':10} {d}")
    print(c(_("\nNota: los exits de Tor y servidores VPN suelen figurar como maliciosos/scanners por el abuso de otros "
            "usuarios; no implica nada de tu tráfico, pero esa salida está en listas de bloqueo."), "90"))


def cmd_panic(b, a):
    return b.call("panic")


def cmd_resume(b, a):
    return b.call("resume")


def cmd_purge(b, a):
    if not a.yes:
        print(_("Esto borrará el histórico anterior a {days} días. Repite con --yes para confirmar.", days=a.days))
        return None
    return b.call("purge", days=a.days)


def cmd_config(b, a):
    from . import config as cm
    path = cm.config_path()
    if a.action == "path":
        print(path)
    elif a.action == "show":
        r = b.call("config_get")
        print(r["text"] or c(_("# {path} no existe: se usan los valores por defecto", path=path), "90"))
    elif a.action == "init":
        if path.exists() and not a.force:
            print(_("{path} ya existe (usa --force)", path=path))
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
        print((_("arranque con la sesión activado") if a.action == "enable" else _("arranque con la sesión desactivado"))
              if r["ok"] else f"systemd: {r['error']}")
        return None
    from .ipc import ping
    print(_("velad: ") + (c(_("en marcha"), "32") if ping() else c(_("detenido"), "90")))


def cmd_tui(b, a):
    from .tui import run
    run(b)


def cmd_app(b, a):
    try:
        from .native import app as native
    except (ImportError, ValueError) as e:
        print(c(_("GUI nativa no disponible ({e}). Necesita GTK 4 y libadwaita: sudo apt install gir1.2-adw-1 python3-gi. Alternativa: vela gui", e=e), "31"))
        return None
    if a.install:
        print(_("lanzador instalado en {v1} (búscalo como «VELA»)", v1=native.install_desktop()))
        return None
    native.run(b, uninstall=getattr(a, "uninstall", False), quit_=getattr(a, "quit", False))
    return None


def cmd_tray(b, a):
    from . import autostart
    if a.install:
        print(_("icono de bandeja al iniciar sesión: {v1}", v1=autostart.tray_enable()))
        return None
    if a.remove:
        autostart.tray_disable()
        print(_("icono de bandeja desactivado"))
        return None
    try:
        from . import tray
    except (ImportError, ValueError) as e:
        print(c(_("bandeja no disponible ({e}). Necesita gir1.2-ayatanaappindicator3-0.1 y la extensión AppIndicator.", e=e), "31"))
        return None
    sys.exit(tray.run())


def cmd_uninstall(b, a):
    """Desinstalación fácil: no necesita el repositorio; enseña la lista y pide confirmación."""
    from . import uninstall
    p = uninstall.plan(a.purge)
    if a.json and a.dry_run:
        print(json.dumps({k: [str(x) if not isinstance(x, tuple) else [str(x[0]), x[1]] for x in v]
                          if isinstance(v, list) else v for k, v in p.items()}, indent=2, ensure_ascii=False))
        return 0
    for line in uninstall.describe(p):
        print(line)
    if not (p["files"] or p["dirs"] or p["data"]):
        print(c(_("No hay nada de VELA instalado para este usuario."), "32"))
        return 0
    if a.dry_run:
        print(_("(simulación: no se ha cambiado nada)"))
        return 0
    if not a.yes:
        if not sys.stdin.isatty():
            print(c(_("sin terminal para confirmar: usa --yes"), "31"), file=sys.stderr)
            return 1
        q = _("¿Desinstalar VELA y BORRAR tus datos? [s/N] ") if a.purge else _("¿Desinstalar VELA? [s/N] ")
        if input(q).strip().lower() not in ("s", "si", "sí", "y", "yes", "o", "oui", "j", "ja"):
            print(_("Cancelado: no se ha cambiado nada."))
            return 0
    res = uninstall.run(a.purge, progress=lambda m: print(f"  · {m}", flush=True))
    for e in res["errors"]:
        print(c(f"⚠ {e}", "33"), file=sys.stderr)
    print(c(_("VELA desinstalado."), "32"))
    if not a.purge and any(d.exists() for d in uninstall.data_dirs()):
        print(_("Tus datos se conservan por si reinstalas; para borrarlos: rm -rf {dirs}",
                dirs=" ".join(tilde(d) for d in uninstall.data_dirs() if d.exists())))
    return 0 if not res["errors"] else 1


def cmd_update(b, a):
    """Actualizar VELA desde su clon git: solo bajo petición, por Tor/VPN y solo avanzando (fast-forward)."""
    from . import updater
    as_json = a.json or getattr(a, "json_sub", False)

    def out(obj, code=0):
        if a.progress:
            print("result " + json.dumps(obj, ensure_ascii=False, default=str), flush=True)
        elif as_json:
            print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))
        return code

    def fail(e):
        if a.progress:
            print(f"error {e}", flush=True)
        else:
            print(c(f"error: {e}", "31"), file=sys.stderr)
        return 1
    if a.status:
        st = updater.status()
        if as_json or a.progress:
            return out(st)
        print(_("VELA {v} instalado{c} · origen: {src}", v=st["installed_version"],
                c=f" ({st['installed_commit'][:7]})" if st.get("installed_commit") else "",
                src=tilde(st["source"]) if st.get("source") else "—"))
        if st.get("hint"):
            print(c(st["hint"], "33"))
        elif st.get("pending_install"):
            print(c(_("El clon tiene cambios ya descargados sin instalar: vela update"), "33"))
        return 0
    try:
        res = updater.check(a.via)
    except (updater.UpdateError, OSError, ValueError) as e:
        return fail(e)
    if a.check or not res["available"]:
        if as_json or a.progress:
            return out(res)
        if not res["available"]:
            print(c(_("Ya tienes la última versión ({v}, {cm}). Consultado por {route}.", v=res["installed_version"],
                      cm=res["source_commit"][:7], route=res["route"]), "32"))
            return 0
        _print_update(res)
        return 0
    if not a.progress and not as_json:
        _print_update(res)
        if not a.protect:
            if a.yes:
                a.protect = "restart"
            elif not sys.stdin.isatty():
                return fail(_("sin terminal para confirmar: usa --yes o --protect"))
            else:
                a.protect = _ask_protect()
                if a.protect == "cancel":
                    print(_("Cancelado: no se ha cambiado nada."))
                    return 0
    say = (lambda f, m: print(f"progress {f:.2f} {m}", flush=True)) if a.progress else \
        (lambda f, m: None if as_json else print(f"  [{f * 100:3.0f}%] {m}", flush=True))
    try:
        res = updater.apply(a.via, progress=say, protect=a.protect or "restart")
    except (updater.UpdateError, OSError, ValueError) as e:
        return fail(e)
    if as_json or a.progress:
        return out(res)
    print(c(res["message"], "32"))
    if res.get("updated"):
        print(_("Volver atrás: {cmd}", cmd=res["rollback"]))
    return 0


def _ask_protect() -> str:
    """Lo descargado ya está; antes de parar VELA para cambiar de versión, cómo protegerse mientras está parado."""
    from . import updater
    opts = updater.protection_options()
    print()
    print(_("Mientras se cambia de versión VELA no vigila tus conexiones. ¿Cómo quieres hacerlo?"))
    ks = _("Con kill-switch hasta que arranque la versión nueva (recomendado; solo VPN, Tor y LAN)")
    if not opts.get("killswitch"):
        ks += " · " + _("no disponible: {why}", why=opts.get("killswitch_reason") or "—")
    print(f"  1) {ks}")
    print("  2) " + _("Cerrar y volver a abrir sin protección (posible fuga de IP unos segundos)"))
    print("  3) " + _("Ahora no"))
    r = input("> ").strip()
    if r == "1" and opts.get("killswitch"):
        return "killswitch"
    return {"2": "restart"}.get(r, "cancel")


def _print_update(res):
    if res["behind"]:
        print(c(_("Hay {n} cambios nuevos en {u}{v} (consultado por {route}):", n=res["behind"], u=res["upstream"],
                  v=f" · versión {res['new_version']}" if res.get("new_version") else "", route=res["route"]), "36"))
        for cm in res["commits"][:20]:
            print(f"  {cm['id']}  {cm['date']}  {cm['subject']}")
        if len(res["commits"]) > 20:
            print(_("  … y {n} más", n=len(res["commits"]) - 20))
    elif res.get("pending_install"):
        print(c(_("El clon ya tiene una versión más nueva que la instalada: se reinstalará."), "36"))
    if res["dirty"]:
        print(c(_("Tienes cambios sin guardar en {src}: no se puede actualizar hasta guardarlos o descartarlos.",
                  src=tilde(res["source"])), "33"))
    if res["ahead"]:
        print(c(_("Tu rama tiene {n} commits propios que no están en {u}: resuélvelo con git antes de actualizar.",
                  n=res["ahead"], u=res["upstream"]), "33"))


def cmd_map(b, a):
    """Mapa base propio a partir de OpenStreetMap (se genera una vez y se dibuja sin conexión)."""
    from . import osmmap
    if a.action == "status":
        st = osmmap.status()
        if a.json:
            return st
        if not st["installed"]:
            print(_("Mapa OSM: no instalado ({v1}). La app usa el contorno básico.", v1=st.get('error') or 'usa: vela map build'))
            return None
        pts = ", ".join(f"z{k}: {v}" for k, v in (st.get("points") or {}).items())
        print(_("Mapa OSM en uso ({source}): {path} ({v5:.1f} MB · {places} lugares · puntos {pts})", source=st['source'], path=st['path'], v5=st['bytes'] / 1e6, places=st['places'], pts=pts))
        print(_("Generado {when} · {attribution} (ODbL)", when=iso(st['created']), attribution=st['attribution']))
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
    print(c(_("Mapa generado: {path} ({v3:.1f} MB, {places} lugares, {seconds} s)", path=res['path'], v3=res['bytes'] / 1e6, places=res['places'], seconds=res['seconds']), "32"))
    if res.get("downloaded"):
        print(_("Descargado por {route}: {v3}", route=res['route'], v3=', '.join(res['downloaded'])))
    else:
        print(_("Sin descargas: datos reutilizados de la caché (~/.cache/vela/map). Para datos nuevos de OSM: "
              "vela map build --refresh"))
    if res.get("places_error"):
        print(c(_("Sin nombres de lugares: {places_error}", places_error=res['places_error']), "33"))
    print(_("Reabre la app para verlo. Datos © OpenStreetMap contributors (ODbL)."))
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
    p = argparse.ArgumentParser(prog="vela", description=_("VELA · Vigilant Egress & Leak Analyst. {TAGLINE}", TAGLINE=_(TAGLINE)))
    p.add_argument("--version", action="version", version=f"vela {__version__}")
    p.add_argument("--json", action="store_true", help=_("salida JSON"))
    p.add_argument("--lang", choices=["es", "en", "ca", "pt", "fr", "de"],
                   help=_("idioma de la interfaz (por defecto el del sistema o el elegido en Ajustes)"))
    p.add_argument("--local", action="store_true", help=_("no usar el daemon aunque esté en marcha"))
    sub = p.add_subparsers(dest="cmd")

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(fn=fn)
        sp.add_argument("--json", dest="json_sub", action="store_true", help=_("salida JSON"))
        return sp

    add("status", cmd_status, _("estado actual"))
    sp = add("discover", cmd_discover, _("descubrir capacidades del sistema"))
    sp.add_argument("--write-config", metavar="RUTA")
    sp.add_argument("--force", action="store_true")
    add("network", cmd_network, _("interfaces, direcciones y rutas"))
    sp = add("map", cmd_map, _("mapa base propio de OpenStreetMap: estado o generarlo (descarga única por Tor/VPN)"))
    sp.add_argument("action", nargs="?", default="status", choices=["status", "build"])
    sp.add_argument("--via", default="auto", choices=["auto", "tor", "vpn", "direct"],
                    help=_("por dónde descargar (auto: Tor si hay, si no la VPN; nunca directo salvo que lo pidas)"))
    sp.add_argument("--file", metavar="ZIP", help=_("usar un simplified-land-polygons-complete-3857.zip ya descargado"))
    sp.add_argument("--no-places", action="store_true", help=_("sin nombres de países y ciudades (no consulta Overpass)"))
    sp.add_argument("--refresh", action="store_true", help=_("volver a descargar los datos de OSM en vez de usar la caché"))
    sp.add_argument("--progress", action="store_true", help=argparse.SUPPRESS)
    sp = add("update", cmd_update, _("buscar e instalar actualizaciones de VELA desde su repositorio git (por Tor/VPN)"))
    sp.add_argument("--check", action="store_true", help=_("solo buscar: no cambia nada"))
    sp.add_argument("--status", action="store_true", help=_("versión instalada y estado del clon, sin conexión"))
    sp.add_argument("--via", default="auto", choices=["auto", "tor", "vpn", "direct"],
                    help=_("por dónde contactar con el servidor git (auto: Tor si hay, si no la VPN; nunca directo salvo que lo pidas)"))
    sp.add_argument("--yes", "-y", action="store_true", help=_("no pedir confirmación antes de instalar"))
    sp.add_argument("--protect", choices=["killswitch", "restart"],
                    help=_("mientras VELA está parado para cambiar de versión: kill-switch hasta que arranque la nueva, "
                           "o cerrar y reabrir sin protección (por defecto se pregunta; con --yes, restart)"))
    sp.add_argument("--progress", action="store_true", help=argparse.SUPPRESS)
    sp = add("uninstall", cmd_uninstall, _("desinstalar VELA: servicio, bandeja, lanzador, comandos y programa (tus datos se conservan salvo con --purge)"))
    sp.add_argument("--purge", action="store_true", help=_("borrar también historial, ajustes y claves de API"))
    sp.add_argument("--dry-run", action="store_true", help=_("solo mostrar qué se quitaría"))
    sp.add_argument("--yes", "-y", action="store_true", help=_("no pedir confirmación"))
    add("routes", cmd_routes, _("cómo viaja tu tráfico: programa → directo/proxy/Tor → VPN → lo que ve el destino"))
    sp = add("leakwatch", cmd_leakwatch, _("IP pública y fugas de IP en tiempo real (conexiones fuera del túnel)"))
    sp.add_argument("--once", action="store_true", help=_("una sola pasada"))
    sp.add_argument("--all", action="store_true", help=_("mostrar también las conexiones protegidas"))
    sp.add_argument("--interval", type=float, default=2.0)
    sp = add("networks", cmd_networks, _("todas tus redes: WiFi, LAN, VPN, Docker, VMs, vecinos y tráfico"))
    sp.add_argument("--neighbors", "-n", action="store_true", help=_("listar los dispositivos vistos en cada red"))
    sp.add_argument("--all", action="store_true", help=_("incluir interfaces veth de contenedores"))
    sp = add("vpn", cmd_vpn, _("VPN detectadas"))
    sp.add_argument("action", nargs="?", default="list", choices=["list"])
    sp = add("proxy", cmd_proxy, _("proxies detectados"))
    sp.add_argument("action", nargs="?", default="list", choices=["list"])
    sp = add("tor", cmd_tor, _("estado de Tor / nuevo circuito"))
    sp.add_argument("action", nargs="?", default="status", choices=["status", "newnym"])
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true")
    sp = add("dns", cmd_dns, _("DNS por enlace y fugas; cifrar o restaurar DoT/DoH"))
    sp.add_argument("action", nargs="?", default="check", choices=["check", "status", "encrypt", "restore"])
    sp.add_argument("--active", action="store_true", help=_("test activo (requiere consentimiento)"))
    sp.add_argument("--transport", default="dot", choices=["dot", "doh"])
    sp.add_argument("--provider", default="cloudflare", choices=["cloudflare", "quad9", "google", "mullvad"])
    sp.add_argument("--yes", action="store_true", help=_("aplicar el cambio (requiere allow_dns_changes)"))
    sp = add("ip", cmd_ip, _("IP pública (con consentimiento) e IP WAN del router"))
    sp.add_argument("--route", choices=["default", "tor"])
    sp = add("sessions", cmd_sessions, _("sesiones de salida"))
    sp.add_argument("--limit", type=int, default=30)
    sp.add_argument("--since")
    sp.add_argument("--profile")
    sp = add("counters", cmd_counters, _("contadores de tiempo por IP/VPN/proxy/nodo/país…"))
    sp.add_argument("--layer")
    sp.add_argument("--since")
    sp.add_argument("--profile")
    sp = add("history", cmd_history, _("OPSEC timeline"))
    sp.add_argument("--since", default="24h")
    sp.add_argument("--limit", type=int, default=200)
    sp.add_argument("--severity")
    add("watch", cmd_watch, _("eventos en tiempo real (requiere daemon)"))
    sp = add("rotate", cmd_rotate, _("rotar una capa (tor/proxy/vpn) o ver el estado"))
    sp.add_argument("layer", nargs="?", choices=["tor", "proxy", "vpn"])
    sp.add_argument("--dry-run", action="store_true")
    sp.add_argument("--force", action="store_true", help=_("ignorar el tiempo mínimo de uso"))
    sp = add("leaks", cmd_leaks, _("pruebas de fugas"))
    sp.add_argument("action", nargs="?", default="check", choices=["check"])
    sp.add_argument("--active", action="store_true")
    sp = add("profiles", cmd_profiles, _("perfiles OPSEC"))
    sp.add_argument("action", nargs="?", default="list", choices=["list", "activate", "correlation", "generate"])
    sp.add_argument("name", nargs="?")
    sp.add_argument("--write", action="store_true", help=_("con generate: añadir al config.toml"))
    sp = add("audit", cmd_audit, _("Privacy Audit"))
    sp.add_argument("--html", metavar="FICHERO")
    add("doctor", cmd_doctor, _("diagnóstico de la instalación"))
    sp = add("stats", cmd_stats, _("estadísticas y anomalías"))
    sp.add_argument("--period", default="week", choices=["day", "week", "month"])
    sp.add_argument("--profile")
    sp = add("export", cmd_export, _("exportar histórico"))
    sp.add_argument("--format", default="json", choices=["json", "csv", "html"])
    sp.add_argument("--out", required=True)
    sp.add_argument("--since")
    sp = add("data", cmd_data, _("backup completo, importación y borrado de datos"))
    sp.add_argument("action", nargs="?", default="info", choices=["info", "export", "import", "reset"])
    sp.add_argument("path", nargs="?")
    sp.add_argument("--out", default="vela-backup.json")
    sp.add_argument("--mode", default="merge", choices=["merge", "replace"])
    sp.add_argument("--scope", default="history", choices=["history", "all"])
    sp.add_argument("--no-history", action="store_true")
    sp.add_argument("--config", action="store_true")
    sp.add_argument("--settings", action="store_true")
    sp.add_argument("--secrets", action="store_true")
    sp.add_argument("--backup", action="store_true", help=_("guardar una copia antes de borrar"))
    sp.add_argument("--yes", action="store_true")
    sp = add("deps", cmd_deps, _("comprobar o instalar dependencias opcionales"))
    sp.add_argument("action", nargs="?", default="check", choices=["check", "install", "ollama"])
    sp.add_argument("--feature", choices=["ocr", "capture", "mac", "dns", "cloudflared", "llm"])
    sp.add_argument("--yes", action="store_true")
    sp = add("translate", cmd_translate, _("traducir texto con el LLM local"))
    sp.add_argument("text", nargs="?")
    sp.add_argument("--to", default="es")
    sp.add_argument("--source", default="auto")
    sp = add("ocr", cmd_ocr, _("OCR de una región de pantalla o de una imagen y traducción"))
    sp.add_argument("--image")
    sp.add_argument("--langs", default="spa,eng")
    sp.add_argument("--to", default="es")
    sp.add_argument("--source", default="auto")
    sp.add_argument("--no-translate", action="store_true")
    sp = add("tz", cmd_tz, _("abrir una aplicación con otra zona horaria"))
    sp.add_argument("action", nargs="?", default="list", choices=["list", "launch"])
    sp.add_argument("--app")
    sp.add_argument("--command")
    sp.add_argument("--tz", default="UTC")
    sp.add_argument("--query")
    sp.add_argument("--dry-run", action="store_true")
    sp = add("mac", cmd_mac, _("cambiar o restaurar la MAC de una interfaz"))
    sp.add_argument("action", nargs="?", default="list", choices=["list", "set", "random", "restore"])
    sp.add_argument("--iface")
    sp.add_argument("--mac")
    sp.add_argument("--yes", action="store_true")
    add("anomalies", cmd_anomalies, _("anomalías de red de la línea base"))
    sp = add("logs", cmd_logs, _("log de auditoría y log de errores"))
    sp.add_argument("action", nargs="?", default="show", choices=["show", "clear"])
    sp.add_argument("--kind", default="all", choices=["all", "audit", "errors"])
    sp.add_argument("--limit", type=int, default=100)
    sp = add("notify", cmd_notify, _("activar, silenciar o consultar las notificaciones"))
    sp.add_argument("action", nargs="?", default="status", choices=["status", "on", "off", "mute"])
    sp.add_argument("--for", dest="for_", help=_("duración del silencio (p. ej. 15m, 8h); sin ella, indefinido"))
    sp = add("refresh", cmd_refresh, _("invalidar caches y recalcular alertas y recomendaciones ahora"))
    sp.add_argument("domains", nargs="*", choices=["network", "networks", "dns", "tor", "leaks", "profiles",
                                                   "anomalies", "public", "all"])
    sp = add("about", cmd_about, _("información de VELA y del creador"))
    sp.add_argument("--sync", action="store_true", help=_("sincronizar el perfil público de GitHub"))
    sp = add("killswitch", cmd_killswitch, _("kill-switch nftables"))
    sp.add_argument("action", nargs="?", default="status", choices=["status", "preview", "apply", "release"])
    sp.add_argument("--yes", action="store_true")
    add("fix", cmd_fix, _("comandos concretos para corregir lo detectado (no ejecuta nada)"))
    sp = add("intel", cmd_intel, _("GreyNoise/VirusTotal/Shodan/Censys sobre las IPs de tu historial o un listado"))
    sp.add_argument("action", nargs="?", default="show", choices=["scan", "show", "targets", "keys", "set-key"])
    sp.add_argument("targets", nargs="*", help=_("IPs (scan/show) o nombre de clave (set-key)"))
    sp.add_argument("--file", help=_("fichero con un listado de IPs (cualquier formato; '-' = stdin)"))
    sp.add_argument("--history", action="store_true", help=_("incluir todas las IPs del historial y actuales"))
    sp.add_argument("--providers", help=_("lista separada por comas (greynoise,virustotal,shodan,censys)"))
    sp.add_argument("--include-own", action="store_true", help=_("incluir tus IPs propias (WAN/IP directa)"))
    sp.add_argument("--refresh", action="store_true", help=_("ignorar la caché"))
    sp.add_argument("--allow-direct", action="store_true", help=_("permitir consultar sin VPN (expone tu IP real)"))
    sp.add_argument("--since")
    add("panic", cmd_panic, _("modo de emergencia (no borra datos)"))
    add("resume", cmd_resume, _("salir del modo de emergencia"))
    sp = add("purge", cmd_purge, _("borrar histórico antiguo"))
    sp.add_argument("--days", type=float, required=True)
    sp.add_argument("--yes", action="store_true")
    sp = add("config", cmd_config, _("configuración"))
    sp.add_argument("action", nargs="?", default="show", choices=["show", "path", "init", "edit"])
    sp.add_argument("--force", action="store_true")
    sp = add("daemon", cmd_daemon, _("gestionar velad"))
    sp.add_argument("action", nargs="?", default="status", choices=["status", "start", "stop", "run", "enable", "disable"])
    add("tui", cmd_tui, _("interfaz de terminal"))
    sp = add("tray", cmd_tray, _("icono en la bandeja del sistema con estado y controles"))
    sp.add_argument("--install", action="store_true", help=_("mostrarlo al iniciar sesión y arrancarlo ahora"))
    sp.add_argument("--remove", action="store_true", help=_("quitarlo del inicio de sesión y cerrarlo"))
    sp = add("app", cmd_app, _("aplicación nativa de escritorio (GTK 4 + libadwaita)"))
    sp.add_argument("--install", action="store_true", help=_("instalar el lanzador en el menú de aplicaciones"))
    sp.add_argument("--uninstall", action="store_true", help=_("abrir la app y preguntar si desinstalar VELA"))
    sp.add_argument("--quit", action="store_true", help=_("cerrar la app si está abierta (también oculta en la bandeja)"))
    sp = add("gui", cmd_gui, _("interfaz gráfica (web local)"))
    sp.add_argument("--no-browser", action="store_true")
    sp.add_argument("--port", type=int, default=0)
    return p


def _drop_sudo_privileges(argv: list[str]) -> None:
    """Si se lanzó con `sudo vela …`, vuelve a ejecutar como el usuario que invocó sudo.

    Así los datos no quedan en /root y la app puede abrir la sesión gráfica del usuario. Las
    acciones que necesitan root (DNS, MAC, kill-switch) siguen usando pkexec/sudo desde ese
    usuario. Para conservar root a propósito: `VELA_KEEP_ROOT=1 sudo vela …`.
    """
    if os.geteuid() != 0 or os.environ.get("VELA_KEEP_ROOT") == "1" or os.environ.get("VELA_REEXEC") == "1":
        return
    user = os.environ.get("SUDO_USER")
    if not user or user == "root":
        return
    try:
        import pwd
        pw = pwd.getpwnam(user)
    except (ImportError, KeyError):
        return
    if pw.pw_uid == 0:
        return
    env = os.environ.copy()
    env.update({"HOME": pw.pw_dir, "USER": user, "LOGNAME": user, "VELA_REEXEC": "1"})
    runtime = f"/run/user/{pw.pw_uid}"
    if os.path.isdir(runtime):
        env["XDG_RUNTIME_DIR"] = runtime
        bus = os.path.join(runtime, "bus")
        if os.path.exists(bus):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
        if os.path.exists(os.path.join(runtime, "wayland-0")):
            env.setdefault("WAYLAND_DISPLAY", "wayland-0")
    xauth = os.path.join(pw.pw_dir, ".Xauthority")
    if os.path.exists(xauth):
        env["XAUTHORITY"] = xauth
    try:
        print(_("sudo detectado: ejecutando VELA como {user} (VELA_KEEP_ROOT=1 conserva root)", user=user),
              file=sys.stderr)
        os.setgid(pw.pw_gid)
        os.setgroups(os.getgrouplist(user, pw.pw_gid))
        os.setuid(pw.pw_uid)
        os.execvpe(sys.executable, [sys.executable, "-m", "vela", *argv], env)
    except (OSError, PermissionError) as e:
        print(_("no se pudo cambiar al usuario {user}: {e}; sigo como root", user=user, e=e), file=sys.stderr)


def _early_lang(argv: list[str]) -> None:
    """--lang se aplica antes de construir el parser (la ayuda ya sale traducida)."""
    from . import i18n
    for i, a in enumerate(argv):
        code = a.split("=", 1)[1] if a.startswith("--lang=") else (argv[i + 1] if a == "--lang" and i + 1 < len(argv) else None)
        if code in i18n.LANGS:
            os.environ["VELA_LANG"] = code          # también para los procesos hijos (mapa, bandeja…)
            i18n.set_language(code)


def main(argv: list[str] | None = None) -> int:
    from . import logs
    logs.setup()
    _drop_sudo_privileges(sys.argv[1:] if argv is None else argv)
    _early_lang(sys.argv[1:] if argv is None else argv)
    if not sys.platform.startswith("linux"):
        print(_("VELA solo funciona en Linux. Las versiones para Windows están en las ramas «windows-lite» y «windows» del repositorio."), file=sys.stderr)
        return 2
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "fn", None):
        parser.print_help()
        return 0
    a.json = a.json or getattr(a, "json_sub", False)
    if not os.environ.get("VELA_NO_MIGRATE"):
        from . import migrate
        for msg in migrate.migrate():                 # una sola vez: datos del nombre anterior (opsectools)
            print(c(_("migración a VELA: {msg}", msg=msg), "36"), file=sys.stderr)
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
    if a.cmd == "update":
        return cmd_update(None, a)
    if a.cmd == "uninstall":
        return cmd_uninstall(None, a)
    if a.cmd == "app" and getattr(a, "quit", False):      # cerrar la app abierta sin arrancar el motor
        from .native import app as native
        return native.run(None, quit_=True)
    from .ipc import IPCError, LocalBackend, connect
    try:
        b = LocalBackend() if a.local else connect()
        res = a.fn(b, a)
    except IPCError as e:
        print(c(f"error: {e}", "31"), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    except Exception as e:  # noqa: BLE001 — la CLI informa del error sin enseñar una traza al usuario
        logs.error(_("error en la CLI"), e, {"command": getattr(a, "cmd", "?")})
        print(c(f"error: {e}", "31"), file=sys.stderr)
        return 1
    if res is not None:
        print(json.dumps(res, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
