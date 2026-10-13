"""Cómo viaja tu tráfico: programa → capa local (directo / proxy / Tor) → salida (VPN o no) → lo que ve el destino.

Se reconstruye solo con la tabla de sockets del kernel:
  * programa → proxy/Tor: conexiones de loopback hacia el puerto de un proxy local o del SocksPort de Tor;
  * proxy/Tor → Internet: conexiones a Internet abiertas por el PROCESO del proxy (o por el usuario de Tor);
  * el resto de conexiones a Internet de cada programa son directas;
  * la interfaz de la IP local de cada conexión dice si va por el túnel VPN o no.

Así se ve, por ejemplo, que un proxy local NO cambia la IP que ve el destino (su tráfico sale igualmente
por la VPN o por tu conexión), mientras que un proxy remoto o Tor sí.
"""

from __future__ import annotations

import ipaddress

LOOPBACK = {"127.0.0.1", "::1"}


def _is_loop(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


def build(flows: list[dict], loop_socks: list[dict], loop_owners: dict, local_proxies: list[dict],
          tunnels: list[str], public: dict, tor_socks_ports: list[int], proxy_owner_pids: dict) -> dict:
    """Devuelve nodos y enlaces (diagrama de Sankey de 4 columnas) y un resumen por capa.

    flows: conexiones a Internet ya clasificadas (leakwatch, con process/pid/iface/verdict/tor).
    loop_socks: sockets de loopback (lado cliente) hacia puertos de proxy/Tor.
    local_proxies: [{port, kind}] · proxy_owner_pids: {port: pid del servidor del proxy}.
    """
    nodes: dict[str, dict] = {}
    links: dict[tuple[str, str], dict] = {}

    def node(nid, col, label, kind):
        nodes.setdefault(nid, {"id": nid, "col": col, "label": label, "kind": kind, "value": 0})
        return nid

    def link(a, b, n, kind, detail=None):
        k = (a, b)
        e = links.setdefault(k, {"source": a, "target": b, "value": 0, "kind": kind, "details": []})
        e["value"] += n
        if detail and len(e["details"]) < 12 and detail not in e["details"]:
            e["details"].append(detail)

    proxy_ports = {p["port"]: p["kind"] for p in local_proxies if p["kind"] in ("http", "socks5")}
    tor_ports = set(tor_socks_ports)
    pid_to_proxy = {pid: port for port, pid in proxy_owner_pids.items() if pid and port in proxy_ports}

    # 1) programas que usan un proxy local o Tor (loopback, lado cliente)
    for s in loop_socks:
        port = s["rport"]
        if port not in proxy_ports and port not in tor_ports:
            continue
        pid, comm = loop_owners.get(s["inode"], (None, None))
        if pid is not None and pid in pid_to_proxy:          # el propio proxy hablando consigo mismo
            continue
        app = comm or "desconocido"
        if port in tor_ports:
            mid = node(f"tor:{port}", 1, f"Tor (SOCKS :{port})", "tor")
        else:
            mid = node(f"proxy:{port}", 1, f"Proxy {proxy_ports[port].upper()} :{port}", "proxy")
        link(node(f"app:{app}", 0, app, "app"), mid, 1, nodes[mid]["kind"], f"{app} → 127.0.0.1:{port}")

    # 2) conexiones a Internet
    vis = {}
    pub = (public or {}).get("default") or {}
    for f in flows:
        app = f["process"]
        tunnel = f.get("iface_kind") in ("wireguard", "tun", "ppp")
        net_id = node(f"net:{f.get('iface')}", 2, f"Túnel VPN {f.get('iface')}" if tunnel else
                      f"Sin túnel ({f.get('iface') or '?'})", "vpn" if tunnel else "direct")
        if f.get("pid") in pid_to_proxy:                       # tráfico del servidor proxy
            src = node(f"proxy:{pid_to_proxy[f['pid']]}", 1, f"Proxy {proxy_ports[pid_to_proxy[f['pid']]].upper()} "
                       f":{pid_to_proxy[f['pid']]}", "proxy")
        elif app in ("[debian-tor]", "[tor]", "[_tor]", "tor"):  # tráfico del daemon de Tor hacia sus guards
            port = sorted(tor_ports)[0] if tor_ports else 9050
            src = node(f"tor:{port}", 1, f"Tor (SOCKS :{port})", "tor")
        else:
            src = node("direct", 1, "Directo (sin proxy)", "direct")
            link(node(f"app:{app}", 0, app, "app"), src, 1, "direct", f"{app} → {f['remote']}:{f['rport']}")
        link(src, net_id, 1, "vpn" if tunnel else "direct", f"{f['remote']}:{f['rport']}")
        if nodes[src]["kind"] == "tor":
            dest = node("dst:tor", 3, "Red Tor → los destinos ven un exit de Tor", "tor")
        elif tunnel:
            ip = pub.get("ip") if pub.get("via_tunnel") else None
            dest = node("dst:vpn", 3, f"IP de la VPN{f' {ip}' if ip else ''}", "vpn")
        else:
            ip = pub.get("ip") if pub.get("ok") and not pub.get("via_tunnel") else None
            dest = node("dst:real", 3, f"Tu IP real{f' {ip}' if ip else ''}", "direct")
        if nodes[src]["kind"] == "proxy" and not _is_loop(f["remote"]):
            vis.setdefault(src, set()).add(f["remote"])
        link(net_id, dest, 1, nodes[dest]["kind"], f"{app} → {f['remote']}")

    for (a, b), e in links.items():
        nodes[a]["value"] = max(nodes[a]["value"], sum(x["value"] for x in links.values() if x["source"] == a))
        nodes[b]["value"] = max(nodes[b]["value"], sum(x["value"] for x in links.values() if x["target"] == b))

    explain = explain_routes(nodes, links, tunnels, pub, vis)
    return {"nodes": list(nodes.values()), "links": list(links.values()), "explain": explain}


def explain_routes(nodes, links, tunnels, pub, proxy_dests) -> list[str]:
    out = []
    by_kind = lambda k: [n for n in nodes.values() if n["kind"] == k and n["col"] == 1]  # noqa: E731
    users = lambda nid: sorted({l["source"].split(":", 1)[1] for l in links.values()  # noqa: E731
                                if l["target"] == nid and l["source"].startswith("app:")})
    outs = lambda nid: [l for l in links.values() if l["source"] == nid]  # noqa: E731
    for p in by_kind("proxy"):
        u = users(p["id"])
        o = outs(p["id"])
        nets = ", ".join(nodes[l["target"]]["label"] for l in o) or "—"
        line = f"{p['label']}: lo usan {', '.join(u) or 'ningún programa ahora mismo'}. Su tráfico sale por {nets}"
        if o and all(nodes[l["target"]]["kind"] == "vpn" for l in o):
            line += " → los destinos ven la IP de la VPN: un proxy LOCAL no cambia tu IP de salida (sí puede ver y modificar el tráfico)."
        elif o:
            line += " → sin túnel: los destinos ven tu IP real aunque uses el proxy."
        dests = proxy_dests.get(p["id"]) or set()
        if len(dests) == 1:
            line += f" Todo va a {next(iter(dests))}: parece un proxy encadenado a otro proxy remoto (el destino final verá la IP de ese proxy)."
        out.append(line)
    for t in by_kind("tor"):
        u = users(t["id"])
        o = outs(t["id"])
        nets = ", ".join(nodes[l["target"]]["label"] for l in o)
        out.append(f"{t['label']}: lo usan {', '.join(u) or 'ningún programa ahora mismo'}. "
                   + (f"Tor conecta con sus guards por {nets}" + (" (Tor sobre VPN: tu ISP no ve que usas Tor)."
                       if o and all(nodes[l["target"]]["kind"] == "vpn" for l in o) else
                       " (sin VPN: tu ISP ve que usas Tor, aunque no qué haces).") if o else "")
                   + " Los destinos ven la IP de un exit de Tor.")
    d = nodes.get("direct")
    if d:
        u = users("direct")
        o = outs("direct")
        via_vpn = o and all(nodes[l["target"]]["kind"] == "vpn" for l in o)
        out.append(f"Directo (sin proxy): {len(u)} programas ({', '.join(u[:6])}{'…' if len(u) > 6 else ''}) → "
                   + ("por el túnel VPN: los destinos ven la IP de la VPN." if via_vpn else
                      "sin túnel: los destinos ven tu IP real."))
    if not tunnels:
        out.append("No hay VPN conectada: todo lo que no va por Tor (o por un proxy REMOTO) muestra tu IP real.")
    return out
