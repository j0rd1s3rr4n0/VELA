"""Protecciones de terceros: kill-switches de clientes VPN y DNS cifrado.

Dos niveles de evidencia, siempre separados:
  * declarada  – lo que dice la configuración del cliente (p. ej. settings.json de ProtonVPN).
  * verificada – lo que muestra el sistema: interfaces dummy de bloqueo, rutas, procesos, sockets.

La verificación por rutas responde a: "si el túnel desaparece, ¿por dónde saldría el tráfico?".
Se calcula sobre la tabla main quitando los túneles: si la ruta por defecto restante con menor
métrica va a una interfaz de bloqueo (dummy) o es blackhole/unreachable/prohibit, hay protección.
No se lee el firewall (requiere root): un kill-switch hecho solo con nftables queda como "no verificable".
"""

from __future__ import annotations

from .i18n import N_, _

import glob
import ipaddress
import json
import os
import re
from pathlib import Path

from .util import run, run_json, which

HOME = Path.home()
TUNNEL_KINDS = {"wireguard", "tun", "ppp"}
BLOCK_ROUTE_TYPES = {"blackhole", "unreachable", "prohibit"}

PROTON_SETTINGS = [
    "~/.config/Proton/VPN/settings.json",
    "~/snap/proton-vpn/current/.config/Proton/VPN/settings.json",
    "~/.var/app/com.protonvpn.www/config/Proton/VPN/settings.json",
]
PROTON_KS_MODES = {0: N_("desactivado"), 1: N_("estándar (solo con la VPN conectada o conectando)"),
                   2: N_("permanente (bloquea siempre sin VPN)")}
SECURE_CORE_ENTRIES = {"CH", "IS", "SE"}
WARP_DNS_ADDRS = {"127.0.2.2", "127.0.2.3", "::ffff:127.0.2.2", "::ffff:127.0.2.3"}


def _read_json(path) -> dict | None:
    try:
        with open(os.path.expanduser(path)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _first(paths) -> tuple[str | None, dict | None]:
    for p in paths:
        data = _read_json(p)
        if data is not None:
            return os.path.expanduser(p), data
    return None, None


# ── rutas: ¿qué pasa si cae el túnel? ───────────────────────────────────────

def default_routes() -> dict[str, list[dict]]:
    """Rutas por defecto de la tabla main, incluidas blackhole/unreachable/prohibit."""
    out = {"ipv4": [], "ipv6": []}
    for fam, flag in (("ipv4", "-4"), ("ipv6", "-6")):
        for r in run_json(["ip", "-j", flag, "route", "show", "table", "main"]) or []:
            if r.get("dst") != "default":
                continue
            out[fam].append({"dev": r.get("dev"), "gateway": r.get("gateway"), "metric": r.get("metric", 0),
                             "type": r.get("type", "unicast")})
    return out


def fallback_route(routes: list[dict], kinds: dict[str, str]) -> dict | None:
    """Ruta por defecto que quedaría al desaparecer los túneles (menor métrica, sin túneles)."""
    rest = [r for r in routes if kinds.get(r.get("dev")) not in TUNNEL_KINDS]
    return min(rest, key=lambda r: r.get("metric") or 0) if rest else None


def route_protection(routes: dict[str, list[dict]], kinds: dict[str, str]) -> dict:
    res = {}
    for fam in ("ipv4", "ipv6"):
        fb = fallback_route(routes[fam], kinds)
        if fb is None:
            state, why = "bloqueado", _("sin ruta por defecto fuera del túnel")
        elif fb["type"] in BLOCK_ROUTE_TYPES:
            state, why = "bloqueado", f"ruta {fb['type']}"
        elif kinds.get(fb.get("dev")) == "dummy":
            state, why = "bloqueado", _("ruta a la interfaz de bloqueo {dev} (métrica {metric})", dev=fb['dev'], metric=fb['metric'])
        else:
            state, why = "expuesto", _("saldría por {v1} vía {v3} (métrica {metric})", v1=fb.get('dev'), v3=fb.get('gateway') or '-', metric=fb['metric'])
        res[fam] = {"state": state, "detail": why, "fallback": fb}
    return res


# ── kill-switches de clientes ───────────────────────────────────────────────

def _nm_connections() -> list[dict]:
    code, out, _ign = run(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,ACTIVE", "connection", "show"])
    rows = []
    for line in out.splitlines() if code == 0 else []:
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) >= 4:
            rows.append({"name": f[0], "type": f[1], "device": f[2] or None, "active": f[3] == "yes"})
    return rows


def proton_exit_country(name: str) -> str | None:
    """'ProtonVPN CH-DE#2' → 'DE' (Secure Core: entrada CH/IS/SE, salida DE); 'ES#12' → 'ES';
    'US-NY#5' → 'US' (la segunda parte es un estado/región, no un país)."""
    m = re.search(r"\b([A-Z]{2})(?:-([A-Z]{2,3}))?#\d+", name or "")
    if not m:
        return None
    first, second = m.group(1), m.group(2)
    if second and first in SECURE_CORE_ENTRIES and len(second) == 2:
        return second
    return first


def proton_state(nm: list[dict], kinds: dict[str, str]) -> dict | None:
    path, settings = _first(PROTON_SETTINGS)
    ks_conns = [c for c in nm if c["name"].startswith("pvpn-killswitch")]
    vpn_conns = [c for c in nm if c["name"].startswith("ProtonVPN")]
    ifaces = [n for n, k in kinds.items() if n.startswith("pvpnks")]
    installed = bool(path or which("proton-vpn") or which("protonvpn-app") or which("protonvpn") or os.path.isdir("/snap/proton-vpn")
                     or os.path.isdir(os.path.expanduser("~/.var/app/com.protonvpn.www")))
    if not (installed or ks_conns or vpn_conns):
        return None
    mode = (settings or {}).get("killswitch")
    active_ks = [c["name"] for c in ks_conns if c["active"]]
    return {
        "client": "ProtonVPN",
        "settings_file": path,
        "declared": {"killswitch": mode, "killswitch_mode": _(PROTON_KS_MODES.get(mode, N_("desconocido"))),
                     "ipv6": (settings or {}).get("ipv6"),
                     "netshield": ((settings or {}).get("features") or {}).get("netshield"),
                     "custom_dns": ((settings or {}).get("custom_dns") or {}).get("enabled"),
                     "split_tunneling": (((settings or {}).get("features") or {}).get("split_tunneling") or {}).get("enabled")}
        if settings else None,
        "killswitch_connections": [c["name"] for c in ks_conns],
        "killswitch_active": bool(active_ks),
        "killswitch_ifaces": ifaces,
        "vpn_connections": [{"name": c["name"], "device": c["device"], "active": c["active"]} for c in vpn_conns],
        "connected": any(c["active"] for c in vpn_conns),
    }


def mullvad_state() -> dict | None:
    if not which("mullvad"):
        return None
    code, out, _ign = run(["mullvad", "lockdown-mode", "get"])
    lockdown = None
    if code == 0:
        lockdown = bool(re.search(r"\bon\b|enabled|true", out, re.I))
    code, st, _ign = run(["mullvad", "status"])
    return {"client": "Mullvad", "declared": {"lockdown_mode": lockdown},
            "killswitch_active": True if st and "Connected" in st else None,
            "note": _("Mullvad bloquea el tráfico con su propio firewall durante reconexiones; con lockdown "
                    "también estando desconectado"), "connected": bool(st and "Connected" in st)}


def nordvpn_state() -> dict | None:
    if not which("nordvpn"):
        return None
    code, out, _ign = run(["nordvpn", "settings"])
    ks = None
    m = re.search(r"Kill Switch:\s*(\w+)", out or "", re.I)
    if m:
        ks = m.group(1).lower() in ("enabled", "on", "true")
    return {"client": "NordVPN", "declared": {"killswitch": ks}, "killswitch_active": ks}


def detect_killswitches(kinds: dict[str, str], routes: dict | None = None) -> dict:
    """kinds: interfaz → tipo (de network.snapshot)."""
    routes = routes or default_routes()
    rp = route_protection(routes, kinds)
    nm = _nm_connections() if which("nmcli") else []
    clients = [c for c in (proton_state(nm, kinds), mullvad_state(), nordvpn_state()) if c]
    tunnel_up = any(k in TUNNEL_KINDS for k in kinds.values())
    verified = {fam: rp[fam]["state"] == "bloqueado" for fam in rp}
    declared_on = [c for c in clients if (c.get("declared") or {}).get("killswitch") not in (None, 0, False)
                   or (c.get("declared") or {}).get("lockdown_mode") or c.get("killswitch_active")]
    active = bool(tunnel_up and verified["ipv4"]) or any(c.get("killswitch_active") for c in clients)
    return {
        "active": active,
        "route_protection": rp,
        "verified_ipv4": verified["ipv4"],
        "verified_ipv6": verified["ipv6"],
        "clients": clients,
        "declared_by": [c["client"] for c in declared_on],
        "limitations": _("Verificación basada en rutas e interfaces; las reglas de firewall de los clientes "
                       "(nftables) no se pueden leer sin root."),
    }


# ── DNS efectivo y cifrado ──────────────────────────────────────────────────

def warp_state() -> dict | None:
    if not which("warp-cli"):
        return None
    _ign, st, _ign = run(["warp-cli", "--accept-tos", "status"])
    _ign, settings, _ign = run(["warp-cli", "--accept-tos", "settings"])
    mode = re.search(r"Mode:\s*(\S+)", settings or "")
    via = re.search(r"Resolve via:\s*(\S+)\s*@\s*\[([^\]]*)\]", settings or "")
    return {
        "provider": "Cloudflare WARP",
        "connected": "Connected" in (st or ""),
        "status": (st or "").strip().splitlines()[0] if st and st.strip() else None,
        "mode": mode.group(1) if mode else None,
        "doh_host": via.group(1) if via else None,
        "upstream_ips": [x.strip() for x in via.group(2).split(",")] if via else [],
        "always_on": "Always On: true" in (settings or ""),
    }


def cloudflared_dns_procs() -> list[dict]:
    """Instancias de `cloudflared proxy-dns` (DoH local)."""
    out = []
    for d in glob.glob("/proc/[0-9]*"):
        try:
            args = [a.decode(errors="replace") for a in Path(d, "cmdline").read_bytes().split(b"\0") if a]
        except OSError:
            continue
        if not args or not os.path.basename(args[0]).startswith("cloudflared") or "proxy-dns" not in args:
            continue
        opts = {}
        for i, a in enumerate(args):
            if a.startswith("--") and i + 1 < len(args) and not args[i + 1].startswith("--"):
                opts.setdefault(a[2:], []).append(args[i + 1])
        out.append({"provider": "cloudflared", "address": (opts.get("address") or ["localhost"])[0],
                    "port": int((opts.get("port") or ["53"])[0]),
                    "upstreams": opts.get("upstream") or ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"]})
    return out


def _procs_named(*names) -> bool:
    for d in glob.glob("/proc/[0-9]*"):
        try:
            if Path(d, "comm").read_text().strip() in names:
                return True
        except OSError:
            continue
    return False


def browser_doh() -> list[dict]:
    found = []
    profiles = glob.glob(os.path.expanduser("~/.mozilla/firefox/*/prefs.js")) + \
        glob.glob(os.path.expanduser("~/snap/firefox/common/.mozilla/firefox/*/prefs.js")) + \
        glob.glob(os.path.expanduser("~/.var/app/org.mozilla.firefox/.mozilla/firefox/*/prefs.js"))
    for p in profiles:
        try:
            text = open(p, errors="replace").read()
        except OSError:
            continue
        mode = re.search(r'user_pref\("network\.trr\.mode",\s*(\d+)\)', text)
        uri = re.search(r'user_pref\("network\.trr\.(?:custom_)?uri",\s*"([^"]*)"\)', text)
        m = int(mode.group(1)) if mode else 0
        if m in (2, 3):
            found.append({"browser": "Firefox", "profile": p, "mode": {2: _("DoH con respaldo"), 3: _("solo DoH")}[m],
                          "uri": uri.group(1) if uri else _("por defecto (Cloudflare)")})
    for name, ls in (("Chrome", "~/.config/google-chrome/Local State"), ("Chromium", "~/.config/chromium/Local State"),
                     (_("Chromium (snap)"), "~/snap/chromium/common/chromium/Local State"),
                     ("Brave", "~/.config/BraveSoftware/Brave-Browser/Local State")):
        data = _read_json(ls)
        doh = (data or {}).get("dns_over_https") or {}
        if doh.get("mode") in ("secure", "automatic"):
            found.append({"browser": name, "mode": doh["mode"], "uri": doh.get("templates") or _("automático")})
    return found


def attribute_resolvers(servers: list[str], warp: dict | None, cloudflared: list[dict], resolved_dot: bool,
                        has_dnscrypt: bool, has_stubby: bool) -> list[dict]:
    """Para cada resolver efectivo: proveedor, transporte y si está cifrado (True/False/None)."""
    out = []
    for s in servers:
        ip = s.split("#")[0].split("%")[0]
        entry = {"addr": s, "provider": None, "transport": _("DNS en claro (UDP/TCP 53)"), "encrypted": False,
                 "upstream": None, "evidence": None}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            out.append({**entry, "encrypted": None, "evidence": _("dirección no reconocida")})
            continue
        if warp and ip in WARP_DNS_ADDRS:
            doh = warp.get("mode") in ("DnsOverHttps", "WarpWithDnsOverHttps", "doh", "warp+doh")
            entry.update(provider="Cloudflare WARP",
                         transport="DoH" if doh else f"túnel WARP ({warp.get('mode')})",
                         encrypted=True if warp.get("connected") else None,
                         upstream=warp.get("doh_host"),
                         evidence=_("warp-cli: modo {v1}, {v3}", v1=warp.get('mode'), v3=warp.get('status')))
        elif addr.is_loopback and any(c["address"] == str(addr) or (c["address"] == "localhost" and str(addr) == "127.0.0.1")
                                      for c in cloudflared):
            c = cloudflared[0]
            entry.update(provider="cloudflared proxy-dns", transport="DoH", encrypted=True,
                         upstream=", ".join(c["upstreams"]), evidence=_("proceso cloudflared proxy-dns"))
        elif addr.is_loopback and str(addr).startswith("127.0.0.5"):
            entry.update(provider="systemd-resolved (stub)", transport="DoT" if resolved_dot else "stub local",
                         encrypted=True if resolved_dot else None,
                         evidence=_("el cifrado depende de los servidores configurados en resolved"))
        elif addr.is_loopback and (has_dnscrypt or has_stubby):
            entry.update(provider="dnscrypt-proxy" if has_dnscrypt else "stubby",
                         transport="DNSCrypt/DoH" if has_dnscrypt else "DoT", encrypted=True,
                         evidence=_("proceso en ejecución escuchando en loopback (atribución probable)"))
        elif addr.is_loopback:
            entry.update(provider="resolver local", encrypted=None, evidence=_("resolver local de origen desconocido"))
        elif resolved_dot:
            entry.update(transport="DoT (systemd-resolved)", encrypted=True, evidence=_("+DNSOverTLS en resolved"))
        out.append(entry)
    return out


def detect_dns_encryption(dns_snap: dict) -> dict:
    warp = warp_state()
    cfd = cloudflared_dns_procs()
    resolvers = attribute_resolvers(dns_snap.get("effective_servers") or [], warp, cfd, bool(dns_snap.get("dot")),
                                    _procs_named("dnscrypt-proxy"), _procs_named("stubby"))
    flags = [r["encrypted"] for r in resolvers]
    system = True if flags and all(f is True for f in flags) else (False if any(f is False for f in flags) else None)
    upstream_route = None
    if warp and warp.get("upstream_ips"):
        v4 = next((x for x in warp["upstream_ips"] if ":" not in x), None)
        if v4:
            r = run_json(["ip", "-j", "route", "get", v4])
            if r:
                upstream_route = {"ip": v4, "dev": r[0].get("dev")}
    server_routes = {}
    for srv in dns_snap.get("effective_servers") or []:
        ip = srv.split("#")[0].split("%")[0]
        try:
            if ipaddress.ip_address(ip).is_loopback:
                continue
        except ValueError:
            continue
        r = run_json(["ip", "-j", "route", "get", ip])
        server_routes[srv] = r[0].get("dev") if r else None
    return {"resolvers": resolvers, "system_encrypted": system, "warp": warp, "cloudflared": cfd,
            "browsers": browser_doh(), "upstream_route": upstream_route, "server_routes": server_routes}
