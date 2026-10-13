"""Detección de fugas y validación OPSEC.

Cada diagnóstico es un dict con: check, title, severity, status (pass/fail/warn/unknown),
mode (pasiva/activa), method, evidence, observed, limitations, confidence, recommendation, ts.

Reglas de prudencia:
  * Nunca se declara fuga DNS solo porque el resolver esté en otro país que la VPN/proxy.
  * Si algo no se puede comprobar, el estado es "unknown" con su limitación, no "pass".
"""

from __future__ import annotations

import ipaddress

from . import discovery
from .util import now

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def finding(check, title, severity, status, mode, method, evidence, observed, limitations, confidence,
            recommendation) -> dict:
    return {"check": check, "title": title, "severity": severity, "status": status, "mode": mode,
            "method": method, "evidence": evidence, "observed": observed, "limitations": limitations,
            "confidence": confidence, "recommendation": recommendation, "ts": now()}


def tz_country(tz: str | None, zone_tabs=("/usr/share/zoneinfo/zone.tab", "/usr/share/zoneinfo/zone1970.tab")) -> str | None:
    """País de una zona horaria. zone.tab primero: zone1970.tab omite zonas fusionadas (Europe/Stockholm)."""
    if not tz:
        return None
    for path in zone_tabs:
        try:
            with open(path) as f:
                for line in f:
                    parts = line.rstrip("\n").split("\t")
                    if len(parts) >= 3 and parts[2] == tz:
                        return parts[0].split(",")[0]
        except OSError:
            continue
    return None


def check_ipv6(net: dict) -> dict:
    v4_tunnel = net["via_tunnel"].get("ipv4")
    e6 = net["egress"].get("ipv6")
    ev = {"egress_ipv4": net["egress"].get("ipv4"), "egress_ipv6": e6, "ipv6_internet": net["ipv6_internet"]}
    if e6 and net.get("egress_kind", {}).get("ipv6") == "dummy":
        return finding("ipv6_leak", "IPv6 bloqueado por el kill-switch", "info", "pass", "pasiva",
                       "ip route get (IPv6) + tipo de interfaz", ev,
                       f"El tráfico IPv6 va a la interfaz de bloqueo {e6['dev']}: no sale a Internet",
                       "Basado en la tabla de rutas.", "alta", "Ninguna.")
    if v4_tunnel and e6 and not net["via_tunnel"].get("ipv6") and net["ipv6_internet"]:
        return finding("ipv6_leak", "Fuga IPv6 fuera del túnel", "high", "fail", "pasiva",
                       "ip route get (IPv4 vs IPv6) + direcciones globales de la interfaz", ev,
                       f"IPv4 sale por {net['egress']['ipv4']['dev']} (túnel) pero IPv6 sale por {e6['dev']}",
                       "Basado en la tabla de rutas; no detecta reglas de firewall que bloqueen IPv6.", "alta",
                       "Desactiva IPv6 en la interfaz física o configura la VPN para que capture ::/0.")
    if not e6:
        return finding("ipv6_leak", "Sin ruta IPv6 a Internet", "info", "pass", "pasiva", "ip route get", ev,
                       "No hay ruta IPv6 por defecto: no puede haber fuga IPv6.", "Estado en este instante.",
                       "alta", "Ninguna.")
    return finding("ipv6_leak", "IPv6 coherente con la ruta IPv4", "info", "pass", "pasiva", "ip route get", ev,
                   "IPv6 sigue el mismo camino que IPv4 o no hay túnel que evitar.", "Estado en este instante.",
                   "media", "Ninguna.")



def check_tunnel_route(net: dict, profile: dict) -> dict:
    expects_vpn = bool(profile.get("require_vpn") or profile.get("preferred_vpn"))
    ev = {"tunnels": net["tunnels"], "egress": net["egress"].get("ipv4"), "policy_rules": len(net["policy_rules"])}
    via = net["via_tunnel"].get("ipv4")
    if expects_vpn and not via:
        return finding("tunnel_bypass", "El tráfico no pasa por la VPN que exige el perfil", "high", "fail",
                       "pasiva", "ip route get 1.1.1.1 (respeta policy routing)", ev,
                       f"La ruta por defecto sale por {(net['egress'].get('ipv4') or {}).get('dev')}",
                       "No inspecciona tráfico de aplicaciones con sus propias rutas o namespaces.", "alta",
                       "Conecta la VPN del perfil o activa el kill-switch antes de seguir operando.")
    if net["tunnels"] and not via:
        return finding("tunnel_bypass", "Túnel activo pero la ruta por defecto no lo usa", "medium", "warn",
                       "pasiva", "ip route get + interfaces de túnel", ev,
                       f"Túneles {net['tunnels']} activos; salida por {(net['egress'].get('ipv4') or {}).get('dev')}",
                       "Puede ser split-tunnel intencionado.", "media",
                       "Verifica que el split-tunnel es intencionado.")
    if via:
        return finding("tunnel_bypass", "El tráfico IPv4 sale por el túnel", "info", "pass", "pasiva",
                       "ip route get", ev, f"Salida por {net['egress']['ipv4']['dev']}",
                       "Ruta del kernel; no garantiza que el túnel cifre ni a dónde lleva.", "alta", "Ninguna.")
    return finding("tunnel_bypass", "Conexión directa (sin VPN)", "info", "pass" if not expects_vpn else "fail",
                   "pasiva", "ip route get", ev, "No hay túnel y el perfil no lo exige.",
                   "—", "alta", "Si necesitas ocultar tu IP al destino usa VPN, proxy o Tor.")


def _resolver_label(r: dict) -> str:
    return f"{r['addr']} ({r['provider'] or 'desconocido'}, {r['transport']})"


def check_dns(net: dict, dns: dict) -> list[dict]:
    out = []
    tunnels = set(net["tunnels"])
    enc = dns.get("encryption") or {}
    resolvers = enc.get("resolvers") or []
    ev = {"effective_source": dns.get("effective_source"), "effective_servers": dns.get("effective_servers"),
          "resolvers": resolvers, "default_links": dns.get("default_links"), "split_dns": dns.get("split_dns"),
          "upstream_route": enc.get("upstream_route"), "server_routes": enc.get("server_routes")}
    labels = ", ".join(_resolver_label(r) for r in resolvers) or ", ".join(dns.get("effective_servers") or []) or "ninguno"

    if net["via_tunnel"].get("ipv4"):
        # 1) ¿Por dónde viajan realmente las consultas?
        outside = []
        for srv, dev in (enc.get("server_routes") or {}).items():
            if dev and dev not in tunnels:
                outside.append(f"{srv} por {dev}")
        up = enc.get("upstream_route")
        if up and up.get("dev") and up["dev"] not in tunnels:
            outside.append(f"DoH hacia {up['ip']} por {up['dev']}")
        if dns.get("effective_source") == "systemd-resolved":
            for l in dns.get("default_links", []):
                if l not in tunnels:
                    outside.append(f"resolvers del enlace {l}: {' '.join(dns['links'][l]['servers'])}")
        if outside:
            out.append(finding("dns_leak_config", "Consultas DNS que salen fuera del túnel", "high", "fail", "pasiva",
                               "resolver efectivo + ip route get hacia cada resolver/servidor DoH", ev,
                               "; ".join(outside),
                               "Configuración y rutas observadas; confírmalo con el test activo.", "media",
                               "Haz que el DNS use el túnel (DNS de la VPN o DoH enrutado por el túnel)."))
        else:
            how = []
            if up:
                how.append(f"la conexión DoH a {up['ip']} sale por {up['dev']}")
            if enc.get("server_routes"):
                how.append("los resolvers se alcanzan por el túnel")
            out.append(finding("dns_leak_config", "El DNS viaja por el túnel", "info", "pass", "pasiva",
                               "resolver efectivo + ip route get", ev,
                               f"Resolver efectivo: {labels}" + (f"; {'; '.join(how)}" if how else ""),
                               "Rutas observadas; aplicaciones con DNS propio (DoH del navegador) no se ven aquí.",
                               "media", "Ninguna."))
        # 2) ¿Se usa el DNS de la VPN o uno de terceros?
        third = [r for r in resolvers if r.get("provider") in ("Cloudflare WARP", "cloudflared proxy-dns")]
        if third:
            out.append(finding("dns_third_party", "El DNS no es el de la VPN: lo resuelve un tercero", "low", "warn",
                               "pasiva", "atribución del resolver efectivo", ev,
                               f"Las consultas las resuelve {third[0]['provider']} ({third[0].get('upstream') or '?'}), "
                               "no el resolver de la VPN",
                               "Cifrado y dentro del túnel, pero ese proveedor ve todos tus nombres consultados "
                               "(WARP los asocia además a tu registro de dispositivo).", "alta",
                               "Para separar identidades usa el DNS de la VPN (p. ej. desactiva el modo DoH de WARP) "
                               "o acepta conscientemente que Cloudflare vea tus consultas. Los filtros DNS de la VPN "
                               "(NetShield de Proton) no se aplican."))
    else:
        out.append(finding("dns_leak_config", "DNS directo (no hay túnel)", "info", "pass", "pasiva",
                           "resolver efectivo", ev, f"Resolver efectivo: {labels}",
                           "Sin túnel no hay fuga posible: tu ISP ya ve tu tráfico (el contenido DNS solo si va en claro).",
                           "alta", "Si usas Tor/proxy, resuelve los nombres en el proxy (SOCKS5h / torsocks)."))

    # 3) Cifrado
    encrypted = dns.get("encrypted")
    if encrypted is True:
        out.append(finding("dns_plaintext", "DNS cifrado", "info", "pass", "pasiva",
                           "atribución del resolver (warp-cli, procesos cloudflared/dnscrypt/stubby, flags de resolved)",
                           ev, labels, "Se identifica el cliente de cifrado; no se inspecciona el tráfico.", "alta",
                           "Ninguna."))
    elif encrypted is False:
        out.append(finding("dns_plaintext", "DNS sin cifrar", "low", "warn", "pasiva",
                           "atribución del resolver efectivo", ev, f"Resolver efectivo en claro: {labels}",
                           "No detecta DoH configurado dentro de aplicaciones salvo Firefox/Chromium.", "media",
                           "Activa DNSOverTLS en systemd-resolved, un proxy DoH local o DoH en el navegador."))
    else:
        out.append(finding("dns_plaintext", "Cifrado DNS no verificable", "info", "unknown", "pasiva",
                           "atribución del resolver efectivo", ev, f"Resolver local de origen desconocido: {labels}",
                           "No se pudo identificar qué programa atiende el resolver local.", "baja",
                           "Comprueba el resolver local manualmente."))
    for b in enc.get("browsers") or []:
        out.append(finding("dns_browser_doh", f"{b['browser']} usa su propio DoH", "info", "warn", "pasiva",
                           "preferencias del navegador", b, f"{b['mode']} → {b['uri']}",
                           "Ese navegador ignora el DNS del sistema.", "alta",
                           "Asegúrate de que su DoH es el que quieres para ese perfil."))
    if dns.get("split_dns"):
        out.append(finding("dns_split", "Split DNS activo", "info", "warn", "pasiva", "dominios ~ por enlace",
                           ev, f"Dominios enrutados por {', '.join(dns['split_dns'])}",
                           "Informativo.", "alta", "Revisa que los dominios enrutados son los esperados."))
    return out



def check_active_dns(result: dict, net: dict) -> dict:
    if not result.get("ok"):
        return finding("dns_leak_active", "Test activo de fugas DNS no completado", "info", "unknown", "activa",
                       "consultas únicas contra servidor autoritativo externo", result, result.get("error"),
                       "Requiere conectividad con el servicio de test.", "baja", "Reintenta más tarde.")
    resolvers = result.get("resolvers", [])
    ev = {**result}
    # Solo se marca como fuga si hay túnel y algún resolver coincide con el ASN de tu IP directa,
    # o si el servicio lo concluye. No se usa el país del resolver como criterio.
    concl = (result.get("service_conclusion") or "").lower()
    leak_by_service = "leak" in concl and "no " not in concl
    status = "fail" if leak_by_service and net["via_tunnel"].get("ipv4") else "pass"
    return finding("dns_leak_active", "Resolvers vistos desde Internet", "high" if status == "fail" else "info",
                   status, "activa", f"{len(resolvers)} resolvers observados por {result.get('service')}", ev,
                   ", ".join(f"{r['ip']} ({r.get('asn') or '?'})" for r in resolvers) or "ninguno",
                   "Depende de un servicio externo; el país del resolver NO indica fuga por sí mismo.", "media",
                   "Si aparecen resolvers de tu ISP con la VPN activa, fuerza el DNS de la VPN.")


def check_exposed_proxies(env: dict) -> list[dict]:
    out = []
    kinds = {p["port"]: p["kind"] for p in env["proxy"]["local"]}
    for l in env.get("listening", []):
        if l["port"] in kinds and not ipaddress.ip_address(l["addr"]).is_loopback:
            what = "Servidor web" if kinds[l["port"]] == "http-server" else "Proxy"
            out.append(finding("proxy_exposed", f"{what} en el puerto {l['port']} accesible desde la red", "medium",
                               "fail", "pasiva", "/proc/net/tcp + sondeo de loopback", l,
                               f"Escucha en {l['addr']}:{l['port']}" + (f" ({l['owner']})" if l.get("owner") else ""),
                               "No comprueba si el firewall lo bloquea desde fuera.", "alta",
                               "Haz que escuche solo en 127.0.0.1 o restringe el puerto en el firewall."))
    return out


def check_tor(tor: dict | None, env: dict, profile: dict) -> list[dict]:
    out = []
    for c in env["tor"]["control"]:
        if "NULL" in c["auth"]:
            out.append(finding("tor_control_auth", "ControlPort de Tor sin autenticación", "high", "fail", "pasiva",
                               "PROTOCOLINFO", c, "Cualquier proceso local puede controlar Tor",
                               "—", "alta", "Activa CookieAuthentication 1 en torrc."))
    if profile.get("use_tor"):
        if not tor or not tor.get("available"):
            out.append(finding("tor_required", "El perfil exige Tor y no está disponible", "high", "fail", "pasiva",
                               "control de Tor", tor, (tor or {}).get("error"), "—", "alta",
                               "Arranca el servicio tor o cambia de perfil."))
        elif not tor.get("circuit_established"):
            out.append(finding("tor_health", "Tor sin circuitos establecidos", "medium", "warn", "pasiva",
                               "GETINFO status/circuit-established", {"bootstrap": tor.get("bootstrap")},
                               f"bootstrap {tor.get('bootstrap')}%", "—", "alta", "Espera al bootstrap o revisa la red."))
    return out


def check_guard_churn(store, tor: dict | None = None, window: float = 86400) -> dict | None:
    """Tor usa varios guards primarios a la vez (y conflux usa dos por circuito): ver guards distintos en
    circuitos activos es normal. Solo se avisa de guards observados que NO están en la lista actual de
    entry-guards de Tor, que indicaría una rotación real de guards."""
    keys = {i["key"] for i in store.intervals("tor_guard", since=now() - window)}
    current = {g["fp"] for g in (tor or {}).get("guards") or []}
    churn = keys - current if current else set()
    if len(churn) >= 2:
        return finding("tor_guard_churn", "Cambios de guard de Tor", "medium", "warn", "pasiva",
                       "historial de intervalos tor_guard (24h) vs GETINFO entry-guards",
                       {"observed": sorted(keys), "current_guards": sorted(current), "rotated": sorted(churn)},
                       f"{len(churn)} guards usados en 24h ya no están en la lista de guards de Tor",
                       "Tor también sustituye guards caídos; varios cambios en un día sí son anómalos.",
                       "media", "No fuerces cambios de guard (no borres el estado de Tor ni uses EntryNodes): "
                                "rotarlos rápido facilita ataques de correlación.")
    return None

def check_profile(obs: dict, profile: dict, sys_tz: str | None) -> list[dict]:
    out = []
    pub = (obs.get("public_ip") or {}).get("geo") or {}
    tor_exit = ((obs.get("tor") or {}).get("exit") or {})
    countries = {c for c in (pub.get("country"), ((obs.get("vpn") or {}).get("geo") or {}).get("country")) if c}
    if profile.get("use_tor") and tor_exit.get("country"):
        countries.add(tor_exit["country"])         # en perfiles Tor, el exit también es salida
    for c in countries & set(profile.get("forbidden_countries") or []):
        out.append(finding("profile_geo", f"Salida por un país prohibido por el perfil: {c}", "high", "fail", "pasiva",
                           "GeoIP local de la IP de salida", {"country": c}, c,
                           "La geolocalización por IP es una estimación.", "media", "Rota la salida."))
    allowed = set(profile.get("allowed_countries") or [])
    if allowed:
        for c in countries - allowed:
            out.append(finding("profile_geo", f"Salida por {c}, fuera de los países permitidos", "high", "fail",
                               "pasiva", "GeoIP local", {"country": c, "allowed": sorted(allowed)}, c,
                               "Estimación GeoIP.", "media", "Rota la salida a un país permitido."))
    tz_cc = tz_country(sys_tz)
    vpn_cc = ((obs.get("vpn") or {}).get("geo") or {}).get("country")
    exit_cc = pub.get("country") or vpn_cc or tor_exit.get("country")
    if tz_cc and exit_cc and tz_cc != exit_cc:
        out.append(finding("tz_mismatch", "Zona horaria del sistema distinta del país de salida", "low", "warn",
                           "pasiva", "zona horaria local vs GeoIP de la salida",
                           {"timezone": sys_tz, "tz_country": tz_cc, "exit_country": exit_cc},
                           f"{sys_tz} ({tz_cc}) vs salida en {exit_cc}",
                           "Solo importa si las aplicaciones revelan la zona horaria (navegadores sí, Tor Browser no).",
                           "media", "Usa Tor Browser o alinea la zona horaria del navegador con la salida."))
    return out


def check_identity(env: dict) -> list[dict]:
    out = []
    for i in env["interfaces"]:
        if i["kind"] in discovery.PHYSICAL_KINDS and i["up"] and i["mac_origin"] == "permanente":
            out.append(finding("mac_permanent", f"{i['name']} usa la MAC de fábrica", "low", "warn", "pasiva",
                               "/sys/class/net/*/addr_assign_type", {"iface": i["name"]},
                               "MAC permanente visible en la red local",
                               "Solo es visible en el segmento local (router, WiFi).", "alta",
                               "Configura cloned-mac-address=random (WiFi) o stable en NetworkManager."))
    return out


def check_killswitch(net: dict, ks_state: dict, ext: dict | None = None) -> dict | None:
    ext = ext or {}
    rp = ext.get("route_protection") or {}
    clients = ext.get("clients") or []
    declared = [c for c in clients if c["client"] in (ext.get("declared_by") or [])]
    ev = {"route_protection": rp, "clients": clients, "own_killswitch": ks_state}
    names = ", ".join(c["client"] for c in declared) or "sin cliente identificado"
    modes = "; ".join(f"{c['client']}: {(c.get('declared') or {}).get('killswitch_mode') or (c.get('declared') or {})}"
                      for c in declared)
    if ks_state.get("active"):
        return finding("killswitch", "Kill-switch propio (nftables) activo", "info", "pass", "pasiva",
                       "estado de la tabla inet vela_ks", ev, f"activo desde {ks_state.get('since')}",
                       "—", "alta", "Ninguna.")
    if not net["tunnels"]:
        if ext.get("verified_ipv4"):
            return finding("killswitch", "Tráfico bloqueado sin túnel (kill-switch permanente)", "info", "pass",
                           "pasiva", "rutas por defecto sin túneles", ev, rp.get("ipv4", {}).get("detail"),
                           ext.get("limitations"), "alta", "Ninguna.")
        return None
    v4, v6 = ext.get("verified_ipv4"), ext.get("verified_ipv6")
    if v4 and (v6 or not net["egress"].get("ipv6")):
        rec = "Ninguna."
        if any((c.get("declared") or {}).get("killswitch") == 1 for c in declared):
            rec = ("Modo estándar: protege mientras la VPN está conectada o reconectando, no si cierras la app o "
                   "tras reiniciar. Usa el modo permanente en perfiles de alto riesgo.")
        return finding("killswitch", f"Kill-switch activo ({names})", "info", "pass", "pasiva",
                       "simulación de caída del túnel sobre la tabla de rutas + configuración del cliente", ev,
                       f"Si el túnel cae: IPv4 {rp['ipv4']['detail']}; IPv6 {rp['ipv6']['detail']}"
                       + (f". Declarado: {modes}" if modes else ""),
                       ext.get("limitations"), "alta", rec)
    if v4 and not v6:
        return finding("killswitch", "Kill-switch solo en IPv4", "medium", "warn", "pasiva",
                       "simulación de caída del túnel sobre la tabla de rutas", ev,
                       f"IPv6 {rp['ipv6']['detail']}", ext.get("limitations"), "alta",
                       "Activa la protección IPv6 del cliente VPN o desactiva IPv6 en la interfaz física.")
    if declared:
        return finding("killswitch", f"Kill-switch declarado pero no verificado ({names})", "medium", "warn", "pasiva",
                       "configuración del cliente vs tabla de rutas", ev,
                       f"Declarado: {modes}. Pero si el túnel cae: IPv4 {rp.get('ipv4', {}).get('detail')}",
                       "Puede estar implementado con reglas de firewall que no se leen sin root.", "media",
                       "Compruébalo desconectando la VPN de forma controlada.")
    return finding("killswitch", "Túnel sin kill-switch", "medium", "warn", "pasiva",
                   "simulación de caída del túnel sobre la tabla de rutas", ev,
                   f"Si el túnel cae, IPv4 {rp.get('ipv4', {}).get('detail', 'saldría por la ruta directa')}",
                   ext.get("limitations") or "No detecta kill-switches hechos solo con firewall.", "media",
                   "Activa el kill-switch del cliente VPN o `vela killswitch apply`.")



def check_profile_policy(ctx: dict) -> list[dict]:
    """Políticas del perfil activo: VPN, kill-switch y DNS obligatorios."""
    out = []
    p, net, dns = ctx["profile"], ctx["net"], ctx["dns"]
    name = ctx.get("profile_name") or "activo"
    ext = ctx.get("killswitch_ext") or {}
    if p.get("require_killswitch") and not ((ctx.get("killswitch") or {}).get("active") or
                                             (net["tunnels"] and ext.get("verified_ipv4"))):
        out.append(finding("profile_killswitch", f"El perfil «{name}» exige kill-switch y no hay uno verificado",
                           "high", "fail", "pasiva", "estado de kill-switch propio y de terceros", ext.get("route_protection"),
                           "sin kill-switch verificado", ext.get("limitations") or "—", "media",
                           "Activa el kill-switch del cliente VPN antes de operar con este perfil."))
    policy = p.get("dns_policy", "any")
    enc = dns.get("encrypted")
    tunnels = set(net["tunnels"])
    if policy in ("encrypted", "vpn") and enc is False:
        out.append(finding("profile_dns", f"El perfil «{name}» exige DNS cifrado", "high", "fail", "pasiva",
                           "atribución del resolver efectivo", dns.get("encryption"), "DNS en claro", "—", "media",
                           "Activa DoH/DoT antes de operar con este perfil."))
    if policy == "vpn":
        routes = (dns.get("encryption") or {}).get("server_routes") or {}
        up = (dns.get("encryption") or {}).get("upstream_route") or {}
        devs = set(routes.values()) | ({up.get("dev")} if up.get("dev") else set())
        if not net["via_tunnel"].get("ipv4") or (devs and not devs <= tunnels):
            out.append(finding("profile_dns", f"El perfil «{name}» exige que el DNS vaya por la VPN", "high", "fail",
                               "pasiva", "ip route get hacia los resolvers", {"devs": sorted(d for d in devs if d)},
                               f"DNS por {', '.join(sorted(d for d in devs if d)) or 'ruta directa'}", "—", "media",
                               "Usa el DNS de la VPN o enruta el DoH por el túnel."))
    if policy == "tor" and not (ctx.get("tor") or {}).get("available"):
        out.append(finding("profile_dns", f"El perfil «{name}» resuelve por Tor y Tor no está disponible", "high", "fail",
                           "pasiva", "estado de Tor", None, "Tor no disponible", "—", "alta",
                           "Arranca Tor; usa SOCKS5h/torsocks para que Tor resuelva los nombres."))
    return out


def check_networks(inv: dict | None) -> list[dict]:
    out = []
    if not inv:
        return out
    for i in inv["interfaces"]:
        w = i.get("wifi") or {}
        if w and w.get("security") in ("abierta", "--", ""):
            out.append(finding("wifi_open", f"WiFi abierta: {w.get('ssid')}", "high", "fail", "pasiva",
                               "nmcli device wifi (caché, sin escanear)", w, "red sin cifrado",
                               "—", "alta", "Usa la VPN con kill-switch antes de cualquier tráfico en esta red."))
    for v in inv.get("libvirt") or []:
        if v["isolation_broken"] and v["active"]:
            out.append(finding("vm_isolation", f"Red de VM «{v['name']}» no está aislada", "high", "fail", "pasiva",
                               "virsh net-dumpxml (modo forward)", v, f"forward={v['forward']}",
                               "Se deduce del nombre que debería estar aislada; revisa si es intencionado.", "media",
                               "Quita el <forward> de la red (virsh net-edit) para aislarla del exterior."))
    return out


def check_realtime(lw: dict | None, public: dict | None, profile: dict) -> list[dict]:
    """Fugas observadas en tiempo real (tabla de sockets) y verificación de la IP pública."""
    out = []
    if lw:
        leaks = [f for f in lw.get("flows", []) if f["verdict"] == "fuga"]
        if leaks:
            procs = sorted({f["process"] for f in leaks})
            out.append(finding("ip_leak_live", f"{len(leaks)} conexiones salen por fuera del túnel ({', '.join(procs[:5])})",
                               "critical", "fail", "pasiva",
                               "tabla de sockets del kernel (/proc/net) + interfaz de la IP local, cada 2 s",
                               {"flows": [{k: f[k] for k in ("process", "pid", "proto", "local", "remote", "rport", "iface")}
                                          for f in leaks[:30]]},
                               "; ".join(f"{f['process']} → {f['remote']}:{f['rport']} por {f['iface']}" for f in leaks[:6]),
                               "Sondeo periódico: conexiones de < 2 s pueden no verse; no ve otros network namespaces.",
                               "alta", "Activa un kill-switch que bloquee todo lo que no vaya por el túnel."))
        elif lw.get("tunnel_up"):
            out.append(finding("ip_leak_live", "Ninguna conexión sale por fuera del túnel", "info", "pass", "pasiva",
                               "tabla de sockets del kernel cada 2 s", lw.get("summary"),
                               f"{lw['summary'].get('protegidas', 0)} conexiones protegidas",
                               "Sondeo periódico; conexiones muy breves pueden escaparse a la observación.", "media",
                               "Ninguna."))
        directas = [f for f in lw.get("flows", []) if f["verdict"] == "directa"]
        if directas and not lw.get("tunnel_up"):
            procs = sorted({f["process"] for f in directas})
            out.append(finding("direct_exposure", f"{len(directas)} conexiones muestran tu IP real (sin VPN)",
                               "high" if profile.get("require_vpn") else "medium",
                               "fail" if profile.get("require_vpn") else "warn", "pasiva",
                               "tabla de sockets del kernel", {"processes": procs},
                               "Programas: " + ", ".join(procs[:10]),
                               "Sin túnel no hay 'fuga' técnica: todo sale con tu IP real.", "alta",
                               "Conecta la VPN; con el kill-switch permanente ninguna conexión saldría sin ella."))
    pub = (public or {}).get("default") or {}
    if pub.get("ok") and pub.get("via_tunnel"):
        if pub.get("is_real_ip"):
            out.append(finding("public_real_ip", "Internet ve tu IP real con la VPN conectada", "critical", "fail",
                               "activa", f"eco de IP ({pub.get('endpoint')}) comparado con tus IPs reales conocidas",
                               pub, pub["ip"], "Depende de conocer tu IP real (known_real_ips / learn_real_ip).",
                               "alta", "Desconecta y revisa la VPN: el tráfico no pasa por el túnel."))
        else:
            mm = pub.get("country_mismatch")
            out.append(finding("public_real_ip", "La IP que ve Internet es la de la VPN", "info" if not mm else "low",
                               "pass" if not mm else "warn", "activa",
                               f"eco de IP ({pub.get('endpoint')}) cada {pub.get('interval', '60s')} por el túnel", pub,
                               f"{pub['ip']} ({(pub.get('geo') or {}).get('country') or '?'})"
                               + (f" — se esperaba {mm['expected']}" if mm else ""),
                               "Solo se puede afirmar que no es tu IP real si la conoces (known_real_ips / learn_real_ip)."
                               if not pub.get("own_known") else "—", "media" if not pub.get("own_known") else "alta",
                               "Ninguna." if not mm else "La GeoIP local puede estar desfasada; verifica el servidor."))
    return out


def run_passive(ctx: dict) -> list[dict]:
    """ctx: net, dns, tor, env, profile, obs, store, killswitch, killswitch_ext, timezone."""
    out = [check_ipv6(ctx["net"]), check_tunnel_route(ctx["net"], ctx["profile"])]
    out += check_dns(ctx["net"], ctx["dns"])
    out += check_exposed_proxies(ctx["env"])
    out += check_tor(ctx.get("tor"), ctx["env"], ctx["profile"])
    g = check_guard_churn(ctx["store"], ctx.get("tor")) if ctx.get("store") else None
    if g:
        out.append(g)
    out += check_profile(ctx["obs"], ctx["profile"], ctx.get("timezone"))
    out += check_profile_policy(ctx)
    out += check_identity(ctx["env"])
    out += check_networks(ctx.get("networks"))
    out += check_realtime(ctx.get("leakwatch"), ctx.get("public"), ctx["profile"])
    k = check_killswitch(ctx["net"], ctx.get("killswitch") or {}, ctx.get("killswitch_ext"))
    if k:
        out.append(k)
    return sorted(out, key=lambda f: -SEV_ORDER[f["severity"]])



def webrtc_finding(candidates: list[str], local_ips: list[str], public_ips: list[str], used_stun: bool) -> dict:
    """Evalúa candidatos ICE recogidos por la página de prueba de la GUI."""
    seen = set()
    for c in candidates:
        parts = c.split()
        if len(parts) > 5:
            seen.add(parts[4])
    exposed_local = sorted(ip for ip in seen if ip in local_ips)
    exposed_public = sorted(ip for ip in seen if ip in public_ips)
    mdns = sorted(ip for ip in seen if ip.endswith(".local"))
    status = "fail" if exposed_local or exposed_public else "pass"
    return finding("webrtc", "Exposición de IPs por WebRTC en el navegador", "medium" if status == "fail" else "info",
                   status, "activa", "RTCPeerConnection en la página local de la GUI" + (" + STUN" if used_stun else ""),
                   {"candidates": sorted(seen), "mdns": mdns}, f"IPs locales expuestas: {exposed_local or 'ninguna'}; "
                   f"públicas: {exposed_public or 'ninguna'}; mDNS: {len(mdns)}",
                   "Solo prueba el navegador con el que abriste la GUI." + ("" if used_stun else
                   " Sin STUN no se observa la IP pública (candidatos srflx)."), "media",
                   "Desactiva WebRTC o limita los candidatos (media.peerconnection.ice.default_address_only).")
