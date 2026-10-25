"""Detección de fugas y validación OPSEC.

Cada diagnóstico es un dict con: check, title, severity, status (pass/fail/warn/unknown),
mode (pasiva/activa), method, evidence, observed, limitations, confidence, recommendation, ts.

Reglas de prudencia:
  * Nunca se declara fuga DNS solo porque el resolver esté en otro país que la VPN/proxy.
  * Si algo no se puede comprobar, el estado es "unknown" con su limitación, no "pass".
"""

from __future__ import annotations

from .i18n import _

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
        return finding("ipv6_leak", _("IPv6 bloqueado por el kill-switch"), "info", "pass", "pasiva",
                       _("ip route get (IPv6) + tipo de interfaz"), ev,
                       _("El tráfico IPv6 va a la interfaz de bloqueo {dev}: no sale a Internet", dev=e6['dev']),
                       _("Basado en la tabla de rutas."), "alta", "Ninguna.")
    if v4_tunnel and e6 and not net["via_tunnel"].get("ipv6") and net["ipv6_internet"]:
        return finding("ipv6_leak", _("Fuga IPv6 fuera del túnel"), "high", "fail", "pasiva",
                       _("ip route get (IPv4 vs IPv6) + direcciones globales de la interfaz"), ev,
                       _("IPv4 sale por {dev} (túnel) pero IPv6 sale por {dev2}", dev=net['egress']['ipv4']['dev'], dev2=e6['dev']),
                       _("Basado en la tabla de rutas; no detecta reglas de firewall que bloqueen IPv6."), "alta",
                       _("Desactiva IPv6 en la interfaz física o configura la VPN para que capture ::/0."))
    if not e6:
        return finding("ipv6_leak", _("Sin ruta IPv6 a Internet"), "info", "pass", "pasiva", _("ip route get"), ev,
                       _("No hay ruta IPv6 por defecto: no puede haber fuga IPv6."), _("Estado en este instante."),
                       "alta", "Ninguna.")
    return finding("ipv6_leak", _("IPv6 coherente con la ruta IPv4"), "info", "pass", "pasiva", _("ip route get"), ev,
                   _("IPv6 sigue el mismo camino que IPv4 o no hay túnel que evitar."), _("Estado en este instante."),
                   "media", "Ninguna.")



def check_tunnel_route(net: dict, profile: dict) -> dict:
    expects_vpn = bool(profile.get("require_vpn") or profile.get("preferred_vpn"))
    ev = {"tunnels": net["tunnels"], "egress": net["egress"].get("ipv4"), "policy_rules": len(net["policy_rules"])}
    via = net["via_tunnel"].get("ipv4")
    if expects_vpn and not via:
        return finding("tunnel_bypass", _("El tráfico no pasa por la VPN que exige el perfil"), "high", "fail",
                       "pasiva", _("ip route get 1.1.1.1 (respeta policy routing)"), ev,
                       _("La ruta por defecto sale por {v1}", v1=(net['egress'].get('ipv4') or {}).get('dev')),
                       _("No inspecciona tráfico de aplicaciones con sus propias rutas o namespaces."), "alta",
                       _("Conecta la VPN del perfil o activa el kill-switch antes de seguir operando."))
    if net["tunnels"] and not via:
        return finding("tunnel_bypass", _("Túnel activo pero la ruta por defecto no lo usa"), "medium", "warn",
                       "pasiva", _("ip route get + interfaces de túnel"), ev,
                       _("Túneles {tunnels} activos; salida por {v3}", tunnels=net['tunnels'], v3=(net['egress'].get('ipv4') or {}).get('dev')),
                       _("Puede ser split-tunnel intencionado."), "media",
                       _("Verifica que el split-tunnel es intencionado."))
    if via:
        return finding("tunnel_bypass", _("El tráfico IPv4 sale por el túnel"), "info", "pass", "pasiva",
                       _("ip route get"), ev, _("Salida por {dev}", dev=net['egress']['ipv4']['dev']),
                       _("Ruta del kernel; no garantiza que el túnel cifre ni a dónde lleva."), "alta", "Ninguna.")
    return finding("tunnel_bypass", _("Conexión directa (sin VPN)"), "info", "pass" if not expects_vpn else "fail",
                   "pasiva", _("ip route get"), ev, _("No hay túnel y el perfil no lo exige."),
                   "—", "alta", _("Si necesitas ocultar tu IP al destino usa VPN, proxy o Tor."))


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
    labels = ", ".join(_resolver_label(r) for r in resolvers) or ", ".join(dns.get("effective_servers") or []) or _("ninguno")

    if net["via_tunnel"].get("ipv4"):
        # 1) ¿Por dónde viajan realmente las consultas?
        outside = []
        for srv, dev in (enc.get("server_routes") or {}).items():
            if dev and dev not in tunnels:
                outside.append(f"{srv} por {dev}")
        up = enc.get("upstream_route")
        if up and up.get("dev") and up["dev"] not in tunnels:
            outside.append(_("DoH hacia {ip} por {dev}", ip=up['ip'], dev=up['dev']))
        if dns.get("effective_source") == "systemd-resolved":
            for l in dns.get("default_links", []):
                if l not in tunnels:
                    outside.append(_("resolvers del enlace {l}: {v3}", l=l, v3=' '.join(dns['links'][l]['servers'])))
        if outside:
            out.append(finding("dns_leak_config", _("Consultas DNS que salen fuera del túnel"), "high", "fail", "pasiva",
                               _("resolver efectivo + ip route get hacia cada resolver/servidor DoH"), ev,
                               "; ".join(outside),
                               _("Configuración y rutas observadas; confírmalo con el test activo."), "media",
                               _("Haz que el DNS use el túnel (DNS de la VPN o DoH enrutado por el túnel).")))
        else:
            how = []
            if up:
                how.append(_("la conexión DoH a {ip} sale por {dev}", ip=up['ip'], dev=up['dev']))
            if enc.get("server_routes"):
                how.append(_("los resolvers se alcanzan por el túnel"))
            out.append(finding("dns_leak_config", _("El DNS viaja por el túnel"), "info", "pass", "pasiva",
                               _("resolver efectivo + ip route get"), ev,
                               _("Resolver efectivo: {labels}", labels=labels) + (f"; {'; '.join(how)}" if how else ""),
                               _("Rutas observadas; aplicaciones con DNS propio (DoH del navegador) no se ven aquí."),
                               "media", "Ninguna."))
        # 2) ¿Se usa el DNS de la VPN o uno de terceros?
        third = [r for r in resolvers if r.get("provider") in ("Cloudflare WARP", "cloudflared proxy-dns")]
        if third:
            out.append(finding("dns_third_party", _("El DNS no es el de la VPN: lo resuelve un tercero"), "low", "warn",
                               "pasiva", _("atribución del resolver efectivo"), ev,
                               _("Las consultas las resuelve {provider} ({v3}), no el resolver de la VPN", provider=third[0]['provider'], v3=third[0].get('upstream') or '?'),
                               _("Cifrado y dentro del túnel, pero ese proveedor ve todos tus nombres consultados "
                               "(WARP los asocia además a tu registro de dispositivo)."), "alta",
                               _("Para separar identidades usa el DNS de la VPN (p. ej. desactiva el modo DoH de WARP) "
                               "o acepta conscientemente que Cloudflare vea tus consultas. Los filtros DNS de la VPN "
                               "(NetShield de Proton) no se aplican.")))
    else:
        out.append(finding("dns_leak_config", _("DNS directo (no hay túnel)"), "info", "pass", "pasiva",
                           _("resolver efectivo"), ev, _("Resolver efectivo: {labels}", labels=labels),
                           _("Sin túnel no hay fuga posible: tu ISP ya ve tu tráfico (el contenido DNS solo si va en claro)."),
                           "alta", _("Si usas Tor/proxy, resuelve los nombres en el proxy (SOCKS5h / torsocks).")))

    # 3) Cifrado
    encrypted = dns.get("encrypted")
    if encrypted is True:
        out.append(finding("dns_plaintext", _("DNS cifrado"), "info", "pass", "pasiva",
                           _("atribución del resolver (warp-cli, procesos cloudflared/dnscrypt/stubby, flags de resolved)"),
                           ev, labels, _("Se identifica el cliente de cifrado; no se inspecciona el tráfico."), "alta",
                           "Ninguna."))
    elif encrypted is False:
        out.append(finding("dns_plaintext", _("DNS sin cifrar"), "low", "warn", "pasiva",
                           _("atribución del resolver efectivo"), ev, _("Resolver efectivo en claro: {labels}", labels=labels),
                           _("No detecta DoH configurado dentro de aplicaciones salvo Firefox/Chromium."), "media",
                           _("Activa DNSOverTLS en systemd-resolved, un proxy DoH local o DoH en el navegador.")))
    else:
        out.append(finding("dns_plaintext", _("Cifrado DNS no verificable"), "info", "unknown", "pasiva",
                           _("atribución del resolver efectivo"), ev, _("Resolver local de origen desconocido: {labels}", labels=labels),
                           _("No se pudo identificar qué programa atiende el resolver local."), "baja",
                           _("Comprueba el resolver local manualmente.")))
    for b in enc.get("browsers") or []:
        out.append(finding("dns_browser_doh", _("{browser} usa su propio DoH", browser=b['browser']), "info", "warn", "pasiva",
                           _("preferencias del navegador"), b, f"{b['mode']} → {b['uri']}",
                           _("Ese navegador ignora el DNS del sistema."), "alta",
                           _("Asegúrate de que su DoH es el que quieres para ese perfil.")))
    if dns.get("split_dns"):
        out.append(finding("dns_split", _("Split DNS activo"), "info", "warn", "pasiva", _("dominios ~ por enlace"),
                           ev, _("Dominios enrutados por {v1}", v1=', '.join(dns['split_dns'])),
                           "Informativo.", "alta", _("Revisa que los dominios enrutados son los esperados.")))
    return out



def check_active_dns(result: dict, net: dict) -> dict:
    if not result.get("ok"):
        return finding("dns_leak_active", _("Test activo de fugas DNS no completado"), "info", "unknown", "activa",
                       _("consultas únicas contra servidor autoritativo externo"), result, result.get("error"),
                       _("Requiere conectividad con el servicio de test."), "baja", _("Reintenta más tarde."))
    resolvers = result.get("resolvers", [])
    ev = {**result}
    # Solo se marca como fuga si hay túnel y algún resolver coincide con el ASN de tu IP directa,
    # o si el servicio lo concluye. No se usa el país del resolver como criterio.
    concl = (result.get("service_conclusion") or "").lower()
    leak_by_service = "leak" in concl and "no " not in concl
    status = "fail" if leak_by_service and net["via_tunnel"].get("ipv4") else "pass"
    return finding("dns_leak_active", _("Resolvers vistos desde Internet"), "high" if status == "fail" else "info",
                   status, "activa", _("{n} resolvers observados por {v2}", n=len(resolvers), v2=result.get('service')), ev,
                   ", ".join(f"{r['ip']} ({r.get('asn') or '?'})" for r in resolvers) or _("ninguno"),
                   _("Depende de un servicio externo; el país del resolver NO indica fuga por sí mismo."), "media",
                   _("Si aparecen resolvers de tu ISP con la VPN activa, fuerza el DNS de la VPN."))


def check_exposed_proxies(env: dict) -> list[dict]:
    out = []
    kinds = {p["port"]: p["kind"] for p in env["proxy"]["local"]}
    for l in env.get("listening", []):
        if l["port"] in kinds and not ipaddress.ip_address(l["addr"]).is_loopback:
            what = _("Servidor web") if kinds[l["port"]] == "http-server" else "Proxy"
            out.append(finding("proxy_exposed", _("{what} en el puerto {port} accesible desde la red", what=what, port=l['port']), "medium",
                               "fail", "pasiva", _("/proc/net/tcp + sondeo de loopback"), l,
                               _("Escucha en {addr}:{port}", addr=l['addr'], port=l['port']) + (f" ({l['owner']})" if l.get("owner") else ""),
                               _("No comprueba si el firewall lo bloquea desde fuera."), "alta",
                               _("Haz que escuche solo en 127.0.0.1 o restringe el puerto en el firewall.")))
    return out


def check_tor(tor: dict | None, env: dict, profile: dict) -> list[dict]:
    out = []
    for c in env["tor"]["control"]:
        if "NULL" in c["auth"]:
            out.append(finding("tor_control_auth", _("ControlPort de Tor sin autenticación"), "high", "fail", "pasiva",
                               "PROTOCOLINFO", c, _("Cualquier proceso local puede controlar Tor"),
                               "—", "alta", _("Activa CookieAuthentication 1 en torrc.")))
    if profile.get("use_tor"):
        if not tor or not tor.get("available"):
            out.append(finding("tor_required", _("El perfil exige Tor y no está disponible"), "high", "fail", "pasiva",
                               _("control de Tor"), tor, (tor or {}).get("error"), "—", "alta",
                               _("Arranca el servicio tor o cambia de perfil.")))
        elif not tor.get("circuit_established"):
            out.append(finding("tor_health", _("Tor sin circuitos establecidos"), "medium", "warn", "pasiva",
                               _("GETINFO status/circuit-established"), {"bootstrap": tor.get("bootstrap")},
                               f"bootstrap {tor.get('bootstrap')}%", "—", "alta", _("Espera al bootstrap o revisa la red.")))
    return out


def check_guard_churn(store, tor: dict | None = None, window: float = 86400) -> dict | None:
    """Tor usa varios guards primarios a la vez (y conflux usa dos por circuito): ver guards distintos en
    circuitos activos es normal. Solo se avisa de guards observados que NO están en la lista actual de
    entry-guards de Tor, que indicaría una rotación real de guards."""
    keys = {i["key"] for i in store.intervals("tor_guard", since=now() - window)}
    current = {g["fp"] for g in (tor or {}).get("guards") or []}
    churn = keys - current if current else set()
    if len(churn) >= 2:
        return finding("tor_guard_churn", _("Cambios de guard de Tor"), "medium", "warn", "pasiva",
                       _("historial de intervalos tor_guard (24h) vs GETINFO entry-guards"),
                       {"observed": sorted(keys), "current_guards": sorted(current), "rotated": sorted(churn)},
                       _("{n} guards usados en 24h ya no están en la lista de guards de Tor", n=len(churn)),
                       _("Tor también sustituye guards caídos; varios cambios en un día sí son anómalos."),
                       "media", _("No fuerces cambios de guard (no borres el estado de Tor ni uses EntryNodes): "
                                "rotarlos rápido facilita ataques de correlación."))
    return None

def check_profile(obs: dict, profile: dict, sys_tz: str | None) -> list[dict]:
    out = []
    pub = (obs.get("public_ip") or {}).get("geo") or {}
    tor_exit = ((obs.get("tor") or {}).get("exit") or {})
    countries = {c for c in (pub.get("country"), ((obs.get("vpn") or {}).get("geo") or {}).get("country")) if c}
    if profile.get("use_tor") and tor_exit.get("country"):
        countries.add(tor_exit["country"])         # en perfiles Tor, el exit también es salida
    for c in countries & set(profile.get("forbidden_countries") or []):
        out.append(finding("profile_geo", _("Salida por un país prohibido por el perfil: {c}", c=c), "high", "fail", "pasiva",
                           _("GeoIP local de la IP de salida"), {"country": c}, c,
                           _("La geolocalización por IP es una estimación."), "media", _("Rota la salida.")))
    allowed = set(profile.get("allowed_countries") or [])
    if allowed:
        for c in countries - allowed:
            out.append(finding("profile_geo", _("Salida por {c}, fuera de los países permitidos", c=c), "high", "fail",
                               "pasiva", _("GeoIP local"), {"country": c, "allowed": sorted(allowed)}, c,
                               _("Estimación GeoIP."), "media", _("Rota la salida a un país permitido.")))
    tz_cc = tz_country(sys_tz)
    vpn_cc = ((obs.get("vpn") or {}).get("geo") or {}).get("country")
    exit_cc = pub.get("country") or vpn_cc or tor_exit.get("country")
    if tz_cc and exit_cc and tz_cc != exit_cc:
        out.append(finding("tz_mismatch", _("Zona horaria del sistema distinta del país de salida"), "low", "warn",
                           "pasiva", _("zona horaria local vs GeoIP de la salida"),
                           {"timezone": sys_tz, "tz_country": tz_cc, "exit_country": exit_cc},
                           _("{sys_tz} ({tz_cc}) vs salida en {exit_cc}", sys_tz=sys_tz, tz_cc=tz_cc, exit_cc=exit_cc),
                           _("Solo importa si las aplicaciones revelan la zona horaria (navegadores sí, Tor Browser no)."),
                           "media", _("Usa Tor Browser o alinea la zona horaria del navegador con la salida.")))
    return out


def check_identity(env: dict) -> list[dict]:
    out = []
    for i in env["interfaces"]:
        if i["kind"] in discovery.PHYSICAL_KINDS and i["up"] and i["mac_origin"] == "permanente":
            out.append(finding("mac_permanent", _("{name} usa la MAC de fábrica", name=i['name']), "low", "warn", "pasiva",
                               "/sys/class/net/*/addr_assign_type", {"iface": i["name"]},
                               _("MAC permanente visible en la red local"),
                               _("Solo es visible en el segmento local (router, WiFi)."), "alta",
                               _("Configura cloned-mac-address=random (WiFi) o stable en NetworkManager.")))
    return out


def check_killswitch(net: dict, ks_state: dict, ext: dict | None = None) -> dict | None:
    ext = ext or {}
    rp = ext.get("route_protection") or {}
    clients = ext.get("clients") or []
    declared = [c for c in clients if c["client"] in (ext.get("declared_by") or [])]
    ev = {"route_protection": rp, "clients": clients, "own_killswitch": ks_state}
    names = ", ".join(c["client"] for c in declared) or _("sin cliente identificado")
    modes = "; ".join(f"{c['client']}: {(c.get('declared') or {}).get('killswitch_mode') or (c.get('declared') or {})}"
                      for c in declared)
    if ks_state.get("active"):
        return finding("killswitch", _("Kill-switch propio (nftables) activo"), "info", "pass", "pasiva",
                       _("estado de la tabla inet vela_ks"), ev, _("activo desde {v1}", v1=ks_state.get('since')),
                       "—", "alta", "Ninguna.")
    if not net["tunnels"]:
        if ext.get("verified_ipv4"):
            return finding("killswitch", _("Tráfico bloqueado sin túnel (kill-switch permanente)"), "info", "pass",
                           "pasiva", _("rutas por defecto sin túneles"), ev, rp.get("ipv4", {}).get("detail"),
                           ext.get("limitations"), "alta", "Ninguna.")
        return None
    v4, v6 = ext.get("verified_ipv4"), ext.get("verified_ipv6")
    if v4 and (v6 or not net["egress"].get("ipv6")):
        rec = "Ninguna."
        if any((c.get("declared") or {}).get("killswitch") == 1 for c in declared):
            rec = (_("Modo estándar: protege mientras la VPN está conectada o reconectando, no si cierras la app o "
                   "tras reiniciar. Usa el modo permanente en perfiles de alto riesgo."))
        return finding("killswitch", _("Kill-switch activo ({names})", names=names), "info", "pass", "pasiva",
                       _("simulación de caída del túnel sobre la tabla de rutas + configuración del cliente"), ev,
                       _("Si el túnel cae: IPv4 {detail}; IPv6 {detail2}", detail=rp['ipv4']['detail'], detail2=rp['ipv6']['detail'])
                       + (f". Declarado: {modes}" if modes else ""),
                       ext.get("limitations"), "alta", rec)
    if v4 and not v6:
        return finding("killswitch", _("Kill-switch solo en IPv4"), "medium", "warn", "pasiva",
                       _("simulación de caída del túnel sobre la tabla de rutas"), ev,
                       f"IPv6 {rp['ipv6']['detail']}", ext.get("limitations"), "alta",
                       _("Activa la protección IPv6 del cliente VPN o desactiva IPv6 en la interfaz física."))
    if declared:
        return finding("killswitch", _("Kill-switch declarado pero no verificado ({names})", names=names), "medium", "warn", "pasiva",
                       _("configuración del cliente vs tabla de rutas"), ev,
                       _("Declarado: {modes}. Pero si el túnel cae: IPv4 {v3}", modes=modes, v3=rp.get('ipv4', {}).get('detail')),
                       _("Puede estar implementado con reglas de firewall que no se leen sin root."), "media",
                       _("Compruébalo desconectando la VPN de forma controlada."))
    return finding("killswitch", _("Túnel sin kill-switch"), "medium", "warn", "pasiva",
                   _("simulación de caída del túnel sobre la tabla de rutas"), ev,
                   _("Si el túnel cae, IPv4 {v1}", v1=rp.get('ipv4', {}).get('detail', _('saldría por la ruta directa'))),
                   ext.get("limitations") or _("No detecta kill-switches hechos solo con firewall."), "media",
                   _("Activa el kill-switch del cliente VPN o `vela killswitch apply`."))



def check_profile_policy(ctx: dict) -> list[dict]:
    """Políticas del perfil activo: VPN, kill-switch y DNS obligatorios."""
    out = []
    p, net, dns = ctx["profile"], ctx["net"], ctx["dns"]
    name = ctx.get("profile_name") or "activo"
    ext = ctx.get("killswitch_ext") or {}
    if p.get("require_killswitch") and not ((ctx.get("killswitch") or {}).get("active") or
                                             (net["tunnels"] and ext.get("verified_ipv4"))):
        out.append(finding("profile_killswitch", _("El perfil «{name}» exige kill-switch y no hay uno verificado", name=name),
                           "high", "fail", "pasiva", _("estado de kill-switch propio y de terceros"), ext.get("route_protection"),
                           _("sin kill-switch verificado"), ext.get("limitations") or "—", "media",
                           _("Activa el kill-switch del cliente VPN antes de operar con este perfil.")))
    policy = p.get("dns_policy", "any")
    enc = dns.get("encrypted")
    tunnels = set(net["tunnels"])
    if policy in ("encrypted", "vpn") and enc is False:
        out.append(finding("profile_dns", _("El perfil «{name}» exige DNS cifrado", name=name), "high", "fail", "pasiva",
                           _("atribución del resolver efectivo"), dns.get("encryption"), _("DNS en claro"), "—", "media",
                           _("Activa DoH/DoT antes de operar con este perfil.")))
    if policy == "vpn":
        routes = (dns.get("encryption") or {}).get("server_routes") or {}
        up = (dns.get("encryption") or {}).get("upstream_route") or {}
        devs = set(routes.values()) | ({up.get("dev")} if up.get("dev") else set())
        if not net["via_tunnel"].get("ipv4") or (devs and not devs <= tunnels):
            out.append(finding("profile_dns", _("El perfil «{name}» exige que el DNS vaya por la VPN", name=name), "high", "fail",
                               "pasiva", _("ip route get hacia los resolvers"), {"devs": sorted(d for d in devs if d)},
                               _("DNS por {v1}", v1=', '.join(sorted(d for d in devs if d)) or 'ruta directa'), "—", "media",
                               _("Usa el DNS de la VPN o enruta el DoH por el túnel.")))
    if policy == "tor" and not (ctx.get("tor") or {}).get("available"):
        out.append(finding("profile_dns", _("El perfil «{name}» resuelve por Tor y Tor no está disponible", name=name), "high", "fail",
                           "pasiva", _("estado de Tor"), None, _("Tor no disponible"), "—", "alta",
                           _("Arranca Tor; usa SOCKS5h/torsocks para que Tor resuelva los nombres.")))
    return out


def check_networks(inv: dict | None) -> list[dict]:
    out = []
    if not inv:
        return out
    for i in inv["interfaces"]:
        w = i.get("wifi") or {}
        if w and w.get("security") in ("abierta", "--", ""):
            out.append(finding("wifi_open", _("WiFi abierta: {v1}", v1=w.get('ssid')), "high", "fail", "pasiva",
                               _("nmcli device wifi (caché, sin escanear)"), w, _("red sin cifrado"),
                               "—", "alta", _("Usa la VPN con kill-switch antes de cualquier tráfico en esta red.")))
    for v in inv.get("libvirt") or []:
        if v["isolation_broken"] and v["active"]:
            out.append(finding("vm_isolation", _("Red de VM «{name}» no está aislada", name=v['name']), "high", "fail", "pasiva",
                               _("virsh net-dumpxml (modo forward)"), v, f"forward={v['forward']}",
                               _("Se deduce del nombre que debería estar aislada; revisa si es intencionado."), "media",
                               _("Quita el <forward> de la red (virsh net-edit) para aislarla del exterior.")))
    return out


def check_realtime(lw: dict | None, public: dict | None, profile: dict) -> list[dict]:
    """Fugas observadas en tiempo real (tabla de sockets) y verificación de la IP pública."""
    out = []
    if lw:
        leaks = [f for f in lw.get("flows", []) if f["verdict"] == "fuga"]
        if leaks:
            procs = sorted({f["process"] for f in leaks})
            out.append(finding("ip_leak_live", _("{n} conexiones salen por fuera del túnel ({v2})", n=len(leaks), v2=', '.join(procs[:5])),
                               "critical", "fail", "pasiva",
                               _("tabla de sockets del kernel (/proc/net) + interfaz de la IP local, cada 2 s"),
                               {"flows": [{k: f[k] for k in ("process", "pid", "proto", "local", "remote", "rport", "iface")}
                                          for f in leaks[:30]]},
                               "; ".join(f"{f['process']} → {f['remote']}:{f['rport']} por {f['iface']}" for f in leaks[:6]),
                               _("Sondeo periódico: conexiones de < 2 s pueden no verse; no ve otros network namespaces."),
                               "alta", _("Activa un kill-switch que bloquee todo lo que no vaya por el túnel.")))
        elif lw.get("tunnel_up"):
            out.append(finding("ip_leak_live", _("Ninguna conexión sale por fuera del túnel"), "info", "pass", "pasiva",
                               _("tabla de sockets del kernel cada 2 s"), lw.get("summary"),
                               _("{v0} conexiones protegidas", v0=lw['summary'].get('protegidas', 0)),
                               _("Sondeo periódico; conexiones muy breves pueden escaparse a la observación."), "media",
                               "Ninguna."))
        directas = [f for f in lw.get("flows", []) if f["verdict"] == "directa"]
        if directas and not lw.get("tunnel_up"):
            procs = sorted({f["process"] for f in directas})
            out.append(finding("direct_exposure", _("{n} conexiones muestran tu IP real (sin VPN)", n=len(directas)),
                               "high" if profile.get("require_vpn") else "medium",
                               "fail" if profile.get("require_vpn") else "warn", "pasiva",
                               _("tabla de sockets del kernel"), {"processes": procs},
                               _("Programas: {names}", names=", ".join(procs[:10])),
                               _("Sin túnel no hay 'fuga' técnica: todo sale con tu IP real."), "alta",
                               _("Conecta la VPN; con el kill-switch permanente ninguna conexión saldría sin ella.")))
    pub = (public or {}).get("default") or {}
    if pub.get("ok") and pub.get("via_tunnel"):
        if pub.get("is_real_ip"):
            out.append(finding("public_real_ip", _("Internet ve tu IP real con la VPN conectada"), "critical", "fail",
                               "activa", _("eco de IP ({v1}) comparado con tus IPs reales conocidas", v1=pub.get('endpoint')),
                               pub, pub["ip"], _("Depende de conocer tu IP real (known_real_ips / learn_real_ip)."),
                               "alta", _("Desconecta y revisa la VPN: el tráfico no pasa por el túnel.")))
        else:
            mm = pub.get("country_mismatch")
            out.append(finding("public_real_ip", _("La IP que ve Internet es la de la VPN"), "info" if not mm else "low",
                               "pass" if not mm else "warn", "activa",
                               _("eco de IP ({v1}) cada {v3} por el túnel", v1=pub.get('endpoint'), v3=pub.get('interval', '60s')), pub,
                               f"{pub['ip']} ({(pub.get('geo') or {}).get('country') or '?'})"
                               + (_(" · se esperaba {expected}", expected=mm['expected']) if mm else ""),
                               _("Solo se puede afirmar que no es tu IP real si la conoces (known_real_ips / learn_real_ip).")
                               if not pub.get("own_known") else "—", "media" if not pub.get("own_known") else "alta",
                               "Ninguna." if not mm else _("La GeoIP local puede estar desfasada; verifica el servidor.")))
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
    return finding("webrtc", _("Exposición de IPs por WebRTC en el navegador"), "medium" if status == "fail" else "info",
                   status, "activa", _("RTCPeerConnection en la página local de la GUI") + (" + STUN" if used_stun else ""),
                   {"candidates": sorted(seen), "mdns": mdns}, _("IPs locales expuestas: {v1}; públicas: {v3}; mDNS: {n}", v1=exposed_local or 'ninguna', v3=exposed_public or 'ninguna', n=len(mdns)),
                   _("Solo prueba el navegador con el que abriste la GUI.") + ("" if used_stun else
                   _(" Sin STUN no se observa la IP pública (candidatos srflx).")), "media",
                   _("Desactiva WebRTC o limita los candidatos (media.peerconnection.ice.default_address_only)."))
