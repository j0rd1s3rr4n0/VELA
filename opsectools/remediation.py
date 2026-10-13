"""Remediación: para cada hallazgo, pasos concretos con comandos adaptados al sistema.

Nunca se ejecuta nada: los comandos se muestran para que el usuario los revise y lance él.
Cada paso indica si necesita root y si puede cortar la conexión.
"""

from __future__ import annotations

import re
import shlex

from .util import run, which


def step(desc: str, cmd: str | None = None, root: bool = False, disruptive: bool = False, manual: bool = False) -> dict:
    return {"desc": desc, "cmd": cmd, "root": root, "disruptive": disruptive, "manual": manual}


def _nm_conn_for(iface: str) -> str | None:
    code, out, _ = run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"])
    for line in out.splitlines() if code == 0 else []:
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) >= 2 and f[1] == iface:
            return f[0]
    return None


def _q(s: str) -> str:
    return shlex.quote(s)


def fix_for(f: dict, ctx: dict) -> dict | None:
    """ctx: env, net, dns, ks_ext, profile_name."""
    chk, ev = f["check"], f.get("evidence") or {}
    env = ctx.get("env") or {}
    ufw = bool((env.get("binaries") or {}).get("firewall", {}).get("ufw"))

    if chk == "proxy_exposed":
        port = ev.get("port")
        pid = re.search(r"pid (\d+)", ev.get("owner") or "")
        steps = [step("Identifica qué programa abre el puerto y con qué opciones", f"ss -ltnp 'sport = :{port}'")]
        if pid:
            steps.append(step("Ver la línea de comandos completa del proceso",
                              f"tr '\\0' ' ' < /proc/{pid.group(1)}/cmdline; echo"))
        steps.append(step("Arreglo de raíz: arráncalo escuchando solo en loopback (p. ej. mitmproxy "
                          "`--listen-host 127.0.0.1`, Burp: Proxy listeners → Bind to loopback only, "
                          "python http.server: `--bind 127.0.0.1`)", manual=True))
        if ufw:
            steps.append(step("Mientras tanto, bloquéalo en el firewall para el resto de la red",
                              f"sudo ufw deny in proto tcp to any port {port}", root=True))
        return {"title": "Que el proxy no sea accesible desde la LAN", "steps": steps,
                "verify": f"ss -ltn 'sport = :{port}'   # debe mostrar 127.0.0.1:{port}, no 0.0.0.0"}

    if chk == "mac_permanent":
        iface = ev.get("iface")
        conn = _nm_conn_for(iface) if iface and which("nmcli") else None
        kind = "802-11-wireless" if iface and iface.startswith("wl") else "802-3-ethernet"
        mode = "random" if kind == "802-11-wireless" else "stable"
        steps = []
        if conn:
            steps.append(step(f"MAC {'aleatoria por conexión' if mode == 'random' else 'estable por red (distinta de la de fábrica)'} "
                              f"para «{conn}»", f"nmcli connection modify {_q(conn)} {kind}.cloned-mac-address {mode}"))
            steps.append(step("Reactivar la conexión para aplicarlo (corta la red unos segundos; la VPN se reconectará)",
                              f"nmcli connection up {_q(conn)}", disruptive=True))
        steps.append(step("Para todas las conexiones futuras (global)",
                          "printf '[connection]\\nwifi.cloned-mac-address=random\\nethernet.cloned-mac-address=stable\\n"
                          "[device]\\nwifi.scan-rand-mac-address=yes\\n' | sudo tee /etc/NetworkManager/conf.d/90-opsec-mac.conf",
                          root=True))
        steps.append(step("Reiniciar NetworkManager (corta la red)", "sudo systemctl restart NetworkManager",
                          root=True, disruptive=True))
        return {"title": f"Dejar de usar la MAC de fábrica en {iface}", "steps": steps,
                "verify": f"cat /sys/class/net/{iface}/addr_assign_type   # 3 = fijada por NM, 1 = aleatoria"}

    if chk == "dns_third_party":
        steps = [step("Opción A — usar el DNS de Proton (NetShield activo): desconecta WARP; restaura resolv.conf",
                      "warp-cli --accept-tos disconnect", disruptive=True),
                 step("Comprobar los modos disponibles de tu versión de WARP (doh, warp, warp+doh…)",
                      "warp-cli --accept-tos mode --help"),
                 step("Opción B — mantener Cloudflare de forma consciente: no hay nada que corregir, solo asumir que "
                      "Cloudflare ve los dominios (y los asocia a tu registro de WARP)", manual=True)]
        return {"title": "Elegir quién resuelve tus DNS", "steps": steps,
                "verify": "opsec dns check   # 'Resolver efectivo' debe mostrar el DNS de la VPN"}

    if chk == "dns_plaintext" and f["status"] == "warn":
        conf = "[Resolve]\\nDNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net\\nDNSOverTLS=yes\\n"
        return {"title": "Cifrar el DNS del sistema (DoT en systemd-resolved)", "steps": [
            step("Crear la configuración de DoT", f"sudo mkdir -p /etc/systemd/resolved.conf.d && printf '{conf}' | "
                 "sudo tee /etc/systemd/resolved.conf.d/90-opsec-dot.conf", root=True),
            step("Aplicar", "sudo systemctl restart systemd-resolved", root=True, disruptive=True),
            step("Si usas VPN, prefiere su DNS (evita que un tercero vea tus consultas)", manual=True)],
            "verify": "resolvectl status | grep -i DNSOverTLS   # debe aparecer +DNSOverTLS"}

    if chk == "dns_leak_config" and f["status"] == "fail":
        return {"title": "Que el DNS vaya por el túnel", "steps": [
            step("Ver qué resolver se usa y por dónde sale", "opsec dns check"),
            step("Enrutar todas las consultas por la interfaz del túnel (sustituye <tun> por tu interfaz VPN)",
                 "sudo resolvectl domain <tun> '~.' && sudo resolvectl default-route <tun> yes", root=True),
            step("Quitar la ruta DNS por defecto de la interfaz física",
                 f"sudo resolvectl default-route {((ctx.get('net') or {}).get('routes') or {}).get('ipv4_default', [{}])[0].get('dev', '<iface>')} no",
                 root=True)],
            "verify": "opsec leaks check --active   # con consent.active_dns_leak_test = true"}

    if chk == "killswitch" and f["status"] in ("warn", "pass") and "permanente" in (f.get("recommendation") or ""):
        return {"title": "Kill-switch permanente en ProtonVPN", "steps": [
            step("ProtonVPN → Configuración → Funciones → Kill switch → «Permanente/Avanzado». No tiene CLI: es "
                 "un ajuste de la app", manual=True),
            step("Comprobar que la app lo ha guardado (2 = permanente)",
                 "python3 -c \"import json,os;print(json.load(open(os.path.expanduser("
                 "'~/snap/proton-vpn/current/.config/Proton/VPN/settings.json')))['killswitch'])\"")],
            "verify": "opsec status   # 'Kill-switch: ProtonVPN · si cae el túnel: IPv4 bloqueado'"}

    if chk == "killswitch" and f["status"] == "warn":
        return {"title": "Activar un kill-switch", "steps": [
            step("Actívalo en tu cliente VPN (opción preferible)", manual=True),
            step("O usa el de OPSEC Command Center: revisa las reglas", "opsec killswitch preview"),
            step("Permitirlo en la configuración: [consent] allow_killswitch = true", "opsec config edit"),
            step("Aplicarlo (bloquea toda salida salvo túneles, Tor y LAN)", "opsec killswitch apply --yes",
                 root=True, disruptive=True)],
            "verify": "opsec status"}

    if chk == "ipv6_leak" and f["status"] == "fail":
        dev = (ev.get("egress_ipv6") or {}).get("dev", "<iface>")
        return {"title": "Cerrar la fuga IPv6", "steps": [
            step("Desactivar IPv6 en la interfaz física (temporal)", f"sudo sysctl -w net.ipv6.conf.{dev}.disable_ipv6=1",
                 root=True, disruptive=True),
            step("Hacerlo permanente", f"echo 'net.ipv6.conf.{dev}.disable_ipv6 = 1' | sudo tee /etc/sysctl.d/90-opsec-ipv6.conf",
                 root=True),
            step("O activa la protección IPv6 de tu cliente VPN", manual=True)],
            "verify": "ip -6 route get 2606:4700:4700::1111"}

    if chk in ("tunnel_bypass", "profile_geo", "profile_killswitch", "profile_dns") and f["status"] == "fail":
        steps = []
        if chk == "profile_geo":
            steps.append(step("Cambia de servidor VPN a un país permitido por el perfil (ProtonVPN: elige el país en "
                              "la app; con Secure Core, el país de SALIDA es el segundo: CH-DE sale por DE)", manual=True))
            steps.append(step("Si el país lo marca el exit de Tor: pide circuitos nuevos (prueba primero)",
                              "opsec rotate tor --dry-run"))
        if chk == "tunnel_bypass":
            steps.append(step("Conecta la VPN antes de operar con este perfil", manual=True))
        if chk == "profile_killswitch":
            steps.append(step("Conecta la VPN: el kill-switch estándar de ProtonVPN solo se activa al conectar "
                              "(el permanente bloquea siempre; ProtonVPN → Configuración → Kill switch)", manual=True))
            steps.append(step("O usa el kill-switch propio (revisa las reglas antes)", "opsec killswitch preview"))
        if chk == "profile_dns":
            steps.append(step("Ver el resolver efectivo y si va cifrado/por el túnel", "opsec dns check"))
        steps.append(step("O cambia a un perfil cuyas reglas cumplas", "opsec profiles"))
        return {"title": f"Cumplir la política del perfil «{ctx.get('profile_name')}»", "steps": steps,
                "verify": "opsec leaks check"}

    if chk == "tz_mismatch":
        return {"title": "Que la zona horaria no te delate", "steps": [
            step("Para navegar con la identidad de salida usa Tor Browser (fuerza UTC y resiste fingerprinting)", manual=True),
            step("En Firefox: activa privacy.resistFingerprinting en about:config (informa UTC)", manual=True),
            step("Lanzar una aplicación concreta con otra zona horaria", "TZ=UTC firefox")],
            "verify": "en el navegador: Intl.DateTimeFormat().resolvedOptions().timeZone"}

    if chk in ("tor_required", "tor_health") and f["status"] in ("fail", "warn"):
        return {"title": "Recuperar Tor", "steps": [
            step("Arrancar el servicio", "sudo systemctl start tor@default", root=True),
            step("Ver por qué no conecta", "journalctl -u tor@default -n 50 --no-pager", root=True)],
            "verify": "opsec tor status"}

    if chk == "tor_control_auth":
        return {"title": "Proteger el ControlPort de Tor", "steps": [
            step("Activar autenticación por cookie", "echo 'CookieAuthentication 1' | sudo tee -a /etc/tor/torrc", root=True),
            step("Recargar Tor", "sudo systemctl reload tor@default", root=True)],
            "verify": "opsec discover | grep tor.control"}

    if chk == "vm_isolation":
        name = ev.get("name", "<red>")
        return {"title": f"Aislar la red de VMs «{name}»", "steps": [
            step("Ver la definición actual", f"virsh -c qemu:///system net-dumpxml {_q(name)}"),
            step("Editar y eliminar la línea <forward …/> (sin forward = aislada)",
                 f"virsh -c qemu:///system net-edit {_q(name)}", root=False),
            step("Reiniciar la red (las VMs conectadas perderán red un momento)",
                 f"virsh -c qemu:///system net-destroy {_q(name)} && virsh -c qemu:///system net-start {_q(name)}",
                 disruptive=True)],
            "verify": "opsec networks"}

    if chk in ("ip_leak_live", "direct_exposure", "public_real_ip") and f["status"] in ("fail", "warn"):
        flows = ev.get("flows") or []
        procs = sorted({x["process"] for x in flows}) or ev.get("processes") or []
        steps = []
        if chk == "direct_exposure":
            steps.append(step("Conecta ProtonVPN antes de usar estos programas", manual=True))
        steps += [
            step("Cómo evitarlo de raíz: kill-switch PERMANENTE de ProtonVPN (bloquea todo sin VPN, también al "
                 "arrancar o si cierras la app): ProtonVPN → Configuración → Kill switch → Permanente", manual=True),
            step("Desactiva el split tunneling de ProtonVPN si no lo necesitas (deja programas fuera del túnel)",
                 manual=True),
            step("Alternativa/refuerzo: kill-switch propio (solo deja salir por túneles, Tor y LAN) — revisa las reglas",
                 "opsec killswitch preview"),
            step("Permitirlo y aplicarlo automáticamente al detectar una fuga: [consent] allow_killswitch = true y "
                 "[leakwatch] on_leak = \"killswitch\"", "opsec config edit"),
            step("Si la conexión es IPv6, desactívalo en la interfaz física",
                 "sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1", root=True, disruptive=True),
        ]
        for p in procs[:5]:
            if p and not p.startswith(("[", "desconocido")):
                steps.append(step(f"Ver qué está haciendo «{p}» y si fuerza una interfaz (bind) o tiene proxy propio",
                                  f"ss -tunp | grep -F {_q(p)}"))
        return {"title": "Evitar que tu IP real salga fuera de la VPN", "steps": steps,
                "verify": "opsec leakwatch   # 'fugas: 0' con la VPN conectada"}

    if chk == "tor_guard_churn":
        return {"title": "Guards de Tor", "steps": [
            step("No hay que hacer nada salvo NO forzar cambios: no borres /var/lib/tor ni uses EntryNodes", manual=True)],
            "verify": "opsec tor status"}

    if chk == "webrtc" and f["status"] == "fail":
        return {"title": "Evitar que WebRTC revele tus IPs", "steps": [
            step("Firefox about:config → media.peerconnection.ice.default_address_only = true y "
                 "media.peerconnection.ice.no_host = true (o media.peerconnection.enabled = false)", manual=True),
            step("Chromium/Brave: Ajustes → Privacidad → WebRTC IP handling policy → «Disable non-proxied UDP»", manual=True)],
            "verify": "GUI → pestaña WebRTC → Ejecutar prueba"}
    return None


def status_fixes(ctx: dict) -> list[dict]:
    """Remediaciones que no vienen de un hallazgo sino del estado (IP pública, router, Tor…)."""
    out = []
    pub = (ctx.get("public") or {}).get("default") or {}
    if not pub.get("ok"):
        if pub.get("consent_required"):
            out.append({"check": "public_ip", "title": "Ver la IP pública por la que sales",
                        "why": pub.get("error"), "steps": [
                            step("Permitir la comprobación (solo se hace si el tráfico va por el túnel)",
                                 "opsec config edit   # [consent] direct_ip_checks = true"),
                            step("Comprobar ahora", "opsec ip")], "verify": "opsec status"})
        elif pub.get("skipped"):
            out.append({"check": "public_ip", "title": "IP pública omitida para no exponer tu IP real",
                        "why": pub.get("error"), "steps": [
                            step("Conecta la VPN; la comprobación se hará sola", manual=True),
                            step("Si de verdad quieres ver tu IP real (el servicio de eco la verá)",
                                 "opsec config edit   # [public_ip] require_tunnel = false")], "verify": "opsec ip"})
        elif pub.get("error"):
            out.append({"check": "public_ip", "title": "La comprobación de IP pública falló", "why": pub.get("error"),
                        "steps": [step("Reintentar", "opsec ip --route default")], "verify": "opsec status"})
    wan = ctx.get("wan") or {}
    if wan and not wan.get("ok"):
        out.append({"check": "router_wan", "title": "IP WAN del router desconocida (UPnP desactivado)",
                    "why": "Tener UPnP desactivado en el router es BUENO para la seguridad; no lo actives solo para esto.",
                    "steps": [step("Consúltala en la web de administración del router (http://"
                                   f"{(ctx.get('net') or {}).get('gateway') or '192.168.x.1'})", manual=True)],
                    "verify": "—"})
    return out


def plan(findings: list[dict], ctx: dict) -> list[dict]:
    out = []
    seen = set()
    for f in findings:
        if f["status"] not in ("fail", "warn") and not (f["check"] == "killswitch" and "permanente" in
                                                         (f.get("recommendation") or "")):
            continue
        fx = fix_for(f, ctx)
        if fx and (f["check"], fx["title"]) not in seen:
            seen.add((f["check"], fx["title"]))
            out.append({"check": f["check"], "severity": f["severity"], "finding": f["title"],
                        "why": f.get("observed"), **fx})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out.sort(key=lambda x: order.get(x["severity"], 5))
    return out + status_fixes(ctx)
