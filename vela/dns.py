"""DNS: configuración observada (pasiva) y pruebas activas (con consentimiento).

Distingue tres niveles de evidencia:
  * configurado – lo que dicen resolv.conf / systemd-resolved / NetworkManager.
  * comprobado  – resolución realmente ejecutada (test activo).
  * fuga        – resolver visto desde fuera que no corresponde con la ruta esperada.
"""

from __future__ import annotations

from .i18n import _
from .util import WINDOWS

import ipaddress
import json
import os
import re
import socket
import urllib.request

from .util import now, run

RESOLVED_KEYS = {"Current Scopes", "Protocols", "resolv.conf mode", "Current DNS Server", "DNS Servers",
                 "Fallback DNS Servers", "DNS Domain", "Default Route", "DNSSEC NTA", "LLMNR setting",
                 "MulticastDNS setting", "DNSOverTLS setting", "DNSSEC setting", "DNSSEC supported"}
LIST_KEYS = {"DNS Servers", "Fallback DNS Servers", "DNS Domain", "DNSSEC NTA"}


def parse_resolvectl_status(text: str) -> dict:
    sections: dict[str, dict] = {}
    current, last_key = None, None
    for line in text.splitlines():
        if not line.strip():
            continue
        # Las claves van alineadas a la derecha: la más larga ("Current DNS Server") empieza en la
        # columna 0, así que la cabecera se reconoce por su forma, no por la sangría.
        header = re.fullmatch(r"(Global|Link \d+ \((.+)\))\s*", line)
        if header:
            current = header.group(2) or header.group(1)
            sections[current] = {}
            last_key = None
            continue
        stripped = line.strip()
        key, sep, val = stripped.partition(":")
        if sep and key in RESOLVED_KEYS:
            last_key = key
            sections[current][key] = val.strip().split() if key in LIST_KEYS else val.strip()
        elif last_key in LIST_KEYS and current is not None:  # continuación de lista
            sections[current][last_key] += stripped.split()
    return sections


def _proto_flags(protocols: str) -> dict:
    flags = {}
    for tok in (protocols or "").split():
        if tok[:1] in "+-":
            flags[tok[1:]] = tok[0] == "+"
        elif "=" in tok:
            k, v = tok.split("=", 1)
            flags[k] = v
    return flags


def _server_ip(entry: str) -> str:
    """'1.1.1.1#cloudflare-dns.com' o '[::1]:53' → IP."""
    s = entry.split("#")[0]
    if s.startswith("["):
        s = s[1:].split("]")[0]
    elif s.count(":") == 1:
        s = s.split(":")[0]
    return s.split("%")[0]


def classify_server(entry: str) -> str:
    try:
        ip = ipaddress.ip_address(_server_ip(entry))
    except ValueError:
        return "desconocido"
    if ip.is_loopback:
        return "local"
    if ip.is_private or ip.is_link_local:
        return "lan"
    return "pública"


def snapshot() -> dict:
    if WINDOWS:                       # rama windows-lite: mismos datos desde las API de Windows
        from . import winsys
        return winsys.dns_snapshot()
    resolv = ""
    try:
        with open("/etc/resolv.conf") as f:
            resolv = f.read()
    except OSError:
        pass
    nameservers = re.findall(r"^\s*nameserver\s+(\S+)", resolv, re.M)
    snap = {
        "ts": now(),
        "resolv_conf": nameservers,
        "resolv_conf_target": os.path.realpath("/etc/resolv.conf"),
        "backend": "resolv.conf",
        "links": {},
        "global": {},
    }
    code, out, _ign = run(["resolvectl", "status", "--no-pager"])
    if code == 0 and out.strip():
        snap["backend"] = "systemd-resolved"
        sections = parse_resolvectl_status(out)
        for name, sec in sections.items():
            flags = _proto_flags(sec.get("Protocols", ""))
            entry = {
                "servers": sec.get("DNS Servers", []),
                "current": sec.get("Current DNS Server"),
                "domains": sec.get("DNS Domain", []),
                "default_route": flags.get("DefaultRoute", sec.get("Default Route") == "yes"),
                "dot": flags.get("DNSOverTLS", False),
                "dnssec": flags.get("DNSSEC", "no"),
            }
            entry["server_classes"] = sorted({classify_server(s) for s in entry["servers"]})
            if name == "Global":
                entry["mode"] = sec.get("resolv.conf mode")
                entry["fallback"] = sec.get("Fallback DNS Servers", [])
                snap["global"] = entry
            else:
                snap["links"][name] = entry
    snap["resolv_mode"] = snap["global"].get("mode")
    active = {n: l for n, l in snap["links"].items() if l["servers"]}
    snap["active_links"] = sorted(active)
    snap["default_links"] = sorted(n for n, l in active.items() if l["default_route"] or "~." in l["domains"])
    snap["split_dns"] = sorted(n for n, l in active.items()
                               if any(d.startswith("~") and d != "~." for d in l["domains"]))
    snap["dot"] = any(l["dot"] for l in snap["links"].values()) or bool(snap["global"].get("dot"))
    snap["all_servers"] = sorted({s for l in active.values() for s in l["servers"]} |
                                 set(snap["global"].get("servers", [])) |
                                 ({*nameservers} if snap["backend"] == "resolv.conf" else set()))
    # Resolver EFECTIVO: si resolv.conf apunta al stub de resolved (127.0.0.53/54) mandan los enlaces de
    # resolved; si no (modo "foreign": WARP, cloudflared, dnscrypt…), mandan los nameserver de resolv.conf.
    uses_stub = bool(nameservers) and all(n.startswith(("127.0.0.53", "127.0.0.54")) for n in nameservers)
    if uses_stub and snap["backend"] == "systemd-resolved":
        snap["effective_source"] = "systemd-resolved"
        snap["effective_servers"] = sorted({s for n in snap["default_links"] for s in snap["links"][n]["servers"]} |
                                           set(snap["global"].get("servers", []))) or nameservers
    else:
        snap["effective_source"] = "resolv.conf" + (f" (modo {snap['resolv_mode']})" if snap.get("resolv_mode") else "")
        snap["effective_servers"] = nameservers
    from .protection import detect_dns_encryption
    snap["encryption"] = detect_dns_encryption(snap)
    snap["encrypted"] = snap["encryption"]["system_encrypted"]
    return snap


# ── test activo de fugas (con consentimiento) ───────────────────────────────

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def active_leak_test(base_url: str = "https://bash.ws", queries: int = 10, timeout: float = 10) -> dict:
    """Pide un id al servicio, resuelve nombres únicos con el resolver del sistema y pregunta qué
    resolvers llegaron a su servidor autoritativo. Genera tráfico real por la ruta por defecto:
    el servicio ve tu IP de salida. Solo debe llamarse con consent.active_dns_leak_test."""
    started = now()
    try:
        test_id = _NO_PROXY.open(f"{base_url}/id", timeout=timeout).read().decode().strip()
        if not re.fullmatch(r"[0-9a-zA-Z]+", test_id):
            raise ValueError(_("id no válido"))
        host = base_url.split("//", 1)[1].split("/")[0]
        for i in range(1, queries + 1):
            try:
                socket.getaddrinfo(f"{i}.{test_id}.{host}", None)
            except OSError:
                pass  # se espera NXDOMAIN; lo que importa es la consulta en el autoritativo
        raw = _NO_PROXY.open(f"{base_url}/dnsleak/test/{test_id}?json", timeout=timeout).read().decode()
        rows = json.loads(raw)
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "ts": started}
    seen_ip = [r for r in rows if r.get("type") == "ip"]
    resolvers = [r for r in rows if r.get("type") == "dns"]
    conclusion = next((r.get("ip") for r in rows if r.get("type") == "conclusion"), None)
    return {
        "ok": True, "ts": started, "service": base_url,
        "your_ip": [{"ip": r.get("ip"), "country": r.get("country_name"), "asn": r.get("asn")} for r in seen_ip],
        "resolvers": [{"ip": r.get("ip"), "country": r.get("country_name"), "asn": r.get("asn")} for r in resolvers],
        "service_conclusion": conclusion,
    }
