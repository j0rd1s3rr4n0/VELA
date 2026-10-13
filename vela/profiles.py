"""Generación de perfiles OPSEC adaptados a lo que hay en el sistema.

Cada perfil es un conjunto de reglas que el motor valida continuamente (leaks.check_profile*,
check_tunnel_route, check_tor) y que el Correlation Risk Engine usa para detectar vínculos entre
identidades. Los perfiles separan identidades de RED: no evitan la correlación por cookies, cuentas
o huella del navegador (usa un navegador o contenedor distinto por perfil).
"""

from __future__ import annotations

import datetime as dt

from . import config as config_mod
from .leaks import tz_country

# Alianzas de intercambio de inteligencia de señales (Five/Nine/Fourteen Eyes)
FIVE_EYES = ["US", "GB", "CA", "AU", "NZ"]
FOURTEEN_EYES = FIVE_EYES + ["DK", "FR", "NL", "NO", "DE", "BE", "IT", "SE", "ES"]


def _toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_val(x) for x in v) + "]"
    s = str(v).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{s}"'


def generate(env: dict, dns_effective: dict | None = None) -> dict:
    """Propuesta de perfiles: {nombre: {campos…, "_why": [motivos]}}."""
    home = tz_country((env.get("identity") or {}).get("timezone"))
    ks = env.get("killswitch") or {}
    has_vpn = bool(ks.get("clients")) or any(i["kind"] in ("wireguard", "tun", "ppp") for i in env["interfaces"]) \
        or any(c["type"] in ("vpn", "wireguard") for c in (env["vpn"].get("networkmanager") or []))
    names: dict[str, str] = {}      # sin duplicados por mayúsculas: "ProtonVPN" (cliente) == "protonvpn" (proveedor)
    for n in [c["client"] for c in ks.get("clients", []) if c.get("vpn_connections") is not None] + \
             [p for p in env["vpn"]["providers"] if p not in ("cloudflare-warp", "tailscale", "zerotier")]:
        names.setdefault(n.lower(), n)
    vpn_names = sorted(names.values())
    has_ks = bool(ks.get("declared_by"))
    has_tor = bool(env["tor"]["control"] or env["tor"]["socks"])
    enc = (dns_effective or env.get("dns_effective") or {}).get("encrypted")
    proxies = [f"http://127.0.0.1:{p['port']}" if p["kind"] == "http" else f"socks5://127.0.0.1:{p['port']}"
               for p in env["proxy"]["local"] if p["kind"] in ("http", "socks5")]
    home_list = [home] if home else []
    out: dict[str, dict] = {}

    out["diario"] = {
        "description": "Uso diario: VPN con kill-switch y DNS cifrado; sin restricciones geográficas",
        "use_tor": False, "require_vpn": has_vpn, "require_killswitch": has_ks,
        "preferred_vpn": vpn_names, "dns_policy": "encrypted" if enc else "any",
        "allowed_countries": [], "forbidden_countries": [], "allowed_proxies": [], "retention_days": 90,
        "_why": [f"VPN detectada: {', '.join(vpn_names) or 'túnel genérico'}" if has_vpn else "sin VPN: no se exige",
                 "kill-switch del cliente verificado" if has_ks else "sin kill-switch detectado",
                 "DNS cifrado detectado" if enc else "DNS sin cifrar: política 'any'"],
    }
    out["privado"] = {
        "description": "Navegación privada: nunca salir por tu propio país, VPN + kill-switch obligatorios",
        "use_tor": False, "require_vpn": True, "require_killswitch": True, "preferred_vpn": vpn_names,
        "dns_policy": "encrypted", "allowed_countries": [], "forbidden_countries": home_list,
        "allowed_proxies": [], "retention_days": 30,
        "_why": [f"país de origen estimado por zona horaria: {home or 'desconocido'}",
                 "una salida en tu propio país facilita la atribución"],
    }
    if has_tor:
        out["anonimo"] = {
            "description": "Anonimato: Tor sobre VPN (el ISP no ve que usas Tor); resolver nombres por Tor; "
                           "usa Tor Browser",
            "use_tor": True, "require_vpn": has_vpn, "require_killswitch": has_ks, "preferred_vpn": vpn_names,
            "dns_policy": "tor", "allowed_countries": [], "forbidden_countries": home_list,
            "allowed_proxies": [], "retention_days": 7,
            "_why": ["Tor detectado (ControlPort/SocksPort)",
                     "Tor sobre VPN oculta el uso de Tor a tu ISP" if has_vpn else "sin VPN: Tor directo",
                     "retención corta del historial"],
        }
        out["alto_riesgo"] = {
            "description": "Alto riesgo: Tor + VPN + kill-switch obligatorio, sin salidas en países 14-Eyes ni "
                           "en tu país; retención mínima (considera storage.mode = \"memory\")",
            "use_tor": True, "require_vpn": True, "require_killswitch": True, "preferred_vpn": vpn_names,
            "dns_policy": "tor", "allowed_countries": [],
            "forbidden_countries": sorted(set(FOURTEEN_EYES) | set(home_list)),
            "allowed_proxies": [], "retention_days": 1,
            "_why": ["excluye 14-Eyes como salida (VPN y exit de Tor)",
                     "kill-switch obligatorio; en ProtonVPN conviene el modo permanente"],
        }
    if proxies:
        out["laboratorio"] = {
            "description": "Pruebas/laboratorio: tráfico a través de los proxies locales detectados, siempre dentro de la VPN",
            "use_tor": False, "require_vpn": has_vpn, "require_killswitch": False, "preferred_vpn": vpn_names,
            "dns_policy": "any", "allowed_countries": [], "forbidden_countries": [],
            "allowed_proxies": proxies, "retention_days": 30,
            "_why": [f"proxies locales detectados: {', '.join(proxies)}",
                     "separado del resto para que el Correlation Risk Engine detecte mezclas"],
        }
    return out


def to_toml(profiles: dict, existing: set[str] = frozenset()) -> str:
    lines = [f"# Perfiles generados por `vela profiles generate` el {dt.datetime.now():%Y-%m-%d %H:%M}",
             "# Recuerda: separan identidades de RED; usa además un navegador/contenedor distinto por perfil."]
    for name, p in profiles.items():
        if name in existing:
            continue
        lines.append("")
        for why in p.get("_why", []):
            lines.append(f"# · {why}")
        lines.append(f"[profiles.{name}]")
        for k, v in p.items():
            if not k.startswith("_"):
                lines.append(f"{k} = {_toml_val(v)}")
    return "\n".join(lines) + "\n"


def write(profiles: dict, current_cfg: dict) -> dict:
    """Añade al config.toml del usuario los perfiles que aún no existen (nunca sobrescribe)."""
    path = config_mod.config_path()
    text = path.read_text() if path.exists() else ""
    existing = set(current_cfg.get("profiles", {}))
    new = [n for n in profiles if n not in existing]
    if not new:
        return {"written": [], "skipped": sorted(profiles), "path": str(path)}
    block = to_toml(profiles, existing)
    merged = (text.rstrip() + "\n\n" if text.strip() else "") + block
    config_mod.save_text(merged, path)          # valida antes de guardar
    return {"written": new, "skipped": sorted(existing & set(profiles)), "path": str(path)}
