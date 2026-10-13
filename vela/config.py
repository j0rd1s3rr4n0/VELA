"""Configuración: valores por defecto seguros + config.toml del usuario (tomllib, stdlib).

Principio: todo lo que genera tráfico hacia terceros o modifica el sistema está
desactivado por defecto y requiere un consentimiento explícito en `[consent]`.
"""

from __future__ import annotations

import copy
import os
import tomllib
from pathlib import Path

from .util import parse_duration, private_dir, xdg_dir

DEFAULTS: dict = {
    "consent": {
        # Consultar la IP pública por la ruta directa (sin túnel) expone tu IP real al servicio de eco.
        "direct_ip_checks": False,
        # Consultar la IP de salida a través de proxies (si el proxy no tuneliza, también expone tu IP).
        "proxy_ip_checks": False,
        # Comprobación de IP a través de Tor: no expone tu IP de origen.
        "tor_ip_checks": True,
        # Test activo de fugas DNS contra un servicio externo.
        "active_dns_leak_test": False,
        # Permitir que la rotación modifique conexiones (VPN/proxy/Tor NEWNYM).
        "allow_rotation_changes": False,
        # Permitir aplicar el kill-switch con nftables (requiere sudo/pkexec).
        "allow_killswitch": False,
        # Consultar IPs en GreyNoise/VirusTotal/Shodan/Censys (el servicio sabe que te interesan).
        "threat_intel_lookups": False,
    },
    "intel": {
        "providers": ["greynoise", "virustotal", "shodan", "censys"],
        "via_tor": False,              # consultar a través de Tor (algunos servicios lo bloquean)
        "tor_socks_port": 9050,
        "cache_ttl": "24h",
        "exclude": [],                 # IPs que nunca se consultan
        "include_own": False,          # nunca consultar tus IPs propias (WAN, IP directa) salvo que lo pidas
        "allow_direct": False,         # permitir consultas sin VPN (saldrían desde tu IP real)
        # Consultar AUTOMÁTICAMENTE en VirusTotal las IPs a las que te conectas (Tiempo real).
        # Ojo: VirusTotal (Google) verá los destinos con los que hablas. Desactivado por defecto.
        "auto_live": False,
        "live_daily_limit": 400,       # tope diario (la API gratuita de VT permite 500/día)
        "live_notify": "flagged",      # "flagged" = solo sospechosas/maliciosas · "all" = cada IP puntuada
    },
    "monitor": {
        "network_interval": "30s",     # respaldo del sondeo; los cambios llegan por netlink
        "tor_interval": "20s",
        "dns_interval": "2m",
        "public_ip_interval": "15m",
        "router_wan_interval": "10m",
        "leak_interval": "5m",
    },
    "public_ip": {
        "endpoints": [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.co/ip",
            "https://checkip.amazonaws.com",
        ],
        "tor_endpoint": "https://check.torproject.org/api/ip",
        "min_interval": "30s",         # límite de frecuencia por vía de consulta
        "realtime_interval": "60s",    # con túnel activo: comprobación continua de la IP de salida
        "known_real_ips": [],          # tus IPs reales (si las conoces): permiten detectar que Internet las ve
        "learn_real_ip": False,        # sin túnel, aprender tu IP real (1 consulta/hora; el servicio la ve)
        # Solo consultar por la ruta por defecto si el tráfico va por un túnel: así el servicio de eco ve
        # la IP de la VPN y nunca tu IP real (si el túnel cae, la consulta se omite).
        "require_tunnel": True,
        "timeout": "10s",
    },
    "leakwatch": {
        "enabled": True,
        "interval": "2s",              # cada cuánto se revisa la tabla de sockets
        "on_leak": "alert",            # "alert" o "killswitch" (aplica el kill-switch propio; requiere consentimiento)
        "allow": [],                   # excepciones: "IP", "IP:puerto" o "proc:nombre"
    },
    "router": {"upnp": True},          # consulta UPnP-IGD al router: tráfico solo dentro de la LAN
    "tor": {"control": "auto", "socks": "auto"},
    "dns": {"leak_test_url": "https://bash.ws"},
    "storage": {
        "mode": "disk",                # "disk" o "memory" (sin persistencia)
        "path": "",                    # vacío = ~/.local/share/vela/vela.db
        "retention_days": 90,
    },
    "rotation": {
        "tor": {"enabled": False, "max_ttl": "10m", "min_ttl": "2m", "jitter": "3m", "no_repeat": 10,
                "cooldown": "1h", "max_per_hour": 6, "exclude_countries": [], "repeat_scope": "exit",
                "retries_on_repeat": 2},
        "proxy": {"enabled": False, "max_ttl": "20m", "min_ttl": "2m", "jitter": "5m", "no_repeat": 1,
                  "cooldown": "10m", "max_per_hour": 6, "exclude": [], "listen": "127.0.0.1:1088"},
        "vpn": {"enabled": False, "adapter": "auto", "max_ttl": "45m", "min_ttl": "5m", "jitter": "10m",
                "no_repeat": 3, "cooldown": "2h", "max_per_hour": 2, "exclude": [], "exclude_countries": [],
                "exclude_asn": [], "require_killswitch": True},
    },
    "killswitch": {"backend": "auto", "allow_lan": True},
    "profiles": {
        "default": {"description": "Perfil por defecto", "use_tor": False, "require_vpn": False,
                    "require_killswitch": False, "allowed_countries": [],
                    "forbidden_countries": [], "preferred_vpn": [], "allowed_proxies": [],
                    "dns_policy": "any", "retention_days": 90},
    },
    "active_profile": "default",
    "correlation": {"time_similarity_threshold": 0.85},
    "gui": {"host": "127.0.0.1", "port": 0, "open_browser": True},
}

DURATION_KEYS = {"network_interval", "tor_interval", "dns_interval", "public_ip_interval",
                 "router_wan_interval", "leak_interval", "min_interval", "timeout",
                 "max_ttl", "min_ttl", "jitter", "cooldown", "cache_ttl",
                 "realtime_interval", "interval"}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def config_path() -> Path:
    return Path(os.environ.get("VELA_CONFIG") or os.environ.get("OPSEC_CONFIG") or xdg_dir("config") / "config.toml")


def validate(cfg: dict) -> list[str]:
    errors = []

    def walk(d, prefix=""):
        for k, v in d.items():
            if isinstance(v, dict):
                walk(v, f"{prefix}{k}.")
            elif k in DURATION_KEYS:
                try:
                    parse_duration(v)
                except ValueError as e:
                    errors.append(f"{prefix}{k}: {e}")
    walk(cfg)
    if cfg.get("active_profile") not in cfg.get("profiles", {}):
        errors.append(f"active_profile: el perfil {cfg.get('active_profile')!r} no existe")
    if cfg["storage"]["mode"] not in ("disk", "memory"):
        errors.append("storage.mode debe ser 'disk' o 'memory'")
    if cfg["gui"]["host"] not in ("127.0.0.1", "::1", "localhost"):
        errors.append("gui.host debe ser una dirección de loopback")
    return errors


# Ajustes que la app puede cambiar: se guardan en un fichero propio que se aplica ENCIMA de config.toml,
# así la app nunca reescribe (ni pierde los comentarios de) tu config.toml.
SETTINGS_KEYS: dict[str, object] = {
    "consent.direct_ip_checks": bool, "consent.proxy_ip_checks": bool, "consent.tor_ip_checks": bool,
    "consent.active_dns_leak_test": bool, "consent.allow_rotation_changes": bool, "consent.allow_killswitch": bool,
    "consent.threat_intel_lookups": bool, "public_ip.require_tunnel": bool, "intel.via_tor": bool,
    "intel.allow_direct": bool, "leakwatch.enabled": bool, "leakwatch.on_leak": ("alert", "killswitch"),
    "storage.retention_days": int, "intel.auto_live": bool, "intel.live_daily_limit": int,
    "intel.live_notify": ("flagged", "all"), "monitor.public_ip_interval": "duration", "public_ip.realtime_interval": "duration",
}


def settings_path() -> Path:
    return Path(os.environ.get("VELA_SETTINGS") or os.environ.get("OPSEC_SETTINGS") or xdg_dir("config") / "app-settings.toml")


def load_overlay() -> dict:
    p = settings_path()
    if not p.exists():
        return {}
    with open(p, "rb") as f:
        return tomllib.load(f)


def get_key(cfg: dict, dotted: str):
    cur = cfg
    for part in dotted.split("."):
        cur = cur[part]
    return cur


def set_key(cfg: dict, dotted: str, value):
    parts = dotted.split(".")
    cur = cfg
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def coerce_setting(key: str, value):
    kind = SETTINGS_KEYS.get(key)
    if kind is None:
        raise KeyError(f"ajuste no permitido desde la app: {key}")
    if kind is bool:
        if not isinstance(value, bool):
            raise ValueError(f"{key} debe ser true/false")
    elif kind is int:
        value = int(value)
        if value < 0:
            raise ValueError(f"{key} no puede ser negativo")
    elif kind == "duration":
        parse_duration(value)
        value = str(value)
    elif isinstance(kind, tuple) and value not in kind:
        raise ValueError(f"{key} debe ser uno de {kind}")
    return value


def _toml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return '"' + str(v).replace("\\", "\\\\").replace('"', '\\"') + '"'


def save_overlay(overlay: dict) -> Path:
    lines = ["# Ajustes guardados desde la app VELA (se aplican sobre config.toml)."]
    for section in sorted(overlay):
        lines.append(f"\n[{section}]")
        for k in sorted(overlay[section]):
            lines.append(f"{k} = {_toml_scalar(overlay[section][k])}")
    text = "\n".join(lines) + "\n"
    tomllib.loads(text)
    p = settings_path()
    private_dir(p.parent)
    tmp = p.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, p)
    return p


def load(path: Path | None = None) -> dict:
    path = path or config_path()
    user = {}
    if path.exists():
        with open(path, "rb") as f:
            user = tomllib.load(f)
    cfg = deep_merge(deep_merge(DEFAULTS, user), load_overlay())
    errors = validate(cfg)
    if errors:
        raise ValueError("configuración no válida:\n  " + "\n  ".join(errors))
    return cfg


def load_text(text: str) -> dict:
    cfg = deep_merge(DEFAULTS, tomllib.loads(text))
    errors = validate(cfg)
    if errors:
        raise ValueError("\n".join(errors))
    return cfg


def save_text(text: str, path: Path | None = None) -> Path:
    """Valida y guarda el TOML del usuario (permisos 0600)."""
    load_text(text)
    path = path or config_path()
    private_dir(path.parent)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(tmp, path)
    return path


def dur(cfg_section: dict, key: str) -> float:
    return parse_duration(cfg_section[key])
