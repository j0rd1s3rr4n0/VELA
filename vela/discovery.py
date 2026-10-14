#!/usr/bin/env python3
"""Autodetección del entorno de red y anonimato.

Inspecciona el sistema y decide qué collectors, drivers de rotación y kill-switch
puede usar VELA. No hace ninguna conexión fuera de 127.0.0.1: solo lee /proc,
/sys, ficheros de configuración, ejecuta comandos locales de solo lectura y sondea
puertos de loopback.

    python3 -m vela discover            # informe legible
    python3 -m vela discover --json     # informe en JSON
    python3 -m vela discover --write-config ~/.config/vela/config.toml
"""

from __future__ import annotations

from .i18n import _

import argparse
import datetime as dt
import glob
import grp
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

from .util import which

HOME = Path.home()

BINARIES = {
    "tor": ["tor", "torsocks", "torify", "obfs4proxy", "lyrebird", "snowflake-client", "torbrowser-launcher"],
    "vpn": ["wg", "wg-quick", "openvpn", "openconnect", "nmcli"],
    "proxy": ["proxychains4", "proxychains", "privoxy", "redsocks", "sing-box", "xray", "v2ray", "clash", "mihomo", "ssh"],
    "dns": ["resolvectl", "dnscrypt-proxy", "unbound", "stubby", "dnsmasq", "dig", "kdig"],
    "firewall": ["nft", "iptables", "ip6tables", "ufw", "firewall-cmd"],
    "identity": ["macchanger", "ip", "iw"],
}

# proveedor -> (binarios posibles, comando de estado de solo lectura)
VPN_PROVIDERS = {
    "mullvad": (["mullvad"], ["mullvad", "status"]),
    "protonvpn": (["proton-vpn", "protonvpn-app", "protonvpn", "protonvpn-cli"], None),
    "nordvpn": (["nordvpn"], ["nordvpn", "status"]),
    "expressvpn": (["expressvpnctl", "expressvpn"], None),
    "pia": (["piactl"], ["piactl", "get", "connectionstate"]),
    "ivpn": (["ivpn"], ["ivpn", "status"]),
    "windscribe": (["windscribe-cli", "windscribe"], None),
    "surfshark": (["surfshark-vpn"], None),
    "airvpn": (["eddie-cli", "hummingbird"], None),
    "cyberghost": (["cyberghostvpn"], None),
    "tailscale": (["tailscale"], ["tailscale", "status", "--peers=false"]),
    "zerotier": (["zerotier-cli"], ["zerotier-cli", "info"]),
    "strongswan": (["swanctl", "ipsec"], None),
    "openconnect": (["openconnect"], None),
    "cloudflare-warp": (["warp-cli"], ["warp-cli", "--accept-tos", "status"]),
}
# Clientes con CLI que permite elegir servidor de salida (los demás solo se observan;
# ProtonVPN para Linux v4 es solo app gráfica).
ROTATABLE_PROVIDERS = {"mullvad", "nordvpn", "expressvpn", "pia", "ivpn", "windscribe",
                       "surfshark", "airvpn", "cyberghost"}

# Estados de capacidad
OPERATIVA = "operativa"
INACTIVA = "detectada_inactiva"
SIN_PERMISOS = "sin_permisos"
NO_DISPONIBLE = "no_disponible"
NO_VERIFICABLE = "no_verificable"

INTERESTING_PROCESSES = {
    "tor", "openvpn", "wireguard-go", "mullvad-daemon", "nordvpnd", "privoxy", "dnscrypt-proxy",
    "unbound", "stubby", "sing-box", "xray", "v2ray", "clash", "mihomo", "i2pd", "redsocks",
}

INTERESTING_SERVICES = (
    "tor", "openvpn", "wg-quick", "mullvad", "nordvpn", "protonvpn", "expressvpn", "piavpn", "ivpn",
    "windscribe", "networkmanager", "systemd-resolved", "dnscrypt-proxy", "unbound", "stubby",
    "dnsmasq", "privoxy", "i2pd", "nftables", "ufw", "firewalld", "sing-box", "xray", "v2ray",
)

CANDIDATE_PROXY_PORTS = [9050, 9150, 1080, 1081, 1086, 2080, 3128, 7890, 7891, 8080, 8118, 8888, 10808, 10809, 20170]
TOR_CONTROL_PORTS = [9051, 9151]

TOR_BROWSER_GLOBS = [
    "~/.local/share/torbrowser/tbb/*/tor-browser*",
    "~/.var/app/org.torproject.torbrowser-launcher/data/torbrowser/tbb/*/tor-browser*",
    "~/.var/app/com.github.micahflee.torbrowser-launcher/data/torbrowser/tbb/*/tor-browser*",
    "~/tor-browser*", "~/Descargas/tor-browser*", "~/Downloads/tor-browser*", "/opt/tor-browser*",
]

OVPN_GLOBS = [
    "/etc/openvpn/*.conf", "/etc/openvpn/client/*.conf", "/etc/openvpn/client/*.ovpn",
    "~/*.ovpn", "~/.config/openvpn/*.ovpn", "~/vpn/*.ovpn", "~/Descargas/*.ovpn", "~/Downloads/*.ovpn",
]

PY_MODULES = {
    "stem": "stem", "textual": "textual", "typer": "typer", "httpx": "httpx", "socksio": "httpx[socks]",
    "dns": "dnspython", "fastapi": "fastapi", "uvicorn": "uvicorn", "geoip2": "geoip2", "sqlcipher3": "sqlcipher3",
}

VPN_KINDS = {"wireguard", "tun", "ppp"}
# Interfaces que los clientes VPN usan como "agujero negro" del kill-switch (p. ej. pvpnksintrf0 de Proton)
BLACKHOLE_KINDS = {"dummy"}
PHYSICAL_KINDS = {"ethernet", "wifi"}


# ── utilidades ──────────────────────────────────────────────────────────────

def read(path) -> str | None:
    try:
        return Path(path).read_text(errors="replace")
    except OSError:
        return None


def run(cmd: list[str], timeout: float = 3) -> str | None:
    """Ejecuta un comando local de solo lectura. Devuelve stdout o None si falla."""
    exe = which(cmd[0])
    if not exe:
        return None
    cmd = [exe, *cmd[1:]]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL, env={**os.environ, "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def expand_globs(patterns: list[str]) -> list[str]:
    found = []
    for pat in patterns:
        found += glob.glob(os.path.expanduser(pat))
    return sorted(set(found))


def is_local(addr: str) -> bool:
    ip = ipaddress.ip_address(addr)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_loopback or ip.is_unspecified


def redact_url(value: str) -> str:
    return re.sub(r"//[^@/]+@", "//***@", value)


# ── sockets y procesos ──────────────────────────────────────────────────────

def _decode_proc_addr(h: str) -> str:
    raw = bytes.fromhex(h)
    # /proc/net expresa las direcciones como palabras de 32 bits en orden del host
    if sys.byteorder == "little":
        raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    return str(ipaddress.ip_address(raw))


def listening_sockets(proto: str) -> list[tuple[str, int]]:
    """Sockets en escucha según /proc/net/{tcp,udp}[6] (no necesita root)."""
    result = []
    for fname in (f"/proc/net/{proto}", f"/proc/net/{proto}6"):
        for line in (read(fname) or "").splitlines()[1:]:
            f = line.split()
            if len(f) < 4:
                continue
            if proto == "tcp" and f[3] != "0A":  # LISTEN
                continue
            if proto == "udp" and not f[2].endswith(":0000"):  # solo sockets no conectados
                continue
            addr_hex, _ign, port_hex = f[1].partition(":")
            try:
                result.append((_decode_proc_addr(addr_hex), int(port_hex, 16)))
            except ValueError:
                continue
    return result


def list_processes() -> list[tuple[str, str]]:
    procs = []
    for d in glob.glob("/proc/[0-9]*"):
        comm = read(f"{d}/comm")
        if comm:
            procs.append((d, comm.strip()))
    return procs


def ssh_socks_tunnels(procs) -> list[int]:
    """Puertos de túneles SOCKS creados con `ssh -D`."""
    ports = []
    for d, comm in procs:
        if comm != "ssh":
            continue
        try:
            args = [a.decode(errors="replace") for a in Path(d, "cmdline").read_bytes().split(b"\0") if a]
        except OSError:
            continue
        for i, a in enumerate(args):
            if re.fullmatch(r"-[A-Za-z]*D", a) and i + 1 < len(args):
                spec = args[i + 1]
            elif m := re.fullmatch(r"-D(.+)", a):
                spec = m.group(1)
            else:
                continue
            if m := re.search(r"(\d+)$", spec):
                ports.append(int(m.group(1)))
    return sorted(set(ports))


def probe_port(port: int) -> str:
    """Identifica qué escucha en 127.0.0.1:port sin generar tráfico externo."""
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
            s.settimeout(1)
            s.sendall(b"GET / HTTP/1.0\r\n\r\n")
            data = s.recv(512)
    except OSError:
        pass
    if b"Tor is not an HTTP Proxy" in data:
        return "tor-socks"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as s:
            s.settimeout(1)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) == b"\x05\x00":
                return "socks5"
    except OSError:
        pass
    if data.startswith(b"HTTP/"):
        return "http" if is_http_proxy(port) else "http-server"
    return "desconocido"


def is_http_proxy(port: int) -> bool:
    """¿Es un proxy HTTP o solo un servidor web? Se pide CONNECT a un puerto cerrado de ESTA máquina
    (127.0.0.1:9): un proxy lo intenta y responde 200/502/503/504; un servidor web responde 400/404/405/501.
    No genera tráfico fuera del equipo."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1.5) as s:
            s.settimeout(2)
            s.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            head = s.recv(512)
    except OSError:
        return False
    m = re.match(rb"HTTP/\d\.\d (\d{3})", head)
    if not m:
        return False
    code = int(m.group(1))
    return code in (200, 502, 503, 504) or b"proxy" in head.lower()


# ── Tor ─────────────────────────────────────────────────────────────────────

def tor_protocolinfo(target) -> dict | None:
    """Pregunta PROTOCOLINFO al ControlPort/ControlSocket (permitido sin autenticar)."""
    try:
        if isinstance(target, str):
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(1)
            s.connect(target)
        else:
            s = socket.create_connection(target, timeout=1)
            s.settimeout(1)
        with s:
            s.sendall(b"PROTOCOLINFO 1\r\n")
            data = b""
            while b"250 OK" not in data and len(data) < 4096:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
    except OSError:
        return None
    text = data.decode(errors="replace")
    if not text.startswith("250-PROTOCOLINFO"):
        return None
    info = {"target": target if isinstance(target, str) else f"{target[0]}:{target[1]}"}
    m = re.search(r"METHODS=(\S+)", text)
    info["auth"] = m.group(1).split(",") if m else []
    m = re.search(r'Tor="([^"]+)"', text)
    info["version"] = m.group(1) if m else None
    m = re.search(r'COOKIEFILE="([^"]*)"', text)
    if m:
        info["cookie_file"] = m.group(1)
        info["cookie_readable"] = os.access(m.group(1), os.R_OK)
    return info


def parse_torrc() -> dict:
    keep = {"SocksPort", "ControlPort", "ControlSocket", "CookieAuthentication", "UseBridges",
            "ClientTransportPlugin", "ExitNodes", "ExcludeExitNodes", "ExcludeNodes", "EntryNodes",
            "StrictNodes", "DNSPort", "TransPort"}
    opts: dict[str, list[str]] = {}
    has_password = False
    for f in ["/etc/tor/torrc", *sorted(glob.glob("/etc/tor/torrc.d/*"))]:
        for line in (read(f) or "").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            key, _ign, val = line.partition(" ")
            if key == "HashedControlPassword":
                has_password = True
            elif key in keep:
                opts.setdefault(key, []).append(val.strip())
    opts["HashedControlPassword"] = has_password
    return opts


def _ports_from_torrc(values: list[str]) -> list[int]:
    ports = []
    for v in values:
        first = v.split()[0] if v.split() else ""
        if m := re.fullmatch(r"(?:[\d.]+:|\[[^\]]+\]:)?(\d+)", first):
            if int(m.group(1)):
                ports.append(int(m.group(1)))
    return ports


def detect_tor(loop_tcp: set[int], probes: dict[int, str], procs) -> dict:
    torrc = parse_torrc()
    control_ports = sorted(set(TOR_CONTROL_PORTS + _ports_from_torrc(torrc.get("ControlPort", []))))
    controls = []
    for port in control_ports:
        if port in loop_tcp and (info := tor_protocolinfo(("127.0.0.1", port))):
            controls.append(info)
    seen = set()
    for path in ["/run/tor/control", "/var/run/tor/control", *[v.split()[0].removeprefix("unix:")
                 for v in torrc.get("ControlSocket", []) if v]]:
        real = os.path.realpath(path)
        if real in seen or not os.path.exists(real):
            continue
        seen.add(real)
        if info := tor_protocolinfo(real):
            controls.append(info)
    return {
        "installed": bool(which("tor")),
        "running": any(c == "tor" for _ign, c in procs),
        "control": controls,
        "socks": sorted(p for p, kind in probes.items() if kind == "tor-socks"),
        "torrc": torrc,
        "browser": expand_globs(TOR_BROWSER_GLOBS),
        "transports": [b for b in ("obfs4proxy", "lyrebird", "snowflake-client") if which(b)],
    }


# ── red ─────────────────────────────────────────────────────────────────────

def detect_interfaces() -> list[dict]:
    ifaces = []
    base = Path("/sys/class/net")
    if not base.is_dir():
        return ifaces
    link_kinds = {}
    for l in json.loads(run(["ip", "-j", "-d", "link", "show"]) or "[]"):
        link_kinds[l.get("ifname")] = (l.get("linkinfo") or {}).get("info_kind")
    for d in sorted(base.iterdir()):
        name = d.name
        uevent = read(d / "uevent") or ""
        info_kind = link_kinds.get(name)
        if name == "lo":
            kind = "loopback"
        elif info_kind == "dummy":
            kind = "dummy"
        elif "DEVTYPE=wireguard" in uevent or info_kind == "wireguard":
            kind = "wireguard"
        elif (d / "tun_flags").exists():
            kind = "tun"
        elif name.startswith("ppp"):
            kind = "ppp"
        elif (d / "wireless").exists() or (d / "phy80211").exists():
            kind = "wifi"
        elif "DEVTYPE=bridge" in uevent or name.startswith(("veth", "docker", "virbr", "br-")):
            kind = "virtual"
        elif (d / "device").exists():
            kind = "ethernet"
        else:
            kind = "virtual"
        try:
            flags = int((read(d / "flags") or "0").strip(), 16)
        except ValueError:
            flags = 0
        assign = (read(d / "addr_assign_type") or "").strip()
        ifaces.append({
            "name": name,
            "kind": kind,
            "up": bool(flags & 0x1),
            "mac_origin": {"0": "permanente", "1": "aleatoria", "2": "copiada", "3": "fijada"}.get(assign, "?"),
        })
    return ifaces


def detect_routes() -> dict:
    v4 = []
    for line in (read("/proc/net/route") or "").splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == "00000000" and f[7] == "00000000":
            v4.append((int(f[6]), f[0]))
    v6 = []
    for line in (read("/proc/net/ipv6_route") or "").splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == "0" * 32 and f[1] == "00" and f[9] != "lo":
            v6.append((int(f[5], 16), f[9]))
    return {"ipv4_default": [i for _ign, i in sorted(v4)], "ipv6_default": [i for _ign, i in sorted(v6)]}


def detect_egress() -> dict:
    """Interfaz por la que saldría el tráfico. `ip route get` consulta al kernel sin enviar paquetes
    y, a diferencia de /proc/net/route, respeta las reglas de policy routing (p. ej. wg-quick)."""
    out = {}
    for fam, flag, target in (("ipv4", "-4", "1.1.1.1"), ("ipv6", "-6", "2606:4700:4700::1111")):
        m = re.search(r"\bdev (\S+)", run(["ip", flag, "route", "get", target]) or "")
        out[fam] = m.group(1) if m else None
    return out


def detect_ipv6() -> dict:
    """El kernel marca como scope global también las ULA (fc00::/7), que no salen a Internet."""
    global_ifaces, ula_ifaces = set(), set()
    for line in (read("/proc/net/if_inet6") or "").splitlines():
        f = line.split()
        if len(f) == 6 and f[3] == "00":
            addr = ipaddress.IPv6Address(bytes.fromhex(f[0]))
            (global_ifaces if addr.is_global else ula_ifaces).add(f[5])
    disabled = (read("/proc/sys/net/ipv6/conf/all/disable_ipv6") or "0").strip() == "1"
    return {"disabled": disabled, "global_ifaces": sorted(global_ifaces), "ula_ifaces": sorted(ula_ifaces)}


def detect_system() -> dict:
    osr = {}
    for line in (read("/etc/os-release") or "").splitlines():
        k, _ign, v = line.partition("=")
        osr[k] = v.strip().strip('"')
    proc_version = read("/proc/version") or ""
    container = None
    if os.path.exists("/.dockerenv"):
        container = "docker"
    elif os.path.exists("/run/.containerenv"):
        container = "podman"
    elif "container=" in (read("/proc/1/environ") or "").replace("\0", "\n"):
        container = "otro"
    virt = (run(["systemd-detect-virt"]) or "").strip() or None
    u = os.uname()
    return {
        "os": u.sysname, "distro": osr.get("PRETTY_NAME"), "distro_id": osr.get("ID"),
        "kernel": u.release, "arch": u.machine,
        "wsl": "microsoft" in proc_version.lower(),
        "virtualization": None if virt in (None, "none") else virt,
        "container": container,
    }


def socket_owners() -> dict[int, str]:
    """Mapea inodo de socket -> proceso, solo para procesos del usuario (sin root)."""
    owners = {}
    for d in glob.glob("/proc/[0-9]*"):
        try:
            fds = os.listdir(f"{d}/fd")
        except OSError:
            continue
        comm = (read(f"{d}/comm") or "?").strip()
        for fd in fds:
            try:
                link = os.readlink(f"{d}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                owners[int(link[8:-1])] = f"{comm} (pid {d.rsplit('/', 1)[1]})"
    return owners


def listening_detail() -> list[dict]:
    """Puertos TCP en escucha con dirección de enlace y proceso propietario cuando es visible."""
    owners = socket_owners()
    out = []
    for fname in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in (read(fname) or "").splitlines()[1:]:
            f = line.split()
            if len(f) < 10 or f[3] != "0A":
                continue
            addr_hex, _ign, port_hex = f[1].partition(":")
            try:
                addr = _decode_proc_addr(addr_hex)
            except ValueError:
                continue
            out.append({"addr": addr, "port": int(port_hex, 16), "owner": owners.get(int(f[9]))})
    return out


# ── VPN ─────────────────────────────────────────────────────────────────────

def _nm_split(line: str) -> list[str]:
    return [f.replace("\\:", ":") for f in re.split(r"(?<!\\):", line)]


def detect_networkmanager() -> list[dict] | None:
    out = run(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,ACTIVE", "connection", "show"])
    if out is None:
        return None
    conns = []
    for line in out.splitlines():
        f = _nm_split(line)
        if len(f) < 4:
            continue
        name, ctype, dev, active = f[:4]
        c = {"name": name, "type": ctype, "device": dev or None, "active": active == "yes"}
        if ctype == "vpn":
            st = run(["nmcli", "-t", "-g", "vpn.service-type", "connection", "show", name])
            if st:
                c["vpn_service"] = st.strip().rsplit(".", 1)[-1]
        conns.append(c)
    return conns


def nm_mac_policy() -> dict:
    settings = {}
    files = [*sorted(glob.glob("/usr/lib/NetworkManager/conf.d/*.conf")),
             "/etc/NetworkManager/NetworkManager.conf",
             *sorted(glob.glob("/etc/NetworkManager/conf.d/*.conf"))]
    for f in files:
        for line in (read(f) or "").splitlines():
            m = re.match(r"\s*(wifi\.cloned-mac-address|ethernet\.cloned-mac-address|"
                         r"wifi\.scan-rand-mac-address)\s*=\s*(\S+)", line)
            if m:
                settings[m.group(1)] = m.group(2)
    return settings


def detect_wireguard_configs() -> dict:
    try:
        names = sorted(p[:-5] for p in os.listdir("/etc/wireguard") if p.endswith(".conf"))
        return {"configs": names, "readable": True}
    except PermissionError:
        return {"configs": [], "readable": False}
    except FileNotFoundError:
        return {"configs": [], "readable": True}


def detect_vpn_providers() -> dict:
    found = {}
    for prov, (bins, status_cmd) in VPN_PROVIDERS.items():
        present = [b for b in bins if which(b)]
        if not present:
            continue
        entry = {"binary": present[0]}
        if status_cmd and (out := run(status_cmd, timeout=4)) and out.strip():
            entry["status"] = out.strip().splitlines()[0][:120]
        found[prov] = entry
    return found


# ── proxies ─────────────────────────────────────────────────────────────────

def detect_proxychains() -> dict | None:
    files = [os.environ.get("PROXYCHAINS_CONF_FILE"), HOME / ".proxychains/proxychains.conf",
             "/etc/proxychains4.conf", "/etc/proxychains.conf"]
    for f in filter(None, files):
        text = read(f)
        if text is None:
            continue
        mode, proxies, in_list = None, [], False
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            if line in ("dynamic_chain", "strict_chain", "random_chain", "round_robin_chain"):
                mode = line
            elif line.lower() == "[proxylist]":
                in_list = True
            elif in_list and len(parts := line.split()) >= 3 and parts[2].isdigit():
                proxies.append({"type": parts[0], "host": parts[1], "port": int(parts[2]),
                                "auth": len(parts) >= 5})
        return {"file": str(f), "mode": mode, "proxies": proxies}
    return None


def detect_desktop_proxy() -> dict | None:
    mode = run(["gsettings", "get", "org.gnome.system.proxy", "mode"])
    if mode and "auto" in mode:
        url = (run(["gsettings", "get", "org.gnome.system.proxy", "autoconfig-url"]) or "").strip().strip("'")
        return {"mode": "auto", "pac": redact_url(url) if url else _("WPAD (descubrimiento automático)")}
    if not mode or "manual" not in mode:
        return {"mode": mode.strip().strip("'")} if mode else None
    res = {"mode": "manual"}
    for kind in ("socks", "http", "https"):
        host = (run(["gsettings", "get", f"org.gnome.system.proxy.{kind}", "host"]) or "").strip().strip("'")
        port = (run(["gsettings", "get", f"org.gnome.system.proxy.{kind}", "port"]) or "0").strip()
        if host and port.isdigit() and int(port):
            res[kind] = f"{host}:{port}"
    return res


# ── DNS ─────────────────────────────────────────────────────────────────────

def detect_dns(loop_udp: set[int]) -> dict:
    resolv = read("/etc/resolv.conf") or ""
    info = {
        "resolv_conf": re.findall(r"^\s*nameserver\s+(\S+)", resolv, re.M),
        "resolv_conf_target": os.path.realpath("/etc/resolv.conf"),
        "resolved": None,
        "local_listener": 53 in loop_udp,
        "local_resolvers": [b for b in ("dnscrypt-proxy", "unbound", "stubby", "dnsmasq") if which(b)],
    }
    out = run(["resolvectl", "dns"])
    if out:
        links = {}
        for line in out.splitlines():
            key, _ign, servers = line.partition(":")
            m = re.match(r"Link \d+ \((.+)\)", key.strip())
            links[m.group(1) if m else key.strip()] = servers.split()
        status = run(["resolvectl", "status"]) or ""
        info["resolved"] = {"links": links, "dot": "+DNSOverTLS" in status, "dnssec": "+DNSSEC" in status}
    return info


# ── sistema ─────────────────────────────────────────────────────────────────

def detect_services() -> list[str] | None:
    out = run(["systemctl", "list-units", "--type=service", "--state=active",
               "--no-legend", "--plain", "--no-pager"])
    if out is None:
        return None
    names = [line.split()[0].removesuffix(".service") for line in out.splitlines() if line.strip()]
    return [n for n in names if n.lower().startswith(INTERESTING_SERVICES)]


def detect_identity() -> dict:
    tz = (read("/etc/timezone") or "").strip() or None
    if not tz and os.path.islink("/etc/localtime"):
        tz = os.readlink("/etc/localtime").split("zoneinfo/")[-1]
    return {"hostname": socket.gethostname(), "timezone": os.environ.get("TZ") or tz,
            "lang": os.environ.get("LANG")}


def detect_privileges() -> dict:
    groups = []
    for gid in os.getgroups():
        try:
            groups.append(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return {"root": os.geteuid() == 0, "groups": sorted(groups),
            "escalation": [b for b in ("sudo", "pkexec", "doas") if which(b)]}


def detect_geoip() -> dict:
    return {
        "mmdb": expand_globs(["/usr/share/GeoIP/*.mmdb", "/var/lib/GeoIP/*.mmdb",
                              "~/.local/share/GeoIP/*.mmdb", "~/.local/share/vela/*.mmdb"]),
        "tor_geoip": [p for p in ("/usr/share/tor/geoip", "/usr/share/tor/geoip6") if os.path.exists(p)],
    }


def discover() -> dict:
    procs = list_processes()
    loop_tcp = {p for a, p in listening_sockets("tcp") if is_local(a)}
    loop_udp = {p for a, p in listening_sockets("udp") if is_local(a)}
    torrc_socks = _ports_from_torrc(parse_torrc().get("SocksPort", []))
    ssh_ports = ssh_socks_tunnels(procs)
    probes = {p: probe_port(p) for p in sorted(loop_tcp & set(CANDIDATE_PROXY_PORTS + torrc_socks + ssh_ports))}

    env = {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "system": detect_system(),
        "listening": [l for l in listening_detail() if l["port"] in probes or not is_local(l["addr"])],
        "binaries": {cat: {n: p for n in names if (p := which(n))} for cat, names in BINARIES.items()},
        "processes": sorted({c for _ign, c in procs if c in INTERESTING_PROCESSES}),
        "services": detect_services(),
        "interfaces": detect_interfaces(),
        "routes": detect_routes(),
        "egress": detect_egress(),
        "ipv6": detect_ipv6(),
        "tor": detect_tor(loop_tcp, probes, procs),
        "vpn": {
            "providers": detect_vpn_providers(),
            "networkmanager": detect_networkmanager(),
            "wireguard": detect_wireguard_configs(),
            "openvpn_configs": expand_globs(OVPN_GLOBS),
        },
        "proxy": {
            "local": [{"port": p, "kind": k} for p, k in probes.items()],
            "ssh_tunnels": ssh_ports,
            "proxychains": detect_proxychains(),
            "env": {k: redact_url(v) for k in ("http_proxy", "https_proxy", "all_proxy",
                                               "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
                    if (v := os.environ.get(k))},
            "desktop": detect_desktop_proxy(),
        },
        "dns": detect_dns(loop_udp),
        "mac_policy": nm_mac_policy(),
        "identity": detect_identity(),
        "privileges": detect_privileges(),
        "geoip": detect_geoip(),
        "python": {
            "version": sys.version.split()[0],
            "modules": {m: importlib.util.find_spec(m) is not None for m in PY_MODULES},
        },
        "display": bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")),
    }
    from . import dns as dns_mod, protection
    kinds = {i["name"]: i["kind"] for i in env["interfaces"]}
    env["killswitch"] = protection.detect_killswitches(kinds)
    dsnap = dns_mod.snapshot()
    env["dns_effective"] = {"source": dsnap["effective_source"], "servers": dsnap["effective_servers"],
                            "encrypted": dsnap["encrypted"], "encryption": dsnap["encryption"]}
    return env


# ── decisiones ──────────────────────────────────────────────────────────────

def recommend(env: dict) -> tuple[list[dict], dict]:
    """Traduce lo detectado en avisos y en la configuración que usará el daemon."""
    notes: list[dict] = []
    cfg: dict = {"collectors": {}, "rotation": {}, "killswitch": {}, "geoip": {}, "ui": {}}

    def note(level: str, area: str, text: str):
        notes.append({"level": level, "area": area, "text": text})

    ifaces = {i["name"]: i for i in env["interfaces"]}
    kind_of = lambda name: ifaces.get(name, {}).get("kind")  # noqa: E731
    vpn_ifaces = [i["name"] for i in env["interfaces"] if i["kind"] in VPN_KINDS and i["up"]]
    egress4, egress6 = env["egress"]["ipv4"], env["egress"]["ipv6"]
    tunneled = kind_of(egress4) in VPN_KINDS
    physical = [n for n in env["routes"]["ipv4_default"] if kind_of(n) in PHYSICAL_KINDS] or \
               [i["name"] for i in env["interfaces"] if i["kind"] in PHYSICAL_KINDS and i["up"]]

    # IP pública
    cfg["collectors"]["publicip"] = {"enabled": True, "isp_iface": physical[0] if physical else None,
                                     "interval": "60s", "isp_interval": "5m"}
    if physical:
        note("ok", "IP pública", _("IP del router medida por {v1} (fuera del túnel); IP de salida medida por la ruta por defecto ({egress4})", v1=physical[0], egress4=egress4))
    else:
        note("warn", "IP pública", _("No hay interfaz física activa: solo se medirá la IP de salida"))

    # VPN
    vpn = env["vpn"]
    nm = vpn["networkmanager"] or []
    nm_vpns = [c["name"] for c in nm if c["type"] in ("vpn", "wireguard")]
    wg = vpn["wireguard"]
    can_escalate = env["privileges"]["root"] or bool(env["privileges"]["escalation"])
    if vpn_ifaces:
        note("ok", "VPN", _("Túnel activo: {v1}", v1=', '.join(vpn_ifaces)))
        if tunneled:
            note("ok", "VPN", _("El tráfico IPv4 sale por el túnel ({egress4})", egress4=egress4))
        else:
            note("warn", "VPN", _("Hay túnel activo pero la ruta IPv4 sale por {egress4} (¿split tunnel?)", egress4=egress4))
    for prov, info in vpn["providers"].items():
        note("ok", "VPN", f"Cliente {prov} detectado" + (f": {info['status']}" if info.get("status") else ""))
    if nm_vpns:
        note("ok", "VPN", _("{n} conexión(es) VPN en NetworkManager: {v2}", n=len(nm_vpns), v2=', '.join(nm_vpns)))
    if wg["configs"]:
        note("ok", "VPN", _("Configs WireGuard en /etc/wireguard: {v1}", v1=', '.join(wg['configs'])))
    elif not wg["readable"]:
        note("info", "VPN", _("/etc/wireguard existe pero no es legible sin root"))
    if vpn["openvpn_configs"]:
        note("ok", "VPN", _("{n} perfil(es) OpenVPN encontrados", n=len(vpn['openvpn_configs'])))

    driver, pool = None, []
    rotatable = [p for p in vpn["providers"] if p in ROTATABLE_PROVIDERS]
    if rotatable:
        driver, pool = rotatable[0], ["auto"]
    elif nm_vpns:
        driver, pool = "networkmanager", nm_vpns
    elif wg["configs"] and can_escalate:
        driver, pool = "wg-quick", wg["configs"]
    elif vpn["openvpn_configs"] and env["binaries"]["vpn"].get("openvpn") and can_escalate:
        driver, pool = "openvpn", vpn["openvpn_configs"]
    cfg["collectors"]["vpn"] = {"enabled": bool(vpn_ifaces or driver)}
    cfg["rotation"]["vpn"] = {"enabled": bool(driver), "driver": driver, "pool": pool,
                              "max_ttl": "45m", "jitter": "10m",
                              "no_repeat": min(10, max(len(pool) - 1, 0)) if pool != ["auto"] else 10,
                              "exclude_countries": []}
    if driver:
        note("ok", "VPN", _("Rotación de VPN con el driver «{driver}»", driver=driver))
        if pool != ["auto"] and len(pool) < 3:
            note("warn", "VPN", _("Solo hay {n} VPN(s) en el pool: la no repetición será muy limitada", n=len(pool)))
    else:
        note("off", "VPN", _("No se ha encontrado ninguna VPN que se pueda rotar"))

    # Tor
    tor = env["tor"]
    if tor["control"]:
        c = tor["control"][0]
        note("ok", "Tor", _("ControlPort en {target} (Tor {v3}), auth: {v5}", target=c['target'], v3=c.get('version') or '?', v5=','.join(c['auth'])))
        cfg["collectors"]["tor"] = {"enabled": True, "mode": "control", "control": c["target"]}
        cfg["rotation"]["tor"] = {"enabled": True, "driver": "newnym", "max_ttl": "10m", "jitter": "3m",
                                  "no_repeat_exit": 20, "exclude_exit_countries": []}
        if "NULL" in c["auth"]:
            note("warn", "Tor", _("ControlPort SIN autenticación: cualquier proceso local puede controlar Tor"))
        if c.get("cookie_file") and not c.get("cookie_readable") and "HASHEDPASSWORD" not in c["auth"]:
            note("warn", "Tor", _("No puedes leer {cookie_file}: añade tu usuario al grupo propietario (p. ej. `sudo usermod -aG debian-tor $USER`)", cookie_file=c['cookie_file']))
    elif tor["socks"]:
        port = tor["socks"][0]
        note("ok", "Tor", _("SocksPort en 127.0.0.1:{port} (sin ControlPort accesible)", port=port))
        note("info", "Tor", _("Se rotará el circuito con credenciales SOCKS aleatorias (IsolateSOCKSAuth); "
                            "para ver guard/middle/exit activa `ControlPort 9051` y `CookieAuthentication 1`"))
        cfg["collectors"]["tor"] = {"enabled": True, "mode": "socks", "socks": f"127.0.0.1:{port}"}
        cfg["rotation"]["tor"] = {"enabled": True, "driver": "socks-isolation", "max_ttl": "10m",
                                  "jitter": "3m", "no_repeat_exit": 20, "exclude_exit_countries": []}
    elif tor["installed"]:
        note("warn", "Tor", _("Tor está instalado pero no está en ejecución"))
    else:
        note("off", "Tor", _("Tor no detectado"))
    cfg["collectors"].setdefault("tor", {"enabled": False})
    cfg["rotation"].setdefault("tor", {"enabled": False})
    if tor["browser"]:
        note("info", "Tor", _("Tor Browser en {v1} (su ControlPort 9151 solo existe mientras está abierto)", v1=tor['browser'][0]))
    if any(v.strip() == "1" for v in tor["torrc"].get("UseBridges", [])):
        note("ok", "Tor", _("Usas bridges") + (f" ({', '.join(tor['transports'])})" if tor["transports"] else ""))
    if tor["torrc"].get("DNSPort"):
        note("ok", "Tor", _("DNSPort configurado: {v1}", v1=', '.join(tor['torrc']['DNSPort'])))

    # Proxies
    px = env["proxy"]
    tor_socks = {f"127.0.0.1:{p}" for p in tor["socks"]}
    proxies = [f"{'socks5' if p['kind'] == 'socks5' else 'http'}://127.0.0.1:{p['port']}"
               for p in px["local"] if p["kind"] in ("socks5", "http")]
    proxies += [f"socks5://127.0.0.1:{p}" for p in px["ssh_tunnels"]]
    if px["proxychains"]:
        pc = px["proxychains"]
        note("ok", "Proxy", _("proxychains ({file}, {v3}): {n} proxy(s)", file=pc['file'], v3=pc['mode'] or 'modo por defecto', n=len(pc['proxies'])))
        for p in pc["proxies"]:
            host = "127.0.0.1" if p["host"] == "localhost" else p["host"]
            if f"{host}:{p['port']}" not in tor_socks:
                proxies.append(f"{p['type']}://{host}:{p['port']}")
    for k, v in px["env"].items():
        note("info", "Proxy", _("Variable de entorno {k}={v}", k=k, v=v))
    if px["desktop"] and px["desktop"].get("mode") == "manual":
        note("info", "Proxy", _("Proxy del escritorio (GNOME) en modo manual"))
    kinds = {p["port"]: p["kind"] for p in px["local"]}
    for l in env.get("listening", []):
        if l["port"] in kinds and not ipaddress.ip_address(l["addr"]).is_loopback:
            what = _("Servidor web") if kinds[l["port"]] == "http-server" else "Proxy"
            note("warn", "Proxy", _("{what} en el puerto {port} escucha en {addr} (todas las interfaces): accesible desde la LAN", what=what, port=l['port'], addr=l['addr']) + (f" — {l['owner']}" if l.get("owner") else ""))
        if kinds.get(l["port"]) == "http-server":
            note("info", "Proxy", _("127.0.0.1:{port} es un servidor web, no un proxy (no acepta CONNECT)", port=l['port']))
    for p in px["local"]:
        if p["kind"] == "desconocido":
            note("info", "Proxy", _("Algo escucha en 127.0.0.1:{port} pero no responde como proxy", port=p['port']))
    proxies = list(dict.fromkeys(proxies))
    cfg["collectors"]["proxy"] = {"enabled": bool(proxies), "pool": proxies}
    cfg["rotation"]["proxy"] = {"enabled": len(proxies) >= 2, "driver": "local-forwarder", "pool": proxies,
                                "strategy": "lru", "max_ttl": "20m", "jitter": "5m"}
    if proxies:
        note("ok", "Proxy", _("{n} proxy(s) en el pool: {v2}", n=len(proxies), v2=', '.join(proxies)))
        if len(proxies) < 2:
            note("warn", "Proxy", _("Con un único proxy no se puede rotar"))
    else:
        note("off", "Proxy", _("No se han encontrado proxies"))

    # DNS
    dns = env["dns"]
    cfg["collectors"]["dns"] = {"enabled": True, "backend": "resolved" if dns["resolved"] else "resolv.conf",
                                "leaktest": True, "interval": "5m"}
    if dns["resolved"]:
        r = dns["resolved"]
        note("ok", "DNS", "systemd-resolved: " + "; ".join(f"{k}: {' '.join(v) or '-'}" for k, v in r["links"].items()))
        if r["dot"]:
            note("ok", "DNS", _("DNS-over-TLS activo"))
        if tunneled:
            for link, servers in r["links"].items():
                if link != "Global" and link not in vpn_ifaces and servers:
                    note("warn", "DNS", _("Posible fuga: {link} tiene resolvers propios ({v3}) mientras el tráfico va por el túnel", link=link, v3=' '.join(servers)))
    else:
        note("ok", "DNS", _("resolv.conf: {v1}", v1=' '.join(dns['resolv_conf']) or '(vacío)'))
        if tunneled:
            for s in dns["resolv_conf"]:
                try:
                    if ipaddress.ip_address(s.split("%")[0]).is_private and not is_local(s.split("%")[0]):
                        note("warn", "DNS", _("Posible fuga: el resolver {s} es de tu red local", s=s))
                except ValueError:
                    pass
    if dns["local_resolvers"]:
        note("info", "DNS", _("Resolvers locales instalados: {v1}", v1=', '.join(dns['local_resolvers'])))

    # IPv6
    v6 = env["ipv6"]
    if v6["disabled"]:
        note("ok", "IPv6", _("IPv6 desactivado en el sistema"))
    elif tunneled and egress6 and kind_of(egress6) not in VPN_KINDS:
        note("warn", "IPv6", _("FUGA IPv6: el IPv4 va por el túnel pero el IPv6 sale por {egress6}", egress6=egress6))
    elif v6["global_ifaces"]:
        note("info", "IPv6", _("Direcciones IPv6 globales en: {v1}", v1=', '.join(v6['global_ifaces'])))

    # Kill-switch de terceros
    ksx = env.get("killswitch") or {}
    if ksx.get("declared_by") and ksx.get("verified_ipv4"):
        rp = ksx["route_protection"]
        note("ok", "Kill-switch", _("{v0}: verificado — si el túnel cae, IPv4 {detail}; IPv6 {detail2}", v0=', '.join(ksx['declared_by']), detail=rp['ipv4']['detail'], detail2=rp['ipv6']['detail']))
        for c in ksx["clients"]:
            if (c.get("declared") or {}).get("killswitch") == 1:
                note("info", "Kill-switch", _("{client} en modo estándar: no protege si cierras la app o al reiniciar; el modo permanente sí", client=c['client']))
    elif ksx.get("declared_by"):
        note("warn", "Kill-switch", _("{v0}: declarado pero no verificable por rutas", v0=', '.join(ksx['declared_by'])))
    de = env.get("dns_effective") or {}
    for r in (de.get("encryption") or {}).get("resolvers") or []:
        note("ok" if r["encrypted"] else ("warn" if r["encrypted"] is False else "info"), "DNS",
             _("Resolver efectivo {addr}: {v3} ({transport})", addr=r['addr'], v3=r['provider'] or 'desconocido', transport=r['transport'])
             + (f" → {r['upstream']}" if r.get("upstream") else ""))
    up = (de.get("encryption") or {}).get("upstream_route")
    if up:
        note("ok" if up["dev"] in vpn_ifaces else "warn", "DNS",
             _("La conexión DoH hacia {ip} sale por {dev}", ip=up['ip'], dev=up['dev']))
    # Kill-switch propio
    fw = env["binaries"]["firewall"]
    backend = "nftables" if "nft" in fw else "iptables" if "iptables" in fw else None
    cfg["killswitch"] = {"enabled": bool(backend), "backend": backend}
    if backend:
        note("ok", "Kill-switch", _("Se usará {backend} con una tabla propia", backend=backend)
             + (_(" (convive con ufw/firewalld)") if {"ufw", "firewall-cmd"} & fw.keys() else ""))
        if not can_escalate:
            note("warn", "Kill-switch", _("Sin root, sudo ni pkexec: el kill-switch no se podrá aplicar"))
    else:
        note("warn", "Kill-switch", _("No hay nft ni iptables: no habrá kill-switch durante las rotaciones"))

    # MAC
    for i in env["interfaces"]:
        if i["kind"] in PHYSICAL_KINDS:
            level = "warn" if i["mac_origin"] == "permanente" else "ok"
            note(level, "Identidad", _("{name} ({kind}) usa MAC {mac_origin}", name=i['name'], kind=i['kind'], mac_origin=i['mac_origin']))
    for k, v in env["mac_policy"].items():
        note("info", "Identidad", f"NetworkManager {k}={v}")
    ident = env["identity"]
    note("info", "Identidad", _("hostname={hostname}, zona horaria={timezone}, idioma={lang} (se comparará con el país de salida)", hostname=ident['hostname'], timezone=ident['timezone'], lang=ident['lang']))

    # GeoIP
    geo = env["geoip"]
    cfg["geoip"] = {"mmdb": geo["mmdb"][0] if geo["mmdb"] else "",
                    "tor_geoip": geo["tor_geoip"][0] if geo["tor_geoip"] else ""}
    if geo["mmdb"]:
        note("ok", "GeoIP", _("Base offline: {v1}", v1=geo['mmdb'][0]))
    elif geo["tor_geoip"]:
        note("info", "GeoIP", _("Se usará la base GeoIP de Tor (solo país; el mapa marcará el centro del país)"))
    else:
        note("warn", "GeoIP", _("Sin base GeoIP offline: descarga GeoLite2-City o dbip-city-lite (.mmdb)"))

    # Interfaces de usuario y dependencias
    mods = env["python"]["modules"]
    try:
        import curses  # noqa: F401
        has_curses = True
    except ImportError:
        has_curses = False
    cfg["ui"] = {"cli": True, "tui": has_curses, "gui": env["display"]}
    note("ok", "Interfaz", _("CLI disponible"))
    note("ok" if has_curses else "warn", "Interfaz", "TUI " + (_("disponible (curses)") if has_curses else _("sin curses")))
    note("ok" if env["display"] else "info", "Interfaz", "GUI " + ("disponible" if env["display"] else
                                                                  _("sin entorno gráfico (accesible por URL local)")))
    # El núcleo solo usa la biblioteca estándar; estos módulos son mejoras opcionales.
    optional = {"geoip2": _("ciudad y ASN con bases .mmdb"), "sqlcipher3": _("cifrado real de la base de datos")}
    missing = [f"{m} ({why})" for m, why in optional.items() if not mods.get(m)]
    if missing:
        note("info", "Dependencias", _("Opcionales no instaladas: ") + "; ".join(missing))

    return notes, cfg


# ── clasificación de capacidades ────────────────────────────────────────────

def capabilities(env: dict) -> list[dict]:
    """Clasifica cada capacidad: operativa / detectada_inactiva / sin_permisos / no_disponible /
    no_verificable. Distingue cliente instalado, configuración, túnel activo y tráfico por el túnel."""
    caps: list[dict] = []

    def cap(cid, area, status, detail):
        caps.append({"id": cid, "area": area, "status": status, "detail": detail})

    ifaces = {i["name"]: i for i in env["interfaces"]}
    up_tunnels = [i["name"] for i in env["interfaces"] if i["kind"] in VPN_KINDS and i["up"]]
    egress_kind = ifaces.get(env["egress"]["ipv4"], {}).get("kind")
    root = env["privileges"]["root"]

    cap("net.interfaces", "Red", OPERATIVA if ifaces else NO_DISPONIBLE, _("{n} interfaces vía /sys", n=len(ifaces)))
    cap("net.routes", "Red", OPERATIVA if env["binaries"]["identity"].get("ip") else NO_VERIFICABLE,
        _("ip -j route/rule (policy routing incluido)") if env["binaries"]["identity"].get("ip") else _("sin iproute2"))
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        s.close()
        cap("net.events", "Red", OPERATIVA, _("eventos netlink (rtnetlink) disponibles"))
    except (OSError, AttributeError):
        cap("net.events", "Red", NO_DISPONIBLE, _("sin netlink: se usará sondeo periódico"))
    cap("net.public_ip.direct", "Red", NO_VERIFICABLE, _("requiere consentimiento (expone tu IP real al servicio de eco)"))
    cap("net.router_wan", "Red", NO_VERIFICABLE, _("UPnP-IGD: se comprueba en tiempo de ejecución (solo LAN)"))

    # VPN
    wg_up = [n for n in up_tunnels if ifaces[n]["kind"] == "wireguard"]
    wg = env["vpn"]["wireguard"]
    if wg_up:
        cap("vpn.wireguard", "VPN", OPERATIVA, _("túnel activo: {v1}", v1=', '.join(wg_up)))
    elif wg["configs"]:
        cap("vpn.wireguard", "VPN", INACTIVA, f"configs: {', '.join(wg['configs'])}")
    elif not wg["readable"]:
        cap("vpn.wireguard", "VPN", SIN_PERMISOS, _("/etc/wireguard no legible sin root"))
    elif env["binaries"]["vpn"].get("wg"):
        cap("vpn.wireguard", "VPN", INACTIVA, _("wireguard-tools instalado, sin configuraciones"))
    else:
        cap("vpn.wireguard", "VPN", NO_DISPONIBLE, _("no instalado"))
    ovpn_running = "openvpn" in env["processes"]
    if ovpn_running:
        cap("vpn.openvpn", "VPN", OPERATIVA, _("proceso openvpn en ejecución"))
    elif env["vpn"]["openvpn_configs"]:
        cap("vpn.openvpn", "VPN", INACTIVA, f"{len(env['vpn']['openvpn_configs'])} perfiles")
    elif env["binaries"]["vpn"].get("openvpn"):
        cap("vpn.openvpn", "VPN", INACTIVA, _("openvpn instalado, sin perfiles ni túneles"))
    else:
        cap("vpn.openvpn", "VPN", NO_DISPONIBLE, _("no instalado"))
    nm = env["vpn"]["networkmanager"]
    if nm is None:
        cap("vpn.networkmanager", "VPN", NO_DISPONIBLE, _("nmcli no disponible"))
    else:
        vpns = [c for c in nm if c["type"] in ("vpn", "wireguard")]
        active = [c["name"] for c in vpns if c["active"]]
        if active:
            cap("vpn.networkmanager", "VPN", OPERATIVA, f"activa: {', '.join(active)}")
        elif vpns:
            cap("vpn.networkmanager", "VPN", INACTIVA, _("{n} conexiones VPN configuradas", n=len(vpns)))
        else:
            cap("vpn.networkmanager", "VPN", INACTIVA, _("NetworkManager presente, sin conexiones VPN"))
    ks_clients = {c["client"].lower(): c for c in (env.get("killswitch") or {}).get("clients", [])}
    for prov, info in env["vpn"]["providers"].items():
        client = ks_clients.get(prov)
        conns = [v for v in (client or {}).get("vpn_connections", []) if v["active"]]
        if conns:
            cap(f"vpn.{prov}", "VPN", OPERATIVA, f"conectado: {conns[0]['name']} ({conns[0]['device']})")
        elif client and client.get("vpn_connections") is not None and not conns and info["binary"]:
            cap(f"vpn.{prov}", "VPN", INACTIVA, _("{binary} instalado, sin conexión activa", binary=info['binary']))
        else:
            cap(f"vpn.{prov}", "VPN", OPERATIVA if info.get("status") else NO_VERIFICABLE,
                info.get("status") or _("{binary} instalado; estado no consultable sin sesión/permiso", binary=info['binary']))
    if up_tunnels:
        cap("vpn.traffic", "VPN", OPERATIVA if egress_kind in VPN_KINDS else INACTIVA,
            _("la ruta por defecto usa el túnel") if egress_kind in VPN_KINDS else
            _("hay túnel ({v1}) pero la ruta por defecto no lo usa", v1=', '.join(up_tunnels)))

    # Tor
    tor = env["tor"]
    if tor["control"]:
        c = tor["control"][0]
        cookie_ok = c.get("cookie_readable", True) or "HASHEDPASSWORD" in c["auth"]
        cap("tor.control", "Tor", OPERATIVA if cookie_ok else SIN_PERMISOS,
            f"{c['target']} Tor {c.get('version')}" + ("" if cookie_ok else _(" — cookie no legible")))
        cap("tor.circuits", "Tor", OPERATIVA if cookie_ok else SIN_PERMISOS,
            _("circuitos, streams y relays guard/middle/exit observables"))
        cap("tor.newnym", "Tor", OPERATIVA if cookie_ok else SIN_PERMISOS,
            _("SIGNAL NEWNYM (respetando el rate-limit de Tor; no garantiza una IP distinta)"))
    elif tor["running"]:
        cap("tor.control", "Tor", NO_DISPONIBLE, _("Tor en ejecución sin ControlPort accesible"))
    else:
        cap("tor.control", "Tor", NO_DISPONIBLE if not tor["installed"] else INACTIVA, _("Tor no está en ejecución"))
    cap("tor.socks", "Tor", OPERATIVA if tor["socks"] else NO_DISPONIBLE,
        ", ".join(f"127.0.0.1:{p}" for p in tor["socks"]) or _("sin SocksPort detectado"))
    if tor["browser"]:
        open_tb = 9150 in tor["socks"]
        cap("tor.browser", "Tor", OPERATIVA if open_tb else INACTIVA,
            _("Tor Browser abierto (solo observación; su rotación es 'Nueva identidad' en el navegador)")
            if open_tb else _("Tor Browser instalado, cerrado"))

    # Proxy
    for p in env["proxy"]["local"]:
        if p["kind"] in ("socks5", "http"):
            cap(f"proxy.local.{p['port']}", "Proxy", OPERATIVA, f"{p['kind']} en 127.0.0.1:{p['port']}")
    pc = env["proxy"]["proxychains"]
    cap("proxy.proxychains", "Proxy", OPERATIVA if pc else NO_DISPONIBLE,
        f"{pc['file']}: {len(pc['proxies'])} proxies" if pc else _("sin configuración de proxychains"))
    desk = env["proxy"]["desktop"] or {}
    cap("proxy.system", "Proxy", OPERATIVA if desk.get("mode") in ("manual", "auto") else INACTIVA,
        _("proxy del escritorio: {v1}", v1=desk.get('mode', 'desconocido')) + (f", PAC {desk['pac']}" if desk.get("pac") else ""))
    cap("proxy.env", "Proxy", OPERATIVA if env["proxy"]["env"] else INACTIVA,
        ", ".join(env["proxy"]["env"]) or _("sin variables *_proxy"))

    # DNS
    dns = env["dns"]
    cap("dns.resolved", "DNS", OPERATIVA if dns["resolved"] else NO_DISPONIBLE,
        _("systemd-resolved por enlace") if dns["resolved"] else _("solo resolv.conf"))
    cap("dns.dot", "DNS", OPERATIVA if dns["resolved"] and dns["resolved"]["dot"] else INACTIVA,
        _("DNS-over-TLS en systemd-resolved"))
    de = env.get("dns_effective") or {}
    res = (de.get("encryption") or {}).get("resolvers") or []
    desc = ", ".join(f"{r['addr']} {r['provider'] or '?'} ({r['transport']})" for r in res) or _("sin resolvers")
    cap("dns.encrypted", "DNS", {True: OPERATIVA, False: INACTIVA, None: NO_VERIFICABLE}[de.get("encrypted")],
        _("efectivo vía {v1}: {desc}", v1=de.get('source'), desc=desc))
    for b in (de.get("encryption") or {}).get("browsers") or []:
        cap(f"dns.browser.{b['browser']}", "DNS", OPERATIVA, _("DoH propio del navegador: {mode} {uri}", mode=b['mode'], uri=b['uri']))
    cap("dns.leak_active", "DNS", NO_VERIFICABLE, _("test activo de fugas: requiere consentimiento"))

    # Kill-switch de terceros (verificado por rutas) y propio (nftables)
    ks = env.get("killswitch") or {}
    rp = ks.get("route_protection") or {}
    if ks.get("declared_by") and ks.get("verified_ipv4"):
        cap("killswitch.client", "Protección", OPERATIVA,
            _("{v0}: verificado por rutas (IPv4 {state}, IPv6 {state2})", v0=', '.join(ks['declared_by']), state=rp['ipv4']['state'], state2=rp['ipv6']['state']))
    elif ks.get("declared_by"):
        cap("killswitch.client", "Protección", NO_VERIFICABLE,
            _("{v0}: declarado, no verificable por rutas (¿firewall?)", v0=', '.join(ks['declared_by'])))
    elif up_tunnels:
        cap("killswitch.client", "Protección", INACTIVA if not ks.get("verified_ipv4") else OPERATIVA,
            rp.get("ipv4", {}).get("detail", _("sin kill-switch de cliente")))
    else:
        cap("killswitch.client", "Protección", NO_DISPONIBLE, _("ningún cliente VPN con kill-switch detectado"))
    fw = env["binaries"]["firewall"]
    if "nft" in fw or "iptables" in fw:
        cap("killswitch.own", "Protección", OPERATIVA if root else SIN_PERMISOS,
            ("nftables" if "nft" in fw else "iptables") + ("" if root else _(" — requiere sudo/pkexec con confirmación")))
    else:
        cap("killswitch.own", "Protección", NO_DISPONIBLE, _("sin nft ni iptables"))

    # Geo / almacenamiento / interfaces
    geo = env["geoip"]
    mods = env["python"]["modules"]
    cap("geo.country", "Geo", OPERATIVA if geo["tor_geoip"] or geo["mmdb"] else NO_DISPONIBLE,
        _("base geoip de Tor") if geo["tor_geoip"] else ("mmdb" if geo["mmdb"] else _("sin base offline")))
    cap("geo.city_asn", "Geo", OPERATIVA if geo["mmdb"] and mods.get("geoip2") else NO_DISPONIBLE,
        "GeoLite2/DB-IP .mmdb + geoip2" if geo["mmdb"] else _("sin .mmdb de ciudad/ASN (instálalo para ASN y ciudad)"))
    cap("storage.sqlite", "Datos", OPERATIVA, _("SQLite local con permisos 0600"))
    cap("storage.encryption", "Datos", OPERATIVA if mods.get("sqlcipher3") else NO_DISPONIBLE,
        "SQLCipher" if mods.get("sqlcipher3") else _("sin SQLCipher: la base NO está cifrada (solo permisos de archivo)"))
    cap("ui.cli", "Interfaz", OPERATIVA, "argparse")
    try:
        import curses  # noqa: F401
        cap("ui.tui", "Interfaz", OPERATIVA, _("curses (stdlib)"))
    except ImportError:
        cap("ui.tui", "Interfaz", NO_DISPONIBLE, _("curses no disponible"))
    cap("ui.gui", "Interfaz", OPERATIVA if env["display"] else INACTIVA,
        _("servidor web local en 127.0.0.1 + navegador") if env["display"] else _("sin entorno gráfico (accesible por URL)"))
    return caps


# ── salida ──────────────────────────────────────────────────────────────────

SYMBOL = {"ok": "✔", "warn": "⚠", "off": "·", "info": "ℹ"}
COLOR = {"ok": "32", "warn": "33", "off": "90", "info": "36"}


def render(notes: list[dict], color: bool) -> str:
    lines, area = [], None
    paint = (lambda lvl, s: f"\033[{COLOR[lvl]}m{s}\033[0m") if color else (lambda lvl, s: s)
    for n in notes:
        if n["area"] != area:
            area = n["area"]
            lines.append(f"\n\033[1m{area}\033[0m" if color else f"\n{area}")
        lines.append(f"  {paint(n['level'], SYMBOL[n['level']])} {n['text']}")
    warns = sum(n["level"] == "warn" for n in notes)
    lines.append(f"\n{warns} aviso(s).")
    return "\n".join(lines).lstrip("\n")


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    return json.dumps("" if v is None else str(v), ensure_ascii=False)


def to_toml(cfg: dict, prefix: str = "") -> list[str]:
    lines = []
    scalars = {k: v for k, v in cfg.items() if not isinstance(v, dict)}
    if prefix and scalars:
        lines.append(f"[{prefix}]")
    for k, v in scalars.items():
        lines.append(f"{k} = {_toml_value(v)}")
    if scalars:
        lines.append("")
    for k, v in cfg.items():
        if isinstance(v, dict):
            lines += to_toml(v, f"{prefix}.{k}" if prefix else k)
    return lines


def write_config(cfg: dict, path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise SystemExit(_("{path} ya existe (usa --force para sobrescribirlo)", path=path))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    header = [f"# Generado por `vela discover` el {dt.datetime.now().astimezone():%Y-%m-%d %H:%M}.",
              "# Edítalo a tu gusto; vuelve a ejecutar discover si cambias de herramientas.", ""]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(header + to_toml(cfg)))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vela discover",
                                 description=_("Detecta VPN, Tor, proxies, DNS y firewall disponibles en el sistema."))
    ap.add_argument("--json", action="store_true", help=_("salida completa en JSON"))
    ap.add_argument("--write-config", metavar="RUTA", type=Path, help=_("genera un config.toml adaptado al sistema"))
    ap.add_argument("--force", action="store_true", help=_("sobrescribe el config si ya existe"))
    args = ap.parse_args(argv)

    env = discover()
    notes, cfg = recommend(env)
    if args.json:
        print(json.dumps({"environment": env, "capabilities": capabilities(env), "notes": notes, "config": cfg},
                         indent=2, ensure_ascii=False))
    else:
        print(render(notes, color=sys.stdout.isatty()))
    if args.write_config:
        path = args.write_config.expanduser()
        write_config(cfg, path, args.force)
        print(_("\nConfiguración escrita en {path}", path=path), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
