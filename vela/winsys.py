"""Capa de sistema para Windows (rama windows-lite).

Sustituye lo que en Linux sale de /proc, `ip`, `resolvectl` o NetworkManager, devolviendo EXACTAMENTE
los mismos formatos de datos, para que el motor, los avisos, la GUI web y la CLI funcionen sin cambios.

Fuentes (todas de solo lectura, sin privilegios de administrador):
  * conexiones TCP y su proceso: GetExtendedTcpTable (iphlpapi, la misma API que `netstat -ano`);
  * nombres de proceso: CreateToolhelp32Snapshot;
  * interfaces, direcciones, rutas, ruta efectiva, DNS, vecinos y tráfico: PowerShell (módulos
    NetTCPIP / NetAdapter / DnsClient), en UNA llamada por refresco para no pagar el arranque varias veces;
  * DoH del sistema: Get-DnsClientDohServerAddress + registro (EnableAutoDoh).

Las funciones `parse_*` / `build_*` son puras (sin llamadas al sistema) y se prueban en cualquier SO.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import struct
import subprocess
import sys

from .i18n import _
from .util import now, which

WINDOWS = sys.platform == "win32"

# ── PowerShell ──────────────────────────────────────────────────────────────

def ps(script: str, timeout: float = 25):
    """Ejecuta PowerShell sin perfil ni ventana y devuelve el JSON que imprima (o None)."""
    exe = which("powershell.exe") or which("pwsh.exe") or which("powershell") or which("pwsh")
    if not exe:
        return None
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        p = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command",
                            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script],
                           capture_output=True, timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = p.stdout.decode("utf-8", "replace").strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except ValueError:
        return None


def _list(x) -> list:
    """ConvertTo-Json devuelve un objeto suelto cuando solo hay un elemento."""
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


# ── conexiones TCP (GetExtendedTcpTable) ────────────────────────────────────

AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
TCP_STATES = {1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECV", 5: "ESTABLISHED", 6: "FIN_WAIT1",
              7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB"}
ACTIVE_STATES = {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}     # las mismas que considera leakwatch en Linux


def _port(dw: int) -> int:
    """Los puertos van en los 16 bits bajos del DWORD, en orden de red."""
    return socket.ntohs(dw & 0xFFFF)


def parse_tcp4(buf: bytes) -> list[dict]:
    """MIB_TCPTABLE_OWNER_PID: DWORD n + n × {state, localAddr, localPort, remoteAddr, remotePort, pid}."""
    n = struct.unpack_from("<I", buf, 0)[0]
    rows = []
    for i in range(n):
        st, la, lp, ra, rp, pid = struct.unpack_from("<IIIIII", buf, 4 + i * 24)
        rows.append({"proto": "tcp", "state": TCP_STATES.get(st, str(st)),
                     "local": socket.inet_ntoa(struct.pack("<I", la)), "lport": _port(lp),
                     "remote": socket.inet_ntoa(struct.pack("<I", ra)), "rport": _port(rp), "pid": pid})
    return rows


def parse_tcp6(buf: bytes) -> list[dict]:
    """MIB_TCP6TABLE_OWNER_PID: {localAddr[16], localScope, localPort, remoteAddr[16], remoteScope,
    remotePort, state, pid} = 56 bytes por fila."""
    n = struct.unpack_from("<I", buf, 0)[0]
    rows = []
    for i in range(n):
        o = 4 + i * 56
        la = buf[o:o + 16]
        _ls, lp = struct.unpack_from("<II", buf, o + 16)
        ra = buf[o + 24:o + 40]
        _rs, rp, st, pid = struct.unpack_from("<IIII", buf, o + 40)

        def ip6(raw):
            a = ipaddress.IPv6Address(raw)
            return str(a.ipv4_mapped or a)
        rows.append({"proto": "tcp", "state": TCP_STATES.get(st, str(st)), "local": ip6(la), "lport": _port(lp),
                     "remote": ip6(ra), "rport": _port(rp), "pid": pid})
    return rows


def _tcp_table(family: int) -> bytes:
    import ctypes
    from ctypes import wintypes
    fn = ctypes.windll.iphlpapi.GetExtendedTcpTable
    size = wintypes.DWORD(0)
    fn(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0)
    for _attempt in range(5):
        buf = ctypes.create_string_buffer(size.value)
        if fn(buf, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            return buf.raw
    return b"\0\0\0\0"


def tcp_rows() -> list[dict]:
    if not WINDOWS:
        return []
    return parse_tcp4(_tcp_table(AF_INET)) + parse_tcp6(_tcp_table(AF_INET6))


def read_sockets(rows: list[dict] | None = None) -> list[dict]:
    """Conexiones activas con el formato de leakwatch.read_sockets(). En Windows el «inodo» es el PID:
    así leakwatch.classify() resuelve el programa con el mismo mapa {clave: (pid, nombre)}."""
    rows = tcp_rows() if rows is None else rows
    return [{"proto": "tcp", "local": r["local"], "lport": r["lport"], "remote": r["remote"], "rport": r["rport"],
             "state": r["state"], "uid": None, "inode": r["pid"]} for r in rows if r["state"] in ACTIVE_STATES]


def listening(rows: list[dict] | None = None) -> list[tuple[str, int, int]]:
    rows = tcp_rows() if rows is None else rows
    return [(r["local"], r["lport"], r["pid"]) for r in rows if r["state"] == "LISTEN"]


# ── procesos (Toolhelp32) ───────────────────────────────────────────────────

def process_names() -> dict[int, str]:
    """PID → nombre del ejecutable sin «.exe» (visible para todos los procesos sin privilegios)."""
    if not WINDOWS:
        return {}
    import ctypes
    from ctypes import wintypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_wchar * 260)]
    k32 = ctypes.windll.kernel32
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)          # TH32CS_SNAPPROCESS
    out = {}
    if snap in (None, wintypes.HANDLE(-1).value):
        return out
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out[e.th32ProcessID] = clean_exe(e.szExeFile)
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


def clean_exe(name: str) -> str:
    n = os.path.basename(name or "")
    return n[:-4] if n.lower().endswith(".exe") else n


def owners(wanted: set[int] | None = None) -> dict[int, tuple[int, str]]:
    names = process_names()
    keys = wanted if wanted is not None else set(names)
    return {pid: (pid, names[pid]) for pid in keys if pid in names}


# ── interfaces y rutas ──────────────────────────────────────────────────────

NET_SCRIPT = r"""
$ad = Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name,InterfaceDescription,ifIndex,Status,MacAddress,PhysicalMediaType,MediaType,Virtual,HardwareInterface,MtuSize
$ip = Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,InterfaceIndex,IPAddress,PrefixLength,@{n='Family';e={[string]$_.AddressFamily}}
$rt = Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0' -ErrorAction SilentlyContinue | Select-Object InterfaceAlias,InterfaceIndex,NextHop,RouteMetric,@{n='Family';e={[string]$_.AddressFamily}}
function Eg($t) { $r = @(Find-NetRoute -RemoteIPAddress $t -ErrorAction SilentlyContinue); if ($r.Count -ge 2) { @{dev=$r[0].InterfaceAlias; src=$r[0].IPAddress; gateway=$r[1].NextHop} } }
@{adapters=@($ad); addresses=@($ip); routes=@($rt); egress4=(Eg '1.1.1.1'); egress6=(Eg '2606:4700:4700::1111')} | ConvertTo-Json -Depth 4 -Compress
"""

VPN_HINTS = {
    "wireguard": ("wireguard", "wintun", "nordlynx", "mullvad", "protonvpn", "proton vpn", "cloudflare warp",
                  "tailscale", "netbird"),
    "tun": ("tap-windows", "tap-protonvpn", "tap adapter", "openvpn", "ovpn", "zerotier", "fortinet", "anyconnect",
            "globalprotect", "pangp", "juniper", "pulse secure", "softether", "hamachi", "expressvpn", "surfshark",
            "windscribe", "private internet access", "pia"),
    "ppp": ("wan miniport", "ras async", "ppp", "pptp", "l2tp", "sstp", "ikev2"),
}
VIRTUAL_HINTS = ("hyper-v", "vethernet", "virtualbox", "vmware", "docker", "wsl", "loopback", "bluetooth",
                 "kernel debug", "teredo", "isatap", "6to4", "npcap")


def classify_adapter(a: dict) -> str:
    text = f"{a.get('Name') or ''} {a.get('InterfaceDescription') or ''}".lower()
    for kind, hints in VPN_HINTS.items():
        if any(h in text for h in hints):
            return kind
    if "loopback" in text:
        return "loopback"
    if any(h in text for h in VIRTUAL_HINTS) or a.get("Virtual") is True:
        return "virtual"
    media = f"{a.get('PhysicalMediaType') or ''} {a.get('MediaType') or ''}".lower()
    if "802.11" in media or any(h in text for h in ("wi-fi", "wifi", "wireless", "wlan")):
        return "wifi"
    if a.get("HardwareInterface") is False:
        return "virtual"
    return "ethernet"


def _family(v) -> str:
    s = str(v).lower()
    return "ipv6" if s in ("23", "ipv6") else "ipv4"


def build_network(data: dict | None) -> dict:
    """PowerShell (NET_SCRIPT) → mismo formato que network.snapshot() en Linux."""
    from .network import classify_ip
    from .discovery import VPN_KINDS
    data = data or {}
    ifaces: dict[str, dict] = {}
    for a in _list(data.get("adapters")):
        name = a.get("Name")
        if not name:
            continue
        up = str(a.get("Status") or "").lower() in ("up", "1", "connected")
        ifaces[name] = {"name": name, "kind": classify_adapter(a), "up": up, "mac_origin": "?",
                        "description": a.get("InterfaceDescription"), "addrs": [],
                        "operstate": "UP" if up else "DOWN", "mtu": a.get("MtuSize")}
    for x in _list(data.get("addresses")):
        name = x.get("InterfaceAlias")
        addr = str(x.get("IPAddress") or "").split("%")[0]
        if not addr:
            continue
        if name not in ifaces:
            if addr.startswith(("127.", "::1")):
                continue                                   # loopback de Windows: no es una interfaz real
            ifaces[name] = {"name": name, "kind": "virtual", "up": True, "mac_origin": "?", "addrs": [],
                            "operstate": "UP", "mtu": None}
        ifaces[name]["addrs"].append({"family": _family(x.get("Family")), "addr": addr,
                                      "prefix": x.get("PrefixLength"), "class": classify_ip(addr)})
    routes = {"ipv4_default": [], "ipv6_default": []}
    for r in _list(data.get("routes")):
        key = "ipv6_default" if _family(r.get("Family")) == "ipv6" else "ipv4_default"
        routes[key].append({"dev": r.get("InterfaceAlias"), "gateway": r.get("NextHop"),
                            "metric": r.get("RouteMetric") or 0, "table": "main"})
    for k in routes:
        routes[k].sort(key=lambda r: r["metric"])

    def eg(e):
        if not e or not e.get("dev"):
            return None
        gw = e.get("gateway")
        return {"dev": e["dev"], "src": e.get("src"), "gateway": None if gw in ("0.0.0.0", "::") else gw, "table": "main"}
    egress = {"ipv4": eg(data.get("egress4")), "ipv6": eg(data.get("egress6"))}
    kind = lambda dev: ifaces.get(dev, {}).get("kind")  # noqa: E731
    tunnels = [n for n, i in ifaces.items() if i["kind"] in VPN_KINDS and i["up"]]
    e4, e6 = egress["ipv4"] or {}, egress["ipv6"] or {}
    return {
        "ts": now(), "interfaces": list(ifaces.values()), "routes": routes, "policy_rules": [],
        "egress": egress, "egress_kind": {"ipv4": kind(e4.get("dev")), "ipv6": kind(e6.get("dev"))},
        "local_ip": e4.get("src"), "gateway": e4.get("gateway"), "tunnels": tunnels,
        "via_tunnel": {"ipv4": kind(e4.get("dev")) in VPN_KINDS if e4 else None,
                       "ipv6": kind(e6.get("dev")) in VPN_KINDS if e6 else None},
        "ipv6_internet": bool(e6) and any(a["class"] == "pública" for a in ifaces.get(e6.get("dev"), {}).get("addrs", [])),
    }


def network_snapshot() -> dict:
    return build_network(ps(NET_SCRIPT))


# ── DNS ─────────────────────────────────────────────────────────────────────

DNS_SCRIPT = r"""
$s = Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias,InterfaceIndex,@{n='Family';e={[string]$_.AddressFamily}},ServerAddresses
$d = @()
if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) { $d = Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | Select-Object ServerAddress,DohTemplate,AutoUpgrade,AllowFallbackToUdp }
$auto = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableAutoDoh -ErrorAction SilentlyContinue).EnableAutoDoh
@{servers=@($s); doh=@($d); auto=$auto} | ConvertTo-Json -Depth 4 -Compress
"""

KNOWN_DNS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google", "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9", "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
    "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "10.2.0.1": "Proton VPN", "10.64.0.1": "Mullvad",
    "100.64.0.1": "Mullvad",
}


def build_dns(data: dict | None, egress_dev: str | None = None) -> dict:
    """PowerShell (DNS_SCRIPT) → mismo formato que dns.snapshot() en Linux."""
    from .dns import classify_server
    data = data or {}
    links: dict[str, dict] = {}
    for s in _list(data.get("servers")):
        name = s.get("InterfaceAlias")
        servers = [x for x in _list(s.get("ServerAddresses")) if x and not str(x).lower().startswith("fec0:")]
        if not name or not servers:
            continue
        e = links.setdefault(name, {"servers": [], "current": None, "domains": [], "default_route": True,
                                    "dot": False, "dnssec": "no"})
        e["servers"] += [x for x in servers if x not in e["servers"]]
    for e in links.values():
        e["server_classes"] = sorted({classify_server(x) for x in e["servers"]})
    if egress_dev and egress_dev in links:
        order = [egress_dev] + [n for n in links if n != egress_dev]
    else:
        order = list(links)
    effective = []
    for n in order:
        effective += [x for x in links[n]["servers"] if x not in effective]
    doh = {str(d.get("ServerAddress")): d for d in _list(data.get("doh")) if d.get("ServerAddress")}
    auto = str(data.get("auto") or "") == "2"
    resolvers = []
    for srv in effective:
        entry = {"addr": srv, "provider": KNOWN_DNS.get(srv), "transport": _("DNS en claro (UDP/TCP 53)"),
                 "encrypted": False, "upstream": None, "evidence": None}
        try:
            ip = ipaddress.ip_address(srv.split("%")[0])
        except ValueError:
            resolvers.append({**entry, "encrypted": None, "evidence": _("dirección no reconocida")})
            continue
        d = doh.get(srv)
        if d and (auto or d.get("AutoUpgrade") is True):
            entry.update(transport="DoH", encrypted=True if d.get("AllowFallbackToUdp") is not True else None,
                         upstream=d.get("DohTemplate"),
                         evidence=_("DoH de Windows (Get-DnsClientDohServerAddress)"))
        elif ip.is_loopback:
            entry.update(provider=_("resolver local"), encrypted=None, evidence=_("resolver local de origen desconocido"))
        elif ip.is_private and entry["provider"] is None:
            entry.update(provider=_("router o red local"))
        resolvers.append(entry)
    flags = [r["encrypted"] for r in resolvers]
    system = True if flags and all(f is True for f in flags) else (False if any(f is False for f in flags) else None)
    active = sorted(links)
    return {
        "ts": now(), "resolv_conf": [], "resolv_conf_target": None, "backend": "windows", "links": links,
        "global": {}, "resolv_mode": None, "active_links": active, "default_links": active, "split_dns": [],
        "dot": False, "all_servers": sorted({x for e in links.values() for x in e["servers"]}),
        "effective_source": _("Cliente DNS de Windows"), "effective_servers": effective,
        "encryption": {"resolvers": resolvers, "system_encrypted": system, "warp": None, "cloudflared": [],
                       "browsers": [], "upstream_route": None, "server_routes": {}},
        "encrypted": system,
    }


def dns_snapshot(egress_dev: str | None = None) -> dict:
    return build_dns(ps(DNS_SCRIPT), egress_dev)


# ── kill-switch (versión ligera: no se aplica, solo se informa) ─────────────

def killswitch_status(kinds: dict[str, str]) -> dict:
    unknown = {"state": "desconocido", "detail": _("en Windows no se verifica el kill-switch por rutas (versión ligera)"),
               "fallback": None}
    return {"active": False, "route_protection": {"ipv4": dict(unknown), "ipv6": dict(unknown)},
            "verified_ipv4": False, "verified_ipv6": False, "clients": [], "declared_by": [],
            "limitations": _("Versión ligera para Windows: el kill-switch de tu cliente VPN no se comprueba; "
                             "actívalo en el propio cliente.")}


# ── identidad ───────────────────────────────────────────────────────────────

# Zonas de Windows → IANA (CLDR windowsZones, territorio 001). Las más habituales.
WIN_TZ = {
    "Romance Standard Time": "Europe/Paris", "W. Europe Standard Time": "Europe/Berlin",
    "Central Europe Standard Time": "Europe/Budapest", "Central European Standard Time": "Europe/Warsaw",
    "GMT Standard Time": "Europe/London", "Greenwich Standard Time": "Atlantic/Reykjavik",
    "E. Europe Standard Time": "Europe/Chisinau", "FLE Standard Time": "Europe/Kiev",
    "GTB Standard Time": "Europe/Bucharest", "Russian Standard Time": "Europe/Moscow",
    "Turkey Standard Time": "Europe/Istanbul", "Israel Standard Time": "Asia/Jerusalem",
    "Egypt Standard Time": "Africa/Cairo", "South Africa Standard Time": "Africa/Johannesburg",
    "Morocco Standard Time": "Africa/Casablanca", "W. Central Africa Standard Time": "Africa/Lagos",
    "Arabian Standard Time": "Asia/Dubai", "Iran Standard Time": "Asia/Tehran", "India Standard Time": "Asia/Kolkata",
    "China Standard Time": "Asia/Shanghai", "Tokyo Standard Time": "Asia/Tokyo", "Korea Standard Time": "Asia/Seoul",
    "Singapore Standard Time": "Asia/Singapore", "SE Asia Standard Time": "Asia/Bangkok",
    "AUS Eastern Standard Time": "Australia/Sydney", "New Zealand Standard Time": "Pacific/Auckland",
    "Eastern Standard Time": "America/New_York", "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver", "Pacific Standard Time": "America/Los_Angeles",
    "Canada Central Standard Time": "America/Regina", "Atlantic Standard Time": "America/Halifax",
    "Central Standard Time (Mexico)": "America/Mexico_City", "SA Pacific Standard Time": "America/Bogota",
    "Argentina Standard Time": "America/Buenos_Aires", "E. South America Standard Time": "America/Sao_Paulo",
    "Pacific SA Standard Time": "America/Santiago", "Venezuela Standard Time": "America/Caracas",
    "SA Western Standard Time": "America/La_Paz", "UTC": "UTC", "Coordinated Universal Time": "UTC",
}


def identity() -> dict:
    data = ps("@{tz=(Get-TimeZone).Id; culture=(Get-Culture).Name} | ConvertTo-Json -Compress") or {}
    tz = data.get("tz")
    culture = (data.get("culture") or "").replace("-", "_")
    return {"hostname": socket.gethostname(), "timezone": os.environ.get("TZ") or WIN_TZ.get(tz, tz),
            "timezone_windows": tz, "lang": os.environ.get("LANG") or (f"{culture}.UTF-8" if culture else None)}


def is_admin() -> bool:
    if not WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (OSError, AttributeError):
        return False


# ── proxy del sistema (Opciones de Internet) ────────────────────────────────

def desktop_proxy() -> dict | None:
    if not WINDOWS:
        return None
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
    except OSError:
        return None

    def val(n):
        try:
            return winreg.QueryValueEx(k, n)[0]
        except OSError:
            return None
    from .discovery import redact_url
    if val("AutoConfigURL"):
        return {"mode": "auto", "pac": redact_url(str(val("AutoConfigURL")))}
    if val("ProxyEnable"):
        return {"mode": "manual", "http": str(val("ProxyServer") or "")}
    return {"mode": "none"}


# ── VPN y Tor instalados ────────────────────────────────────────────────────

VPN_PROCESSES = {
    "ProtonVPN": ("protonvpn", "protonvpnservice", "protonvpn.wireguardservice"),
    "Mullvad": ("mullvad-daemon", "mullvad vpn"), "NordVPN": ("nordvpn", "nordvpn-service"),
    "WireGuard": ("wireguard",), "OpenVPN": ("openvpn", "openvpn-gui", "openvpnserv"),
    "Cloudflare WARP": ("warp-svc", "cloudflare warp"), "ExpressVPN": ("expressvpn",),
    "Surfshark": ("surfshark",), "Windscribe": ("windscribe",),
}


def vpn_providers(names: set[str]) -> dict:
    low = {n.lower() for n in names}
    found = {}
    for prov, procs in VPN_PROCESSES.items():
        hit = [p for p in procs if p in low]
        if hit:
            found[prov] = {"binary": hit[0], "status": _("proceso en ejecución")}
    return found


def tor_browser_paths() -> list[str]:
    import glob
    pats = [os.path.join(os.environ.get(v, ""), *p) for v, p in (
        ("USERPROFILE", ("Desktop", "Tor Browser")), ("USERPROFILE", ("OneDrive", "Desktop", "Tor Browser")),
        ("LOCALAPPDATA", ("Tor Browser",)), ("ProgramFiles", ("Tor Browser",))) if os.environ.get(v)]
    return sorted({p for pat in pats for p in glob.glob(pat)})


def tor_geoip_files() -> list[str]:
    out = []
    for base in tor_browser_paths():
        for f in ("geoip", "geoip6"):
            p = os.path.join(base, "Browser", "TorBrowser", "Data", "Tor", f)
            if os.path.exists(p):
                out.append(p)
    return out


# ── descubrimiento (mismas claves que discovery.discover()) ────────────────

def discover() -> dict:
    import datetime as dt
    import importlib.util
    from . import discovery as d
    rows = tcp_rows()
    names = process_names()
    procs = [(str(pid), n.lower()) for pid, n in names.items()]
    loop_tcp = {p for a, p, _pid in listening(rows) if d.is_local(a)}
    probes = {p: d.probe_port(p) for p in sorted(loop_tcp & set(d.CANDIDATE_PROXY_PORTS))}
    net = network_snapshot()
    ifaces = [{k: i[k] for k in ("name", "kind", "up", "mac_origin")} for i in net["interfaces"]]
    listening_detail = [{"addr": a, "port": p, "owner": f"{names.get(pid, '?')} (pid {pid})"}
                        for a, p, pid in listening(rows) if p in probes or not d.is_local(a)]
    dsnap = dns_snapshot((net["egress"].get("ipv4") or {}).get("dev"))
    tor = d.detect_tor(loop_tcp, probes, procs)
    tor["browser"] = tor_browser_paths()
    tor["installed"] = tor["installed"] or bool(tor["browser"])
    six = {"global_ifaces": sorted({i["name"] for i in net["interfaces"] for a in i["addrs"]
                                     if a["family"] == "ipv6" and a["class"] == "pública"}), "ula_ifaces": []}
    env = {
        "generated": dt.datetime.now().astimezone().isoformat(timespec="seconds"),
        "system": {"os": "Windows", "distro": platform.platform(), "distro_id": "windows", "kernel": platform.version(),
                   "arch": platform.machine(), "wsl": False, "virtualization": None, "container": None},
        "listening": listening_detail,
        "binaries": {cat: {n: p for n in ns if (p := which(n))} for cat, ns in d.BINARIES.items()},
        "processes": sorted({n for _pid, n in procs if n in d.INTERESTING_PROCESSES}),
        "services": None,
        "interfaces": ifaces,
        "routes": {k: [r["dev"] for r in v] for k, v in net["routes"].items()},
        "egress": {fam: (net["egress"].get(fam) or {}).get("dev") for fam in ("ipv4", "ipv6")},
        "ipv6": {"disabled": False, **six},
        "tor": tor,
        "vpn": {"providers": vpn_providers({n for _pid, n in procs}), "networkmanager": None,
                "wireguard": {"configs": [], "readable": False}, "openvpn_configs": []},
        "proxy": {"local": [{"port": p, "kind": k} for p, k in probes.items()], "ssh_tunnels": [], "proxychains": None,
                  "env": {k: d.redact_url(v) for k in ("http_proxy", "https_proxy", "all_proxy",
                                                       "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") if (v := os.environ.get(k))},
                  "desktop": desktop_proxy()},
        "dns": {"resolv_conf": [], "resolv_conf_target": None, "resolved": None, "local_listener": False,
                "local_resolvers": []},
        "mac_policy": {},
        "identity": identity(),
        "privileges": {"root": is_admin(), "groups": [], "escalation": []},
        "geoip": {"mmdb": [], "tor_geoip": tor_geoip_files()},
        "python": {"version": sys.version.split()[0],
                   "modules": {m: importlib.util.find_spec(m) is not None for m in d.PY_MODULES}},
        "display": True,
    }
    env["killswitch"] = killswitch_status({i["name"]: i["kind"] for i in ifaces})
    env["dns_effective"] = {"source": dsnap["effective_source"], "servers": dsnap["effective_servers"],
                            "encrypted": dsnap["encrypted"], "encryption": dsnap["encryption"]}
    return env


# ── inventario de redes (página «Redes») ────────────────────────────────────

INV_SCRIPT = r"""
$st = Get-NetAdapterStatistics -ErrorAction SilentlyContinue | Select-Object Name,ReceivedBytes,SentBytes
$nb = Get-NetNeighbor -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Reachable','Stale','Delay','Probe','Permanent' -and $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' -and $_.LinkLayerAddress -ne 'FF-FF-FF-FF-FF-FF' } | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,@{n='State';e={[string]$_.State}}
$wl = (netsh wlan show interfaces) -join "`n"
@{stats=@($st); neighbors=@($nb); wlan=$wl} | ConvertTo-Json -Depth 4 -Compress
"""


def parse_wlan(text: str) -> dict[str, dict]:
    """`netsh wlan show interfaces` → {interfaz: {ssid, signal, security}} (claves en inglés o español)."""
    out, cur = {}, None
    for line in (text or "").splitlines():
        k, sep, v = line.partition(":")
        if not sep:
            continue
        k, v = k.strip().lower(), v.strip()
        if k in ("name", "nombre"):
            cur = out.setdefault(v, {})
        elif cur is not None and k == "ssid":
            cur["ssid"] = v
        elif cur is not None and k in ("signal", "señal"):
            cur["signal"] = int(v.rstrip("%")) if v.rstrip("%").isdigit() else None
        elif cur is not None and k in ("authentication", "autenticación"):
            cur["security"] = v
    return {n: w for n, w in out.items() if w.get("ssid")}


def build_inventory(net: dict, dns: dict | None, data: dict | None) -> dict:
    from . import networks as nmod
    from .util import fingerprint
    data = data or {}
    stats = {s.get("Name"): {"rx_bytes": s.get("ReceivedBytes"), "tx_bytes": s.get("SentBytes")}
             for s in _list(data.get("stats"))}
    neigh: dict[str, list[dict]] = {}
    for n in _list(data.get("neighbors")):
        mac = str(n.get("LinkLayerAddress") or "").replace("-", ":").lower()
        neigh.setdefault(n.get("InterfaceAlias"), []).append({"ip": n.get("IPAddress"), "mac": mac,
                                                              "state": n.get("State"), "vendor": nmod.vendor(mac),
                                                              "router": False})
    wlan = parse_wlan(data.get("wlan") or "")
    gws = {}
    for fam in ("ipv4_default", "ipv6_default"):
        for r in net["routes"][fam]:
            if r.get("gateway") and r.get("dev") and r["gateway"] not in ("0.0.0.0", "::"):
                gws.setdefault(r["dev"], r["gateway"])
    links = (dns or {}).get("links") or {}
    out = []
    for i in net["interfaces"]:
        name = i["name"]
        cat = nmod.category(name, i["kind"])
        subnets = [str(ipaddress.ip_interface(f"{a['addr']}/{a['prefix']}").network)
                   for a in i["addrs"] if a["family"] == "ipv4" and a.get("prefix") is not None]
        gw = gws.get(name)
        for n in neigh.get(name, []):
            n["router"] = n["ip"] == gw
        gw_mac = next((n["mac"] for n in neigh.get(name, []) if n["ip"] == gw), None) if gw else None
        w = wlan.get(name)
        ident = fingerprint({"gw_mac": gw_mac, "ssid": (w or {}).get("ssid"), "subnet": subnets[:1]}) \
            if cat in ("lan", "wifi") and gw_mac else None
        out.append({"name": name, "kind": i["kind"], "category": cat, "up": i["up"], "mac_origin": i["mac_origin"],
                    "addrs": i["addrs"], "subnets": subnets, "gateway": gw, "gateway_mac": gw_mac,
                    "gateway_vendor": nmod.vendor(gw_mac), "network_id": ident, "connection": None, "wifi": w,
                    "dns": (links.get(name) or {}).get("servers") or [],
                    "stats": stats.get(name) or {"rx_bytes": None, "tx_bytes": None},
                    "neighbors": neigh.get(name, [])})
    return {"ts": now(), "interfaces": out, "saved": [], "docker": None, "libvirt": None}


def inventory(net: dict, dns: dict | None = None) -> dict:
    return build_inventory(net, dns, ps(INV_SCRIPT))
