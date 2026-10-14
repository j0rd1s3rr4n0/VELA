"""Observación de la red local: interfaces, direcciones, rutas, policy routing y eventos netlink.

Solo lectura. `ip route get` pregunta al kernel por qué interfaz saldría un paquete sin
enviarlo, y respeta las reglas de policy routing (wg-quick, Mullvad, Tailscale…).
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time

from . import discovery
from .util import WINDOWS, now, run_json

CGNAT = ipaddress.ip_network("100.64.0.0/10")
PROBE_V4 = "1.1.1.1"
PROBE_V6 = "2606:4700:4700::1111"


def classify_ip(addr: str) -> str:
    ip = ipaddress.ip_address(addr.split("%")[0])
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.version == 4 and ip in CGNAT:
        return "cgnat"
    if ip.version == 6 and ip in ipaddress.ip_network("fc00::/7"):
        return "ula"
    if ip.is_private:
        return "privada"
    if ip.is_global:
        return "pública"
    return "reservada"


def _route_get(target: str, family: str) -> dict | None:
    data = run_json(["ip", "-j", family, "route", "get", target])
    if not data:
        return None
    r = data[0]
    return {"dev": r.get("dev"), "src": r.get("prefsrc"), "gateway": r.get("gateway"), "table": r.get("table")}


def snapshot() -> dict:
    """Foto completa del estado de red local."""
    if WINDOWS:                       # rama windows-lite: mismos datos desde las API de Windows
        from . import winsys
        return winsys.network_snapshot()
    ifaces = {i["name"]: {**i, "addrs": []} for i in discovery.detect_interfaces()}
    for entry in run_json(["ip", "-j", "addr", "show"]) or []:
        name = entry.get("ifname")
        if name not in ifaces:
            continue
        ifaces[name]["operstate"] = entry.get("operstate")
        ifaces[name]["mtu"] = entry.get("mtu")
        for a in entry.get("addr_info", []):
            local = a.get("local")
            if not local:
                continue
            ifaces[name]["addrs"].append({
                "family": "ipv6" if ":" in local else "ipv4", "addr": local,
                "prefix": a.get("prefixlen"), "class": classify_ip(local),
            })

    routes = {"ipv4_default": [], "ipv6_default": []}
    for fam, key in (("-4", "ipv4_default"), ("-6", "ipv6_default")):
        for r in run_json(["ip", "-j", fam, "route", "show", "table", "all"]) or []:
            if r.get("dst") == "default" and r.get("type", "unicast") == "unicast":
                routes[key].append({"dev": r.get("dev"), "gateway": r.get("gateway"),
                                    "metric": r.get("metric", 0), "table": r.get("table", "main")})
    rules = [r for r in (run_json(["ip", "-j", "rule"]) or [])
             if r.get("table") not in ("local", "main", "default") or r.get("fwmark")]

    egress = {"ipv4": _route_get(PROBE_V4, "-4"), "ipv6": _route_get(PROBE_V6, "-6")}
    kind = lambda dev: ifaces.get(dev, {}).get("kind")  # noqa: E731
    tunnels = [n for n, i in ifaces.items() if i["kind"] in discovery.VPN_KINDS and i["up"]]
    e4 = egress["ipv4"] or {}
    e6 = egress["ipv6"] or {}
    return {
        "ts": now(),
        "interfaces": list(ifaces.values()),
        "routes": routes,
        "policy_rules": rules,
        "egress": egress,
        "egress_kind": {"ipv4": kind(e4.get("dev")), "ipv6": kind(e6.get("dev"))},
        "local_ip": e4.get("src"),
        "gateway": e4.get("gateway"),
        "tunnels": tunnels,
        "via_tunnel": {"ipv4": kind(e4.get("dev")) in discovery.VPN_KINDS if e4 else None,
                       "ipv6": kind(e6.get("dev")) in discovery.VPN_KINDS if e6 else None},
        "ipv6_internet": bool(e6) and any(a["class"] == "pública" for a in ifaces.get(e6.get("dev"), {}).get("addrs", [])),
    }


def physical_iface(snap: dict) -> str | None:
    """Interfaz física con ruta por defecto (camino hacia el router)."""
    phys = {i["name"] for i in snap["interfaces"] if i["kind"] in discovery.PHYSICAL_KINDS}
    for r in sorted(snap["routes"]["ipv4_default"], key=lambda r: r["metric"]):
        if r["dev"] in phys:
            return r["dev"]
    up = [i["name"] for i in snap["interfaces"] if i["kind"] in discovery.PHYSICAL_KINDS and i["up"]]
    return up[0] if up else None


def diff(old: dict | None, new: dict) -> list[dict]:
    """Cambios relevantes entre dos fotos, como eventos."""
    if old is None:
        return []
    events = []

    def ev(kind, sev, **data):
        events.append({"kind": kind, "severity": sev, **data})

    o_if = {i["name"]: i for i in old["interfaces"]}
    n_if = {i["name"]: i for i in new["interfaces"]}
    for name in n_if.keys() - o_if.keys():
        ev("interface_added", "info", iface=name, iface_kind=n_if[name]["kind"])
    for name in o_if.keys() - n_if.keys():
        sev = "high" if o_if[name]["kind"] in discovery.VPN_KINDS else "info"
        ev("interface_removed", sev, iface=name, iface_kind=o_if[name]["kind"])
    for name in n_if.keys() & o_if.keys():
        if o_if[name]["up"] != n_if[name]["up"]:
            tunnel_down = n_if[name]["kind"] in discovery.VPN_KINDS and not n_if[name]["up"]
            ev("interface_state", "high" if tunnel_down else "info", iface=name, up=n_if[name]["up"])
        o_a = {a["addr"] for a in o_if[name]["addrs"]}
        n_a = {a["addr"] for a in n_if[name]["addrs"]}
        if o_a != n_a:
            ev("address_change", "info", iface=name, added=sorted(n_a - o_a), removed=sorted(o_a - n_a))
    for fam in ("ipv4", "ipv6"):
        o, n = old["egress"].get(fam) or {}, new["egress"].get(fam) or {}
        if o.get("dev") != n.get("dev") or o.get("gateway") != n.get("gateway"):
            left_tunnel = old["via_tunnel"].get(fam) and not new["via_tunnel"].get(fam)
            ev("route_change", "critical" if left_tunnel else "warning", family=fam,
               before=o or None, after=n or None, left_tunnel=bool(left_tunnel))
        if bool(o) != bool(n):
            ev("connectivity_change", "warning", family=fam, available=bool(n))
    if old["tunnels"] != new["tunnels"]:
        ev("tunnels_change", "warning", before=old["tunnels"], after=new["tunnels"])
    return events


# ── eventos netlink ─────────────────────────────────────────────────────────

RTMGRP_LINK = 0x1
RTMGRP_IPV4_IFADDR = 0x10
RTMGRP_IPV4_ROUTE = 0x40
RTMGRP_IPV6_IFADDR = 0x100
RTMGRP_IPV6_ROUTE = 0x400
RTMGRP_IPV4_RULE = 0x80


class NetlinkWatcher(threading.Thread):
    """Escucha rtnetlink y llama a `callback()` (con antirrebote) cuando cambia la red.
    Si netlink no está disponible, `available` queda en False y el daemon sondea."""

    def __init__(self, callback, debounce: float = 1.0):
        super().__init__(daemon=True, name="netlink")
        self.callback = callback
        self.debounce = debounce
        self.available = False
        self._stop = threading.Event()
        try:
            self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)  # NETLINK_ROUTE
            self.sock.bind((0, RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE |
                               RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_RULE))
            self.sock.settimeout(1.0)
            self.available = True
        except (OSError, AttributeError):
            self.sock = None

    def run(self):
        if not self.sock:
            return
        pending_since = None
        while not self._stop.is_set():
            try:
                data = self.sock.recv(65536)
                if len(data) >= 16:
                    _length, msg_type = struct.unpack("=IH", data[:6])
                    if msg_type >= 16:  # RTM_* (los < 16 son de control)
                        pending_since = pending_since or time.monotonic()
            except TimeoutError:
                pass
            except OSError:
                if self._stop.is_set():
                    break
                time.sleep(1)
            if pending_since and time.monotonic() - pending_since >= self.debounce:
                pending_since = None
                try:
                    self.callback()
                except Exception:  # el watcher no debe morir por un fallo del callback
                    pass

    def stop(self):
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    import json
    print(json.dumps(snapshot(), indent=2, default=str))
