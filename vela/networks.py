"""Inventario y monitorización de TODAS las redes del equipo (solo observación pasiva).

* Interfaces y su categoría: LAN física, WiFi, VPN, contenedores (Docker), máquinas virtuales
  (libvirt), bloqueo (kill-switch), loopback.
* Por red: direcciones, subred, gateway y su MAC, SSID/BSSID/señal, DNS, contadores de tráfico.
* Vecinos de la tabla ARP/NDP del kernel (`ip neigh`) con fabricante por OUI. NO se escanea la red:
  solo se ve a quien tu equipo ya ha hablado.
* Redes guardadas de NetworkManager, redes Docker y libvirt (con su modo de forwarding).

Alertas que genera el motor a partir de aquí:
  - cambio de la MAC del gateway en la misma red  → posible ARP spoofing / MITM (alta);
  - dispositivo nuevo en una red conocida (info);
  - red libvirt "aislada" que tiene salida (NAT/route) → aislamiento roto (alta);
  - conexión a una red nunca vista (info).
"""

from __future__ import annotations

from .i18n import _

import ipaddress
import json
import re
from pathlib import Path

from .util import fingerprint, now, run, run_json, which

OUI_FILES = ["/usr/share/ieee-data/oui.txt", "/var/lib/ieee-data/oui.txt", "/usr/share/hwdata/oui.txt",
             "/usr/share/misc/oui.txt"]
_OUI: dict[str, str] | None = None
ISOLATION_HINTS = ("isolat", "aislad", "malware", "sandbox", "quarantine", "cuarentena", "lab")


def vendor(mac: str | None) -> str | None:
    global _OUI
    if not mac:
        return None
    first = int(mac.split(":")[0], 16)
    if first & 0x02:
        return _("MAC aleatoria/local")
    if _OUI is None:
        _OUI = {}
        for f in OUI_FILES:
            try:
                for line in open(f, errors="replace"):
                    m = re.match(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", line.strip())
                    if m:
                        _OUI[m.group(1).replace("-", ":").lower()] = m.group(2).strip()
                break
            except OSError:
                continue
    return _OUI.get(mac.lower()[:8])


def category(name: str, kind: str) -> str:
    if kind == "loopback":
        return "loopback"
    if kind in ("wireguard", "tun", "ppp"):
        return "vpn"
    if kind == "dummy":
        return "bloqueo"
    if kind == "wifi":
        return "wifi"
    if kind == "ethernet":
        return "lan"
    if name.startswith(("docker", "br-", "veth")):
        return "contenedores"
    if name.startswith(("virbr", "vnet", "macvtap")):
        return "máquinas virtuales"
    return "virtual"


def _stats(name: str) -> dict:
    base = Path("/sys/class/net", name, "statistics")
    out = {}
    for k in ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"):
        try:
            out[k] = int((base / k).read_text())
        except (OSError, ValueError):
            out[k] = None
    return out


def _nm_active() -> dict[str, dict]:
    code, out, _ign = run(["nmcli", "-t", "-f", "NAME,TYPE,DEVICE,UUID", "connection", "show", "--active"])
    res = {}
    for line in out.splitlines() if code == 0 else []:
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) >= 4 and f[2]:
            res[f[2]] = {"connection": f[0], "type": f[1], "uuid": f[3]}
    return res


def _wifi_current() -> dict[str, dict]:
    """Red WiFi conectada por interfaz, desde la caché de NM (--rescan no: no provoca un escaneo)."""
    code, out, _ign = run(["nmcli", "-t", "-f", "IN-USE,DEVICE,SSID,BSSID,CHAN,SIGNAL,SECURITY", "device", "wifi",
                        "list", "--rescan", "no"])
    res = {}
    for line in out.splitlines() if code == 0 else []:
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) >= 7 and f[0] == "*":
            res[f[1]] = {"ssid": f[2], "bssid": f[3], "channel": f[4], "signal": int(f[5]) if f[5].isdigit() else None,
                         "security": f[6] or "abierta"}
    return res


def saved_networks() -> list[dict]:
    code, out, _ign = run(["nmcli", "-t", "-f", "NAME,TYPE,TIMESTAMP,AUTOCONNECT", "connection", "show"])
    res = []
    for line in out.splitlines() if code == 0 else []:
        f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
        if len(f) >= 4 and f[1] in ("802-11-wireless", "802-3-ethernet", "vpn", "wireguard", "gsm", "bluetooth"):
            ts = int(f[2]) if f[2].isdigit() and f[2] != "0" else None
            res.append({"name": f[0], "type": f[1], "last_used": ts, "autoconnect": f[3] == "yes"})
    return res


def docker_networks() -> list[dict] | None:
    if not which("docker"):
        return None
    code, out, _ign = run(["docker", "network", "ls", "--format", "{{json .}}"], timeout=6)
    if code != 0:
        return None
    nets = []
    for line in out.splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        nets.append({"name": d.get("Name"), "id": d.get("ID"), "driver": d.get("Driver"),
                     "internal": d.get("Internal") == "true",
                     "bridge": f"br-{d.get('ID')}" if d.get("Driver") == "bridge" and d.get("Name") != "bridge" else
                     ("docker0" if d.get("Name") == "bridge" else None)})
    return nets


def libvirt_networks() -> list[dict] | None:
    if not which("virsh"):
        return None
    code, out, _ign = run(["virsh", "-c", "qemu:///system", "net-list", "--all", "--name"], timeout=6)
    if code != 0:
        return None
    nets = []
    for name in [l.strip() for l in out.splitlines() if l.strip()]:
        c2, xml, _ign = run(["virsh", "-c", "qemu:///system", "net-dumpxml", name], timeout=6)
        fwd = re.search(r"<forward(?:\s+mode=['\"](\w+)['\"])?", xml or "")
        mode = (fwd.group(1) or "nat") if fwd else "isolated"
        bridge = re.search(r"<bridge name=['\"]([^'\"]+)", xml or "")
        ip = re.search(r"<ip address=['\"]([^'\"]+)['\"](?:\s+netmask=['\"]([^'\"]+))?", xml or "")
        c3, info, _ign = run(["virsh", "-c", "qemu:///system", "net-info", name], timeout=6)
        active = bool(re.search(r"(?im)^(Active|Activo):\s*(yes|s[ií])", info or ""))
        looks_isolated = any(h in name.lower() for h in ISOLATION_HINTS)
        nets.append({"name": name, "forward": mode, "bridge": bridge.group(1) if bridge else None,
                     "ip": ip.group(1) if ip else None, "netmask": ip.group(2) if ip else None, "active": active,
                     "named_isolated": looks_isolated,
                     "isolation_broken": looks_isolated and mode not in ("isolated", None)})
    return nets


def neighbors() -> dict[str, list[dict]]:
    res: dict[str, list[dict]] = {}
    for n in run_json(["ip", "-j", "neigh", "show"]) or []:
        state = n.get("state") or []
        if not n.get("lladdr") or "FAILED" in state or "INCOMPLETE" in state:
            continue
        res.setdefault(n.get("dev"), []).append({"ip": n.get("dst"), "mac": n.get("lladdr").lower(),
                                                 "state": state[0] if state else None, "vendor": vendor(n.get("lladdr")),
                                                 "router": "router" in (n.get("flags") or [])})
    return res


def inventory(net: dict | None = None, dns: dict | None = None) -> dict:
    from . import network as network_mod
    net = net or network_mod.snapshot()
    nm = _nm_active() if which("nmcli") else {}
    wifi = _wifi_current() if which("nmcli") else {}
    neigh = neighbors()
    gws: dict[str, str] = {}
    for fam in ("ipv4_default", "ipv6_default"):
        for r in net["routes"][fam]:
            if r.get("gateway") and r.get("dev"):
                gws.setdefault(r["dev"], r["gateway"])
    links = (dns or {}).get("links") or {}
    out = []
    for i in net["interfaces"]:
        name = i["name"]
        cat = category(name, i["kind"])
        subnets = []
        for a in i["addrs"]:
            if a["family"] == "ipv4" and a.get("prefix") is not None:
                subnets.append(str(ipaddress.ip_interface(f"{a['addr']}/{a['prefix']}").network))
        gw = gws.get(name)
        gw_mac = next((n["mac"] for n in neigh.get(name, []) if n["ip"] == gw), None) if gw else None
        w = wifi.get(name)
        ident = None
        if cat in ("lan", "wifi") and gw_mac:
            # Huella de la red: misma red física = mismo gateway (MAC) y mismo SSID
            ident = fingerprint({"gw_mac": gw_mac, "ssid": (w or {}).get("ssid"), "subnet": subnets[:1]})
        out.append({
            "name": name, "kind": i["kind"], "category": cat, "up": i["up"], "mac_origin": i["mac_origin"],
            "addrs": i["addrs"], "subnets": subnets, "gateway": gw, "gateway_mac": gw_mac,
            "gateway_vendor": vendor(gw_mac), "network_id": ident,
            "connection": (nm.get(name) or {}).get("connection"), "wifi": w,
            "dns": (links.get(name) or {}).get("servers") or [],
            "stats": _stats(name), "neighbors": neigh.get(name, []),
        })
    return {"ts": now(), "interfaces": out, "saved": saved_networks() if which("nmcli") else [],
            "docker": docker_networks(), "libvirt": libvirt_networks()}


def rates(prev: dict | None, cur: dict) -> dict[str, dict]:
    """bytes/s por interfaz entre dos inventarios."""
    if not prev:
        return {}
    dt = max(1e-6, cur["ts"] - prev["ts"])
    p = {i["name"]: i["stats"] for i in prev["interfaces"]}
    out = {}
    for i in cur["interfaces"]:
        a, b = p.get(i["name"]), i["stats"]
        if not a or a.get("rx_bytes") is None or b.get("rx_bytes") is None:
            continue
        out[i["name"]] = {"rx_bps": max(0, (b["rx_bytes"] - a["rx_bytes"]) / dt),
                          "tx_bps": max(0, (b["tx_bytes"] - a["tx_bytes"]) / dt)}
    return out


def diff(prev: dict | None, cur: dict, known: dict) -> list[dict]:
    """Eventos de red. `known`: {network_id: {"gw_mac", "label", "devices": {mac: {...}}}} persistido."""
    events = []
    for i in cur["interfaces"]:
        nid = i.get("network_id")
        if not nid:
            continue
        label = (i.get("wifi") or {}).get("ssid") or i.get("connection") or i["name"]
        entry = known.get(nid)
        if entry is None:
            # misma red (SSID/subred) con otra MAC de gateway → posible suplantación
            same = [k for k, v in known.items() if v.get("label") == label and v.get("subnet") == (i["subnets"][:1] or [None])[0]
                    and v.get("gw_ip") == i["gateway"] and v.get("gw_mac") and v["gw_mac"] != i["gateway_mac"]]
            if same:
                events.append({"kind": "gateway_mac_change", "severity": "high", "data": {
                    "network": label, "gateway": i["gateway"], "before": known[same[0]]["gw_mac"],
                    "after": i["gateway_mac"], "vendor_before": vendor(known[same[0]]["gw_mac"]),
                    "vendor_after": i["gateway_vendor"],
                    "note": _("El gateway de una red conocida responde con otra MAC: posible ARP spoofing/MITM "
                            "(o cambio legítimo de router)")}})
            else:
                events.append({"kind": "network_new", "severity": "info", "data": {
                    "network": label, "iface": i["name"], "gateway": i["gateway"], "gateway_vendor": i["gateway_vendor"],
                    "security": (i.get("wifi") or {}).get("security")}})
            entry = known[nid] = {"label": label, "gw_ip": i["gateway"], "gw_mac": i["gateway_mac"],
                                  "subnet": (i["subnets"][:1] or [None])[0], "first": now(), "devices": {}}
        entry["last"] = now()
        for n in i["neighbors"]:
            dev = entry["devices"].get(n["mac"])
            if dev is None:
                if entry["devices"] or prev is not None:     # no avisar del inventario inicial
                    events.append({"kind": "lan_new_device", "severity": "info", "data": {
                        "network": label, "ip": n["ip"], "mac": n["mac"], "vendor": n["vendor"]}})
                entry["devices"][n["mac"]] = {"ip": n["ip"], "vendor": n["vendor"], "first": now(), "last": now()}
            else:
                dev["last"] = now()
                dev["ip"] = n["ip"]
    for v in cur.get("libvirt") or []:
        if v["isolation_broken"] and v["active"]:
            events.append({"kind": "vm_isolation_broken", "severity": "high", "data": {
                "network": v["name"], "forward": v["forward"],
                "note": _("Red con nombre de aislamiento pero con salida al exterior")}})
    return events
