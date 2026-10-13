"""Datos sintéticos compartidos por las pruebas (no tocan el sistema real)."""

import copy

from opsectools import config


def cfg(**over):
    base = config.deep_merge(config.DEFAULTS, {"storage": {"mode": "memory"}})
    return config.deep_merge(base, over)


def iface(name, kind, up=True, mac="aleatoria", addrs=()):
    return {"name": name, "kind": kind, "up": up, "mac_origin": mac,
            "addrs": [{"family": "ipv6" if ":" in a else "ipv4", "addr": a, "prefix": 24, "class": cls}
                      for a, cls in addrs]}


def net(tunnel=False, v6_dev=None, v6_public=False):
    ifs = [iface("lo", "loopback", mac="permanente"),
           iface("eth0", "ethernet", addrs=[("192.168.1.10", "privada")] + ([("2001:db8::1", "pública")] if v6_public else []))]
    if tunnel:
        ifs.append(iface("wg0", "wireguard", addrs=[("10.66.0.2", "privada")]))
    e4 = {"dev": "wg0" if tunnel else "eth0", "src": "10.66.0.2" if tunnel else "192.168.1.10",
          "gateway": None if tunnel else "192.168.1.1", "table": None}
    e6 = {"dev": v6_dev, "src": None, "gateway": "fe80::1", "table": None} if v6_dev else None
    kind = {"wg0": "wireguard", "eth0": "ethernet"}
    return {"ts": 0, "interfaces": ifs, "routes": {"ipv4_default": [{"dev": "eth0", "gateway": "192.168.1.1", "metric": 100, "table": "main"}],
                                                    "ipv6_default": []},
            "policy_rules": [], "egress": {"ipv4": e4, "ipv6": e6},
            "egress_kind": {"ipv4": kind[e4["dev"]], "ipv6": kind.get(v6_dev)},
            "local_ip": e4["src"], "gateway": "192.168.1.1", "tunnels": ["wg0"] if tunnel else [],
            "via_tunnel": {"ipv4": tunnel, "ipv6": (v6_dev == "wg0") if v6_dev else None},
            "ipv6_internet": v6_public}


def dns(default_links=("eth0",), servers=("192.168.1.1",), dot=False, tunnel_servers=(), encrypted=None,
        resolvers=(), server_routes=None, upstream_route=None, effective_source="systemd-resolved"):
    links = {"eth0": {"servers": list(servers), "current": None, "domains": [], "default_route": "eth0" in default_links,
                      "dot": dot, "dnssec": "no", "server_classes": ["lan"]}}
    if tunnel_servers:
        links["wg0"] = {"servers": list(tunnel_servers), "current": None, "domains": ["~."], "default_route": "wg0" in default_links,
                        "dot": dot, "dnssec": "no", "server_classes": ["pública"]}
    return {"ts": 0, "resolv_conf": ["127.0.0.53"], "resolv_conf_target": "/run/systemd/resolve/stub-resolv.conf",
            "backend": "systemd-resolved", "links": links, "global": {},
            "active_links": sorted(links), "default_links": list(default_links), "split_dns": [], "dot": dot,
            "all_servers": sorted(set(servers) | set(tunnel_servers)),
            "effective_source": effective_source, "effective_servers": sorted(set(servers) | set(tunnel_servers)),
            "encrypted": encrypted,
            "encryption": {"resolvers": list(resolvers), "server_routes": server_routes or {},
                           "upstream_route": upstream_route, "browsers": []}}


ENV = {
    "system": {"distro": "Test", "kernel": "1", "arch": "x86_64", "wsl": False, "virtualization": None, "container": None},
    "listening": [{"addr": "0.0.0.0", "port": 8080, "owner": "python (pid 1)"}, {"addr": "127.0.0.1", "port": 9050, "owner": None}],
    "binaries": {"tor": {"tor": "/usr/sbin/tor"}, "vpn": {"wg": "/usr/bin/wg", "nmcli": "/usr/bin/nmcli"}, "proxy": {},
                 "dns": {"resolvectl": "/usr/bin/resolvectl"}, "firewall": {"nft": "/usr/sbin/nft"}, "identity": {"ip": "/usr/sbin/ip"}},
    "processes": ["tor"], "services": [],
    "interfaces": [{"name": "eth0", "kind": "ethernet", "up": True, "mac_origin": "permanente"},
                   {"name": "wg0", "kind": "wireguard", "up": True, "mac_origin": "?"}],
    "routes": {"ipv4_default": ["eth0"], "ipv6_default": []}, "egress": {"ipv4": "wg0", "ipv6": "eth0"},
    "ipv6": {"disabled": False, "global_ifaces": ["eth0"], "ula_ifaces": []},
    "tor": {"installed": True, "running": True, "control": [{"target": "127.0.0.1:9051", "auth": ["SAFECOOKIE", "COOKIE"],
                                                              "version": "0.4.9", "cookie_file": "/x", "cookie_readable": False}],
            "socks": [9050], "torrc": {"HashedControlPassword": False}, "browser": [], "transports": []},
    "vpn": {"providers": {}, "networkmanager": [{"name": "se1", "type": "wireguard", "device": "wg0", "active": True},
                                                {"name": "nl1", "type": "wireguard", "device": None, "active": False}],
            "wireguard": {"configs": [], "readable": True}, "openvpn_configs": []},
    "proxy": {"local": [{"port": 8080, "kind": "http"}, {"port": 9050, "kind": "tor-socks"}], "ssh_tunnels": [],
              "proxychains": None, "env": {}, "desktop": None},
    "dns": {"resolv_conf": ["127.0.0.53"], "resolv_conf_target": "x", "local_listener": True, "local_resolvers": [],
            "resolved": {"links": {"eth0": ["192.168.1.1"], "wg0": ["10.64.0.1"]}, "dot": False, "dnssec": False}},
    "mac_policy": {}, "identity": {"hostname": "h", "timezone": "Europe/Madrid", "lang": "es_ES.UTF-8"},
    "privileges": {"root": False, "groups": [], "escalation": ["sudo"]},
    "geoip": {"mmdb": [], "tor_geoip": ["/usr/share/tor/geoip"]},
    "python": {"version": "3.14", "modules": {m: False for m in ("stem", "textual", "typer", "httpx", "socksio", "dns",
                                                                 "fastapi", "uvicorn", "geoip2", "sqlcipher3")}},
    "display": False,
}


def env(**over):
    e = copy.deepcopy(ENV)
    e.update(over)
    return e
