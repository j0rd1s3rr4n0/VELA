"""IP pública de salida e IP WAN del router.

Tres conceptos distintos que no deben confundirse:
  * IP local        – la de tu interfaz (p. ej. 192.168.0.33).
  * IP WAN router   – la que el ISP asigna al router (UPnP-IGD, tráfico SOLO dentro de la LAN).
                      Si es privada o 100.64.0.0/10 → CGNAT / doble NAT.
  * IP pública      – la que ve Internet por cada vía de salida (directa, VPN, proxy, Tor).

Las consultas externas se identifican (endpoint y vía), están limitadas en frecuencia y solo se
hacen con el consentimiento correspondiente en `[consent]`. La vía Tor no expone tu IP de origen;
la directa sí, por eso está desactivada por defecto.
"""

from __future__ import annotations

from .i18n import _

import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .util import now, parse_duration

IP_RE = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7})(?![\w.:])")


class ConsentRequired(Exception):
    pass


def extract_ip(text: str) -> str | None:
    try:
        data = json.loads(text)
        for key in ("IP", "ip", "origin", "address"):
            if isinstance(data, dict) and key in data:
                return str(ipaddress.ip_address(str(data[key]).strip()))
    except (ValueError, TypeError):
        pass
    for m in IP_RE.finditer(text):
        try:
            return str(ipaddress.ip_address(m.group(1)))
        except ValueError:
            continue
    return None


# ── transporte ──────────────────────────────────────────────────────────────

def open_direct(host: str, port: int, timeout: float, iface: str | None = None) -> socket.socket:
    last = None
    for fam, stype, proto, _ign, addr in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        s = socket.socket(fam, stype, proto)
        s.settimeout(timeout)
        try:
            if iface:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())
            s.connect(addr)
            return s
        except OSError as e:
            last = e
            s.close()
    raise last or OSError(_("sin direcciones"))


def open_socks5(proxy: tuple[str, int], host: str, port: int, timeout: float,
                username: str | None = None, password: str | None = None) -> socket.socket:
    """SOCKS5 con resolución remota (ATYP=dominio): el DNS lo resuelve el proxy/Tor, sin fuga local."""
    s = socket.create_connection(proxy, timeout=timeout)
    try:
        if username is not None:
            s.sendall(b"\x05\x01\x02")
        else:
            s.sendall(b"\x05\x01\x00")
        ver, method = s.recv(2)
        if ver != 5 or method == 0xFF:
            raise OSError(_("SOCKS5: método de autenticación rechazado"))
        if method == 2:
            u, p = (username or "").encode(), (password or "").encode()
            s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if s.recv(2)[1:2] != b"\x00":
                raise OSError(_("SOCKS5: autenticación fallida"))
        h = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + struct.pack(">H", port))
        head = s.recv(4)
        if len(head) < 4 or head[1] != 0:
            raise OSError(_("SOCKS5: conexión rechazada (código {v1})", v1=head[1] if len(head) > 1 else '?'))
        atyp = head[3]
        n = {1: 4, 4: 16}.get(atyp)
        if n is None:
            n = s.recv(1)[0]
        s.recv(n + 2)
        return s
    except Exception:
        s.close()
        raise


def open_http_connect(proxy: tuple[str, int], host: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection(proxy, timeout=timeout)
    try:
        s.sendall(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode())
        resp = b""
        while b"\r\n\r\n" not in resp and len(resp) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
        if " 200" not in status:
            raise OSError(_("proxy HTTP: {v1}", v1=status or 'sin respuesta'))
        return s
    except Exception:
        s.close()
        raise


def https_request(sock: socket.socket, host: str, path: str, timeout: float, headers: dict | None = None,
                  method: str = "GET") -> tuple[int, str]:
    """Petición HTTPS mínima sobre un socket ya conectado (directo, SOCKS5 o CONNECT). Devuelve (estado, cuerpo)."""
    ctx = ssl.create_default_context()
    hdrs = {"Host": host, "User-Agent": "curl/8.5.0", "Accept": "*/*", "Connection": "close", **(headers or {})}
    with ctx.wrap_socket(sock, server_hostname=host) as tls:
        tls.settimeout(timeout)
        tls.sendall((f"{method} {path or '/'} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
                     + "\r\n").encode())
        data = b""
        while True:
            chunk = tls.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > 5_000_000:
                break
    head, _ign, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
    m = re.match(r"HTTP/\S+\s+(\d{3})", status_line)
    status = int(m.group(1)) if m else 0
    if b"transfer-encoding: chunked" in head.lower():
        out, rest = b"", body
        while rest:
            size_line, _ign, rest = rest.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out += rest[:size]
            rest = rest[size + 2:]
        body = out
    return status, body.decode("utf-8", "replace")


def https_get(sock: socket.socket, host: str, path: str, timeout: float) -> str:
    status, body = https_request(sock, host, path, timeout)
    if status != 200:
        raise OSError(f"HTTP {status}")
    return body


# ── comprobador con consentimiento y límites ────────────────────────────────

class PublicIPChecker:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self._last: dict[str, float] = {}

    def _allowed(self, route: str, consent_key: str, force: bool):
        if not self.cfg["consent"].get(consent_key):
            raise ConsentRequired(_("vía '{route}' desactivada: activa consent.{consent_key} en la configuración", route=route, consent_key=consent_key))
        min_iv = parse_duration(self.cfg["public_ip"]["min_interval"])
        last = self._last.get(route, 0)
        if not force and now() - last < min_iv:
            raise RuntimeError(_("límite de frecuencia: vía '{route}' consultada hace {v3:.0f}s", route=route, v3=now() - last))
        self._last[route] = now()

    def _get(self, url: str, opener) -> dict:
        u = urllib.parse.urlsplit(url)
        timeout = parse_duration(self.cfg["public_ip"]["timeout"])
        t0 = time.monotonic()
        sock = opener(u.hostname, u.port or 443, timeout)
        body = https_get(sock, u.hostname, u.path + (f"?{u.query}" if u.query else ""), timeout)
        ip = extract_ip(body)
        if not ip:
            raise OSError(_("respuesta sin IP reconocible"))
        res = {"ip": ip, "endpoint": u.hostname, "rtt_ms": round((time.monotonic() - t0) * 1000)}
        try:
            data = json.loads(body)
            if isinstance(data, dict) and "IsTor" in data:
                res["is_tor"] = bool(data["IsTor"])
        except ValueError:
            pass
        return res

    def check(self, route: str, *, iface: str | None = None, socks: tuple[str, int] | None = None,
              http_proxy: tuple[str, int] | None = None, force: bool = False) -> dict:
        base = {"route": route, "ts": now()}
        try:
            if route == "tor":
                self._allowed(route, "tor_ip_checks", force)
                url = self.cfg["public_ip"]["tor_endpoint"]
                res = self._get(url, lambda h, p, t: open_socks5(socks, h, p, t))
            elif route.startswith("proxy"):
                self._allowed(route, "proxy_ip_checks", force)
                url = secrets.choice(self.cfg["public_ip"]["endpoints"])
                if socks:
                    res = self._get(url, lambda h, p, t: open_socks5(socks, h, p, t))
                else:
                    res = self._get(url, lambda h, p, t: open_http_connect(http_proxy, h, p, t))
            else:
                self._allowed(route, "direct_ip_checks", force)
                url = secrets.choice(self.cfg["public_ip"]["endpoints"])
                res = self._get(url, lambda h, p, t: open_direct(h, p, t, iface))
            return {**base, "ok": True, **res}
        except ConsentRequired as e:
            return {**base, "ok": False, "consent_required": True, "error": str(e)}
        except Exception as e:  # noqa: BLE001
            return {**base, "ok": False, "error": f"{type(e).__name__}: {e}"}


# ── IP WAN del router por UPnP-IGD ──────────────────────────────────────────

SSDP_ADDR = ("239.255.255.250", 1900)
WAN_SERVICES = ("urn:schemas-upnp-org:service:WANIPConnection:2", "urn:schemas-upnp-org:service:WANIPConnection:1",
                "urn:schemas-upnp-org:service:WANPPPConnection:1")
_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _ssdp_locations(timeout: float, local_ip: str | None) -> list[str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    if local_ip:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
    s.settimeout(0.5)
    for st in ("urn:schemas-upnp-org:device:InternetGatewayDevice:1", *WAN_SERVICES[1:]):
        msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n")
        s.sendto(msg.encode(), SSDP_ADDR)
    locs, deadline = [], time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            data, _ign = s.recvfrom(4096)
        except TimeoutError:
            continue
        except OSError:
            break
        m = re.search(rb"(?im)^location:\s*(\S+)", data)
        if m:
            loc = m.group(1).decode(errors="replace")
            host = urllib.parse.urlsplit(loc).hostname or ""
            try:
                if ipaddress.ip_address(host).is_private and loc not in locs:  # solo dispositivos de la LAN
                    locs.append(loc)
            except ValueError:
                pass
    s.close()
    return locs


def router_wan_ip(timeout: float = 2.5, local_ip: str | None = None) -> dict:
    try:
        locations = _ssdp_locations(timeout, local_ip)
    except OSError as e:
        return {"ok": False, "method": "upnp", "error": f"SSDP: {e}"}
    if not locations:
        return {"ok": False, "method": "upnp", "error": _("ningún router respondió a UPnP-IGD (puede estar desactivado)")}
    errors = []
    for loc in locations:
        try:
            xml = _NO_PROXY.open(loc, timeout=timeout).read()
            root = ET.fromstring(xml)
            ns = {"d": root.tag.split("}")[0].strip("{")} if root.tag.startswith("{") else {}
            pre = "d:" if ns else ""
            base = root.findtext(f"{pre}URLBase", namespaces=ns) or loc
            device = root.find(f".//{pre}device", ns)
            name = device.findtext(f"{pre}friendlyName", namespaces=ns) if device is not None else None
            for svc in root.iter(f"{{{ns['d']}}}service" if ns else "service"):
                stype = svc.findtext(f"{pre}serviceType", namespaces=ns) or ""
                if not any(stype.startswith(w.rsplit(":", 1)[0]) for w in WAN_SERVICES):
                    continue
                ctrl = urllib.parse.urljoin(base, svc.findtext(f"{pre}controlURL", namespaces=ns) or "")
                body = (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                        f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                        f'<u:GetExternalIPAddress xmlns:u="{stype}"/></s:Body></s:Envelope>')
                req = urllib.request.Request(ctrl, data=body.encode(), method="POST", headers={
                    "Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{stype}#GetExternalIPAddress"'})
                resp = _NO_PROXY.open(req, timeout=timeout).read().decode(errors="replace")
                m = re.search(r"<NewExternalIPAddress>([^<]*)</NewExternalIPAddress>", resp)
                if m and m.group(1).strip():
                    ip = m.group(1).strip()
                    addr = ipaddress.ip_address(ip)
                    cgnat = addr in ipaddress.ip_network("100.64.0.0/10")
                    return {"ok": True, "method": "upnp", "ip": ip, "device": name, "service": stype,
                            "cgnat": cgnat, "double_nat": addr.is_private and not cgnat}
        except Exception as e:  # noqa: BLE001
            errors.append(f"{loc}: {type(e).__name__}: {e}")
    return {"ok": False, "method": "upnp", "error": "; ".join(errors) or _("sin servicio WAN")}
