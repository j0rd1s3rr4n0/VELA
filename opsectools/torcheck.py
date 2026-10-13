"""¿Es esta IP de Tor? Tres fuentes, de más privada a menos:

1. Consenso de TU Tor (ControlPort, GETINFO ns/all): relays actuales con IP, ORPort y flags
   (Guard, Exit…). No sale nada a la red.
2. Lista oficial de salidas (https://check.torproject.org/torbulkexitlist): IPs desde las que salen
   los exits (pueden diferir de la del relay). Se descarga ENTERA y por Tor: no revela qué IP te interesa.
3. ExoneraTor (https://metrics.torproject.org/exonerator.html): si la IP fue relay de Tor en una fecha.
   Es por IP, así que siempre va por Tor; si su servidor responde con error se marca "no disponible".
   Solo acepta fechas hasta anteayer: confirma el pasado reciente, no el estado de hoy (para eso, 1 y 2).
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time

from .publicip import https_request, open_socks5
from .util import now

_LOCK = threading.Lock()
_CONSENSUS: dict = {"ts": 0, "by_ip": {}, "count": 0}
_EXITLIST: dict = {"ts": 0, "ips": set(), "error": None}
CONSENSUS_TTL = 1800
EXITLIST_TTL = 3600


def parse_ns_all(text: str) -> dict[str, list[dict]]:
    """Formato de GETINFO ns/all: líneas r/a/s/w por relay."""
    by_ip: dict[str, list[dict]] = {}
    cur = None
    for line in text.splitlines():
        if line.startswith("r "):
            p = line.split()
            if len(p) >= 8:
                cur = {"nick": p[1], "ip": p[6], "orport": int(p[7]), "flags": [], "ipv6": []}
                cur["fp"] = _b64_to_hex(p[2])
                by_ip.setdefault(p[6], []).append(cur)
        elif line.startswith("a ") and cur is not None:
            m = re.match(r"a \[([0-9a-fA-F:]+)\]:(\d+)", line)
            if m:
                ip6 = str(ipaddress.ip_address(m.group(1)))
                cur["ipv6"].append(ip6)
                by_ip.setdefault(ip6, []).append(cur)
        elif line.startswith("s ") and cur is not None:
            cur["flags"] = line[2:].split()
    return by_ip


def _b64_to_hex(b64: str) -> str:
    import base64
    try:
        return base64.b64decode(b64 + "=" * (-len(b64) % 4)).hex().upper()
    except ValueError:
        return ""


def consensus(observer) -> dict:
    """Relays actuales por IP desde el ControlPort (caché 30 min)."""
    with _LOCK:
        if now() - _CONSENSUS["ts"] < CONSENSUS_TTL and _CONSENSUS["by_ip"]:
            return _CONSENSUS
    try:
        ctl = observer._connect()
        try:
            text = ctl.getinfo("ns/all").get("ns/all", "")
        finally:
            ctl.close()
        by_ip = parse_ns_all(text)
        with _LOCK:
            _CONSENSUS.update(ts=now(), by_ip=by_ip, count=sum(len(v) for v in by_ip.values()), error=None)
    except Exception as e:  # noqa: BLE001
        with _LOCK:
            _CONSENSUS["error"] = str(e)
    return _CONSENSUS


def exit_list(socks: tuple[str, int] | None) -> dict:
    """Lista oficial de IPs de salida de Tor (descarga completa por Tor, caché 1 h)."""
    with _LOCK:
        if now() - _EXITLIST["ts"] < EXITLIST_TTL and _EXITLIST["ips"]:
            return _EXITLIST
    if not socks:
        return _EXITLIST
    try:
        s = open_socks5(socks, "check.torproject.org", 443, 40)
        code, body = https_request(s, "check.torproject.org", "/torbulkexitlist", 40)
        if code != 200:
            raise OSError(f"HTTP {code}")
        ips = set()
        for line in body.splitlines():
            line = line.strip()
            try:
                ips.add(str(ipaddress.ip_address(line)))
            except ValueError:
                continue
        with _LOCK:
            _EXITLIST.update(ts=now(), ips=ips, error=None)
    except Exception as e:  # noqa: BLE001
        with _LOCK:
            _EXITLIST["error"] = str(e)
    return _EXITLIST


def parse_exonerator(html: str) -> dict:
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    if "Result is positive" in text:
        cells = re.findall(r"<td[^>]*>([^<]{1,80})</td>", html)
        relays = []
        for i in range(0, len(cells) - 3, 5):
            if re.fullmatch(r"[0-9A-F]{40}", cells[i + 2].strip()):
                relays.append({"date": cells[i].strip(), "fp": cells[i + 2].strip(), "nick": cells[i + 3].strip(),
                               "exit": cells[i + 4].strip().lower() == "yes"})
        uniq = {r["fp"]: r for r in relays}
        return {"status": "ok", "result": "positivo", "relays": list(uniq.values())[:10],
                "exit": any(r["exit"] for r in uniq.values())}
    if "Result is negative" in text:
        return {"status": "ok", "result": "negativo", "relays": []}
    m = re.search(r'panel-title"[^>]*>(.*?)</h3>.*?panel-body"[^>]*>(.*?)</div>', html, re.S)
    msg = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", (m.group(1) + ": " + m.group(2)) if m else "sin resultado")).strip()
    return {"status": "no_disponible", "result": None, "detail": msg[:200]}


def exonerator(ip: str, socks: tuple[str, int] | None, date: str | None = None, timeout: float = 40) -> dict:
    """Consulta ExoneraTor por Tor. `date` (AAAA-MM-DD, por defecto ayer UTC)."""
    if not socks:
        return {"status": "no_disponible", "result": None, "detail": "sin Tor: ExoneraTor solo se consulta por Tor"}
    # ExoneraTor solo acepta fechas hasta anteayer (UTC)
    date = date or time.strftime("%Y-%m-%d", time.gmtime(time.time() - 2 * 86400))
    try:
        s = open_socks5(socks, "metrics.torproject.org", 443, timeout)
        code, body = https_request(s, "metrics.torproject.org", f"/exonerator.html?ip={ip}&timestamp={date}&lang=en",
                                   timeout)
    except Exception as e:  # noqa: BLE001
        return {"status": "no_disponible", "result": None, "detail": f"{type(e).__name__}: {e}", "date": date}
    if code != 200:
        return {"status": "no_disponible", "result": None, "detail": f"HTTP {code}", "date": date}
    return {**parse_exonerator(body), "date": date}


def classify(ip: str, cons: dict, exits: dict, exo: dict | None = None) -> dict:
    """Combina las fuentes en un veredicto: exit / relay / no / desconocido."""
    relays = cons.get("by_ip", {}).get(ip, [])
    in_exitlist = ip in exits.get("ips", set())
    flags = sorted({f for r in relays for f in r["flags"]})
    is_exit = in_exitlist or "Exit" in flags or bool((exo or {}).get("exit"))
    is_relay = bool(relays) or in_exitlist or (exo or {}).get("result") == "positivo"
    if is_exit:
        verdict = "exit"
    elif is_relay:
        verdict = "relay"
    elif cons.get("by_ip") or exits.get("ips"):
        verdict = "no"
    else:
        verdict = "desconocido"
    return {"verdict": verdict, "relays": [{"nick": r["nick"], "fp": r["fp"], "flags": r["flags"]} for r in relays][:5],
            "flags": flags, "in_exit_list": in_exitlist, "consensus": bool(relays),
            "exonerator": exo, "sources": {"consensus_relays": cons.get("count", 0), "exit_list": len(exits.get("ips", ())),
                                           "consensus_error": cons.get("error"), "exit_list_error": exits.get("error")}}
