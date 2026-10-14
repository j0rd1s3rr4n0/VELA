"""Kill-switch con nftables en una tabla PROPIA (`inet vela_ks`).

No modifica ni borra reglas existentes (ufw, firewalld, Docker…): solo crea y elimina su tabla.
Aplicarlo requiere consent.allow_killswitch y privilegios (root, `sudo -n` o pkexec con diálogo).
Política: bloquea toda salida nueva salvo loopback, interfaces de túnel, endpoints VPN permitidos,
el usuario del daemon de Tor y (opcional) la LAN. Liberarlo = borrar la tabla.
"""

from __future__ import annotations

from .i18n import _

import ipaddress
import os
import pwd

from .util import now, run, which

TABLE = "vela_ks"
LEGACY_TABLES = ("opsec_ks",)   # nombre anterior del proyecto: se retira si quedó aplicada


def _endpoint_rules(endpoints: list[str]) -> list[str]:
    rules = []
    for ep in endpoints:
        host, _ign, port = ep.strip().rpartition(":")
        host = host.strip("[]") or ep
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue  # nombres no: el DNS estaría bloqueado y abriría la puerta a fugas
        fam = "ip" if ip.version == 4 else "ip6"
        if port.isdigit():
            rules.append(f"{fam} daddr {ip} udp dport {port} accept")
            rules.append(f"{fam} daddr {ip} tcp dport {port} accept")
        else:
            rules.append(f"{fam} daddr {ip} accept")
    return rules


def build_ruleset(tunnel_ifaces: list[str], endpoints: list[str], allow_lan: bool = True,
                  allow_users: list[str] = ()) -> str:
    lines = [f"table inet {TABLE} {{", "  chain output {",
             "    type filter hook output priority -10; policy drop;",
             '    oifname "lo" accept']
    if tunnel_ifaces:
        names = ", ".join(f'"{i}"' for i in sorted(set(tunnel_ifaces)))
        lines.append(f"    oifname {{ {names} }} accept")
    lines += [f"    {r}" for r in _endpoint_rules(endpoints)]
    for user in allow_users:
        try:
            uid = pwd.getpwnam(user).pw_uid
            lines.append(f"    meta skuid {uid} accept")
        except KeyError:
            pass
    if allow_lan:
        lines += ["    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } accept",
                  "    ip6 daddr { fe80::/10, fc00::/7 } accept",
                  "    udp dport { 67, 68 } accept"]
    lines += ["    counter drop", "  }", "}"]
    return "\n".join(lines) + "\n"


class KillSwitch:
    def __init__(self, cfg: dict, tunnels_fn=lambda: []):
        self.cfg = cfg
        self.tunnels_fn = tunnels_fn
        self.state = {"active": False, "since": None, "reason": None, "backend": "nftables"}

    def _priv_cmd(self) -> list[str] | None:
        if os.geteuid() == 0:
            return []
        code, _ign, _ign = run(["sudo", "-n", "true"])
        if code == 0:
            return ["sudo", "-n"]
        if which("pkexec") and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return ["pkexec"]
        return None

    def can_apply(self) -> tuple[bool, str]:
        if not self.cfg["consent"].get("allow_killswitch"):
            return False, _("consent.allow_killswitch está desactivado")
        if not which("nft"):
            return False, _("nft no instalado")
        if self._priv_cmd() is None:
            return False, _("sin privilegios (root, sudo -n o pkexec con entorno gráfico)")
        return True, ""

    def ruleset(self, endpoints: list[str] = ()) -> str:
        users = [u for u in ("debian-tor", "tor", "_tor") if _user_exists(u)]
        return build_ruleset(self.tunnels_fn(), list(endpoints), self.cfg["killswitch"].get("allow_lan", True), users)

    def engage(self, endpoints: list[str] = (), reason: str = "manual") -> dict:
        ok, why = self.can_apply()
        if not ok:
            return {"ok": False, "error": why}
        priv = self._priv_cmd()
        # add+delete hace la operación idempotente; todo el fichero se aplica de forma atómica
        script = "".join(f"add table inet {t}\ndelete table inet {t}\n" for t in (TABLE, *LEGACY_TABLES)) \
            + self.ruleset(endpoints)
        code, _ign, err = run([*priv, "nft", "-f", "-"], timeout=60, input_text=script)
        if code:
            return {"ok": False, "error": f"nft: {err.strip()}"}
        self.state.update(active=True, since=now(), reason=reason)
        return {"ok": True}

    def release(self) -> dict:
        if not self.state["active"]:
            return {"ok": True, "detail": _("no estaba activo")}
        priv = self._priv_cmd()
        if priv is None:
            return {"ok": False, "error": _("sin privilegios para retirar la tabla")}
        for legacy in LEGACY_TABLES:
            run([*priv, "nft", "delete", "table", "inet", legacy], timeout=60)
        code, _ign, err = run([*priv, "nft", "delete", "table", "inet", TABLE], timeout=60)
        if code and "No such file" not in err:
            return {"ok": False, "error": f"nft: {err.strip()}"}
        self.state.update(active=False, since=None, reason=None)
        return {"ok": True}

    def status(self) -> dict:
        ok, why = self.can_apply()
        return {**self.state, "can_apply": ok, "reason_unavailable": why or None}


def _user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False
