"""Cambiador de MAC: aleatoria, manual y restauración.

La MAC se cambia en la interfaz con `ip link` (o `macchanger` si está instalado). Es un cambio
temporal: al reiniciar o reconectar, NetworkManager puede volver a la MAC original. Antes de
tocar nada se guarda la MAC actual en un fichero 0600 y, si el cambio falla, se intenta
restaurar. Se avisa de que la conexión se corta unos segundos.

Requiere `[consent] allow_mac_changes = true` para aplicar. Sin consentimiento solo se muestra
el plan.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import random
import re
from pathlib import Path

from . import config as config_mod
from .util import now, private_dir, run, tilde, which, xdg_dir

STATE = xdg_dir("state") / "mac-backup.json"


class MacError(RuntimeError):
    pass


def _read(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text().strip()
    except OSError:
        return default


def validate_mac(mac: str) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise MacError(_("MAC no válida: {mac}", mac=mac))
    first = int(mac.split(":")[0], 16)
    if first & 1:
        raise MacError(_("la MAC debe ser unicast (el primer octeto no puede ser impar)"))
    return mac


def random_mac() -> str:
    b = [random.randrange(256) for _ in range(6)]
    b[0] = (b[0] & 0xFC) | 0x02          # localmente administrada y unicast
    return ":".join(f"{x:02x}" for x in b)


def permanent_mac(iface: str) -> str | None:
    if which("ethtool"):
        code, out, _err = run(["ethtool", "-P", iface], timeout=5)
        if code == 0:
            m = re.search(r"Permanent address:\s*([0-9a-f:]{17})", out, re.I)
            if m:
                return m.group(1).lower()
    return None


def interfaces() -> list[dict]:
    out = []
    base = Path("/sys/class/net")
    try:
        names = sorted(p.name for p in base.iterdir() if p.name != "lo")
    except OSError:
        return out
    for name in names:
        d = base / name
        mac = _read(str(d / "address"))
        assign = _read(str(d / "addr_assign_type"))
        driver = None
        try:
            driver = os.path.basename(os.readlink(d / "device/driver"))
        except OSError:
            pass
        out.append({
            "name": name,
            "mac": mac,
            "permanent": permanent_mac(name),
            "randomized": assign == "1",
            "kind": "virtual" if not (d / "device").exists() else "física",
            "driver": driver,
            "state": _read(str(d / "operstate")),
            "up": _read(str(d / "operstate")) in ("up", "unknown"),
            "wireless": (d / "wireless").exists(),
        })
    return out


def _iface(name: str) -> dict:
    for i in interfaces():
        if i["name"] == name:
            return i
    raise MacError(_("interfaz no encontrada: {name}", name=name))


def _load_state() -> dict:
    try:
        return json.loads(STATE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_state(data: dict) -> None:
    private_dir(STATE.parent)
    tmp = STATE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, STATE)


def _priv(args: list[str], timeout: float = 60) -> tuple[int, str, str]:
    if os.geteuid() == 0:
        return run(args, timeout=timeout)
    if which("pkexec"):
        return run(["pkexec", *args], timeout=timeout)
    if which("sudo"):
        code, out, err = run(["sudo", "-n", *args], timeout=timeout)
        if code == 0:
            return code, out, err
        raise MacError(_("sudo pide contraseña; ejecuta el comando a mano o instala pkexec"))
    raise MacError(_("no hay pkexec ni sudo: no puedo cambiar la MAC"))


def _nm_warning(iface: str) -> str | None:
    if not which("nmcli"):
        return None
    code, out, _err = run(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"], timeout=5)
    if code == 0 and any(line.rsplit(":", 1)[-1] == iface for line in out.splitlines()):
        return _("NetworkManager controla {iface}: puede restaurar su MAC al reconectar. Para que sea "
                 "persistente usa cloned-mac-address en la conexión.", iface=iface)
    return None


def plan(iface: str, mac: str | None = None, use_random: bool = False) -> dict:
    i = _iface(iface)
    if i["kind"] == "virtual":
        raise MacError(_("no cambio la MAC de interfaces virtuales ({iface})", iface=iface))
    new = random_mac() if use_random or not mac else validate_mac(mac)
    if new == i["mac"]:
        raise MacError(_("la MAC nueva es igual a la actual"))
    tool = "ip"
    if which("macchanger"):
        tool = "macchanger"
        cmds = [["ip", "link", "set", "dev", iface, "down"],
                ["macchanger", "--mac", new, iface],
                ["ip", "link", "set", "dev", iface, "up"]]
    else:
        cmds = [["ip", "link", "set", "dev", iface, "down"],
                ["ip", "link", "set", "dev", iface, "address", new],
                ["ip", "link", "set", "dev", iface, "up"]]
    return {"iface": iface, "current": i["mac"], "new": new, "commands": cmds, "tool": tool,
            "warning": _nm_warning(iface), "consent": bool((config_mod.load().get("consent") or {}).get("allow_mac_changes"))}


def _set(iface: str, mac: str) -> dict:
    i = _iface(iface)
    p = plan(iface, mac=mac)
    state = _load_state()
    state.setdefault(iface, {"original": i["mac"], "changed": now(), "permanent": i.get("permanent")})
    _save_state(state)
    for cmd in p["commands"]:
        code, out, err = _priv(cmd)
        if code != 0:
            # intentar devolver la interfaz a su estado original
            try:
                _priv(["ip", "link", "set", "dev", iface, "address", i["mac"]])
                _priv(["ip", "link", "set", "dev", iface, "up"])
            except Exception:  # noqa: BLE001
                pass
            raise MacError(_("falló «{cmd}»: {e}", cmd=" ".join(cmd), e=(err or out).strip()[:400]))
    actual = _iface(iface)["mac"]
    ok = actual.lower() == p["new"].lower()
    return {"ok": ok, "iface": iface, "old": i["mac"], "new": actual if ok else p["new"],
            "actual": actual, "tool": p["tool"], "warning": p["warning"],
            "error": None if ok else _("la interfaz no aceptó la MAC (driver o permisos)")}


def set_mac(iface: str, mac: str | None = None, use_random: bool = False, apply: bool = False,
            cfg: dict | None = None, engine=None) -> dict:
    cfg = cfg or config_mod.load()
    p = plan(iface, mac=mac, use_random=use_random)
    if not apply:
        return {"ok": True, "dry_run": True, "plan": p}
    if not (cfg.get("consent") or {}).get("allow_mac_changes"):
        raise MacError(_("activa [consent] allow_mac_changes = true para cambiar la MAC"))
    res = _set(iface, p["new"])
    if engine is not None:
        try:
            engine.store.audit(getattr(engine, "actor", "cli"), "mac_set",
                               {"iface": iface, "old": res.get("old"), "new": res.get("new"), "ok": res["ok"]})
        except Exception:  # noqa: BLE001
            pass
    return res


def restore(iface: str, apply: bool = False, cfg: dict | None = None, engine=None) -> dict:
    cfg = cfg or config_mod.load()
    i = _iface(iface)
    state = _load_state()
    target = (state.get(iface) or {}).get("original") or i.get("permanent") or i["mac"]
    if target == i["mac"]:
        return {"ok": True, "iface": iface, "mac": i["mac"], "detail": _("ya tiene la MAC original")}
    if not apply:
        return {"ok": True, "dry_run": True, "iface": iface, "current": i["mac"], "target": target}
    if not (cfg.get("consent") or {}).get("allow_mac_changes"):
        raise MacError(_("activa [consent] allow_mac_changes = true para cambiar la MAC"))
    res = _set(iface, target)
    if res["ok"]:
        state.pop(iface, None)
        _save_state(state)
    if engine is not None:
        try:
            engine.store.audit(getattr(engine, "actor", "cli"), "mac_restore", {"iface": iface, "ok": res["ok"]})
        except Exception:  # noqa: BLE001
            pass
    return res


def state_path() -> str:
    return tilde(STATE)
