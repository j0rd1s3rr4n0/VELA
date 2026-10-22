"""Lanzar aplicaciones del sistema con otra zona horaria, sin cambiar la del escritorio.

VELA lee los ficheros `.desktop` (sistema, usuario, Flatpak y Snap) y arranca la aplicación con
`TZ=<zona>` en su entorno. La zona del sistema no se toca. Es útil para alinear el navegador o
una app concreta con el país de salida de la VPN sin cambiar el reloj de todo el escritorio.

Limitaciones: las apps que se activan por D-Bus pueden reutilizar una instancia ya abierta y
heredar su entorno; las apps planas que ignoran `TZ` tampoco cambiarán. La interfaz lo avisa.
"""

from __future__ import annotations

from .i18n import _

import os
import re
import shlex
import subprocess
from pathlib import Path

from .util import which

def _data_home() -> Path:
    return Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")


def desktop_dirs() -> list[Path]:
    data = _data_home()
    return [
        Path("/usr/share/applications"),
        Path("/usr/local/share/applications"),
        data / "applications",
        Path("/var/lib/flatpak/exports/share/applications"),
        data / "flatpak/exports/share/applications",
        Path("/var/lib/snapd/desktop/applications"),
    ]
FIELD_CODE = re.compile(r"%[fFuUdDnNickvm]")


def _clean(value: str | None) -> str:
    return (value or "").strip()


def _parse(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    group = None
    data: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            group = line[1:-1]
            continue
        if group != "Desktop Entry":
            continue
        key, sep, val = line.partition("=")
        if sep:
            data[key] = val
    if data.get("Type") != "Application" or data.get("Hidden", "").lower() == "true":
        return None
    if data.get("NoDisplay", "").lower() == "true":
        return None
    exec_ = _clean(data.get("Exec"))
    if not exec_:
        return None
    try:
        argv = shlex.split(exec_)
    except ValueError:
        return None
    argv = [FIELD_CODE.sub("", a) for a in argv]
    argv = [a for a in argv if a]
    if not argv:
        return None
    return {
        "id": path.stem,
        "path": str(path),
        "name": _clean(data.get("Name")) or path.stem,
        "comment": _clean(data.get("Comment")),
        "icon": _clean(data.get("Icon")),
        "exec": argv,
        "terminal": data.get("Terminal", "").lower() == "true",
        "dbus": data.get("DBusActivatable", "").lower() == "true",
        "flatpak": argv[0] == "flatpak" or "flatpak" in path.parts,
        "categories": _clean(data.get("Categories")),
    }


def apps(query: str | None = None) -> list[dict]:
    seen: dict[str, dict] = {}
    dirs = desktop_dirs()
    user_apps = _data_home() / "applications"
    for d in dirs:
        try:
            files = sorted(d.glob("*.desktop"))
        except OSError:
            continue
        for p in files:
            app = _parse(p)
            if not app:
                continue
            key = app["name"].lower()
            if key not in seen or d == user_apps:
                seen[key] = app
    out = sorted(seen.values(), key=lambda a: a["name"].lower())
    if query:
        q = query.lower()
        out = [a for a in out if q in a["name"].lower() or q in (a["comment"] or "").lower()
               or q in a["id"].lower()]
    return out


def timezones() -> list[dict]:
    """Zonas de /usr/share/zoneinfo/zone.tab, con país y coordenadas."""
    out = []
    try:
        for line in Path("/usr/share/zoneinfo/zone.tab").read_text(encoding="utf-8", errors="replace").splitlines():
            if not line or line.startswith("#"):
                continue
            f = line.split("\t")
            if len(f) < 3:
                continue
            out.append({"country": f[0], "coords": f[1], "name": f[2], "comment": f[3] if len(f) > 3 else ""})
    except OSError:
        pass
    if not out:
        for line in Path("/usr/share/zoneinfo/zone1970.tab").read_text(encoding="utf-8", errors="replace").splitlines() \
                if Path("/usr/share/zoneinfo/zone1970.tab").exists() else []:
            if line and not line.startswith("#"):
                f = line.split("\t")
                if len(f) >= 3:
                    out.append({"country": f[0], "coords": f[1], "name": f[2], "comment": ""})
    names = {z["name"] for z in out}
    if "UTC" not in names:
        out.insert(0, {"country": "--", "coords": "", "name": "UTC", "comment": "UTC"})
    return sorted(out, key=lambda z: z["name"])


def timezone_names() -> list[str]:
    return [z["name"] for z in timezones()]


def validate_timezone(name: str) -> str:
    if name not in set(timezone_names()):
        raise ValueError(_("zona horaria no válida: {name}", name=name))
    return name


def current_timezone() -> str:
    try:
        return Path("/etc/timezone").read_text().strip() or os.environ.get("TZ") or "UTC"
    except OSError:
        return os.environ.get("TZ") or "UTC"


def _terminal_wrap(argv: list[str]) -> list[str]:
    for term, flag in (("x-terminal-emulator", "-e"), ("gnome-terminal", "--"), ("konsole", "-e"),
                       ("xterm", "-e")):
        if which(term):
            return [term, flag, *argv]
    return argv


def launch(app: str | Path | dict, tz: str, extra: list[str] | None = None, dry_run: bool = False) -> dict:
    """Lanza una app de `.desktop` con TZ. `app` puede ser id, ruta o dict de `apps()`."""
    validate_timezone(tz)
    if isinstance(app, dict):
        entry = app
    else:
        key = str(app)
        found = [a for a in apps() if a["id"] == key or a["path"] == key or a["name"].lower() == key.lower()]
        if not found:
            raise ValueError(_("aplicación no encontrada: {app}", app=key))
        entry = found[0]
    argv = list(entry["exec"]) + list(extra or [])
    if entry.get("terminal"):
        argv = _terminal_wrap(argv)
    env = {**os.environ, "TZ": tz}
    result = {"app": entry["name"], "id": entry["id"], "timezone": tz, "command": argv,
              "warning": _("La app puede reutilizar una instancia ya abierta y no heredar TZ") if entry.get("dbus") else None}
    if dry_run:
        result["dry_run"] = True
        return result
    try:
        p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        result["pid"] = p.pid
        result["ok"] = True
    except OSError as e:
        result.update(ok=False, error=str(e))
    return result


def launch_command(command: str, tz: str, dry_run: bool = False) -> dict:
    validate_timezone(tz)
    argv = shlex.split(command)
    if not argv:
        raise ValueError(_("comando vacío"))
    env = {**os.environ, "TZ": tz}
    result = {"timezone": tz, "command": argv}
    if dry_run:
        result["dry_run"] = True
        return result
    try:
        p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
        result.update(ok=True, pid=p.pid)
    except OSError as e:
        result.update(ok=False, error=str(e))
    return result
