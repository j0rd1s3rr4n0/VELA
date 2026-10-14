"""Migración desde el nombre anterior del proyecto (opsectools / opsec / opsecd) a VELA.

Se ejecuta al arrancar cualquier comando y no hace nada si ya está migrado. Conserva todo:
  * carpetas XDG: ~/.config, ~/.local/share, ~/.local/state y ~/.cache «opsectools» → «vela»
    (se renombran, así que mantienen los permisos 0700/0600);
  * base de datos opsec.db (+ -wal/-shm) → vela.db y el log opsecd.log → velad.log;
  * servicio de systemd opsecd.service → velad.service, solo si estaba habilitado;
  * autoarranque de la bandeja y lanzador del menú de aplicaciones, solo si existían.
Si el daemon antiguo sigue en marcha no toca nada (la base de datos estaría abierta) y lo indica.
"""

from __future__ import annotations

from .i18n import _

import os
import shutil
import subprocess
from pathlib import Path

from .util import APP, xdg_dir

LEGACY = "opsectools"
OLD_UNIT = "opsecd.service"
OLD_TRAY = Path.home() / ".config/autostart/opsec-tray.desktop"
OLD_LAUNCHER = Path.home() / ".local/share/applications/org.opsectools.CommandCenter.desktop"


def _legacy(path: Path) -> Path:
    return path.parent / LEGACY


def _runtime_base() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("TEMP") or ".")
    return Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}")


def _alive(pidfile: Path) -> bool:
    try:
        os.kill(int(pidfile.read_text().strip()), 0)
        return True
    except (OSError, ValueError):
        return False


def _cache_dir() -> Path:
    return Path(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")) / APP


def _systemctl(*args, timeout=20) -> int:
    try:
        return subprocess.run(["systemctl", "--user", *args], capture_output=True, timeout=timeout).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 1


def pending() -> bool:
    return any(_legacy(xdg_dir(k)).is_dir() for k in ("config", "data", "state")) or \
        (Path.home() / ".config/systemd/user" / OLD_UNIT).exists() or OLD_TRAY.exists() or OLD_LAUNCHER.exists()


def migrate() -> list[str]:
    """Hace la migración pendiente. Devuelve lo que ha hecho (vacío si no había nada)."""
    if not pending():
        return []
    done: list[str] = []
    old_rt = _runtime_base() / LEGACY
    if _alive(old_rt / "opsecd.pid"):
        return [_("el daemon antiguo (opsecd) sigue en marcha: detenlo con «systemctl --user stop opsecd» y vuelve "
                "a ejecutar cualquier comando de vela para migrar")]
    # 1) servicio de systemd (antes de mover nada: el antiguo apunta a rutas viejas)
    old_unit = Path.home() / ".config/systemd/user" / OLD_UNIT
    unit_enabled = False
    if old_unit.exists():
        unit_enabled = _systemctl("is-enabled", "--quiet", OLD_UNIT) == 0
        _systemctl("disable", "--now", OLD_UNIT)
        old_unit.unlink(missing_ok=True)
        _systemctl("daemon-reload")
        done.append(f"servicio {OLD_UNIT} retirado")
    # 2) carpetas XDG
    for kind in ("config", "data", "state"):
        new = xdg_dir(kind)
        old = _legacy(new)
        if old.is_dir() and not new.exists():
            old.rename(new)
            done.append(f"{old} → {new}")
        elif old.is_dir():
            done.append(_("{old} se conserva: ya existe {new} (revisa a mano si queda algo dentro)", old=old, new=new))
    cache = _cache_dir()
    if _legacy(cache).is_dir() and not cache.exists():
        _legacy(cache).rename(cache)
        done.append(f"{_legacy(cache)} → {cache}")
    # 3) nombres de ficheros dentro
    data = xdg_dir("data")
    if (data / "opsec.db").exists() and not (data / "vela.db").exists():
        for suf in ("", "-wal", "-shm", "-journal"):
            if (data / f"opsec.db{suf}").exists():
                (data / f"opsec.db{suf}").rename(data / f"vela.db{suf}")
        done.append(_("base de datos opsec.db → vela.db (historial conservado)"))
    state = xdg_dir("state")
    if (state / "opsecd.log").exists() and not (state / "velad.log").exists():
        (state / "opsecd.log").rename(state / "velad.log")
    # 4) restos del runtime antiguo (socket y pid de un daemon ya parado)
    if old_rt.is_dir():
        shutil.rmtree(old_rt, ignore_errors=True)
    # 5) volver a dejar lo que el usuario tenía activado, con el nombre nuevo
    if unit_enabled:
        from . import autostart
        r = autostart.enable()
        done.append(_("servicio velad.service habilitado (como lo estaba opsecd)") if r.get("ok") else
                    _("no se pudo habilitar velad.service: {v1}", v1=r.get('error')))
    if OLD_TRAY.exists():
        OLD_TRAY.unlink()
        from . import autostart
        autostart.tray_enable(start_now=False)
        done.append(_("autoarranque de la bandeja → vela-tray.desktop"))
    if OLD_LAUNCHER.exists():
        OLD_LAUNCHER.unlink()
        try:
            from .native.app import install_desktop
            done.append(_("lanzador del menú → {v1}", v1=install_desktop()))
        except Exception as e:  # noqa: BLE001 (sin GTK: se instala luego con «vela app --install»)
            done.append(_("lanzador antiguo retirado; instala el nuevo con «vela app --install» ({e})", e=e))
    return done
