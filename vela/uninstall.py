"""Desinstalación fácil de VELA (`vela uninstall`, Ajustes → Desinstalar y la acción del lanzador).

Quita lo que pone install.sh: servicio velad, bandeja, lanzador e iconos, comandos `vela`/`velad` y la
copia del programa en ~/.local/lib/vela. Con `purge` borra además historial, ajustes y claves de API.

Reglas de seguridad:
  * nunca borra una carpeta que sea un repositorio git (tu clon de trabajo se queda donde está), salvo el
    clon que creó autoinstall.sh en ~/.local/src/VELA y solo si no tiene cambios sin guardar;
  * no toca paquetes del sistema (GTK, Tor, OCR…) ni modelos de Ollama: los usan otros programas;
  * `dry_run` enseña la lista exacta sin cambiar nada.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from . import autostart
from .i18n import _

APP_ID = "io.github.j0rd1s3rr4n0.Vela"
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)


def _home(var: str, default: str) -> Path:
    return Path(os.environ.get(var) or Path.home() / default)


def prefix() -> Path:
    return Path(os.environ.get("VELA_PREFIX") or Path.home() / ".local/lib/vela")


def bin_dir() -> Path:
    return Path(os.environ.get("VELA_BIN") or os.environ.get("XDG_BIN_HOME") or Path.home() / ".local/bin")


def autoinstall_clone() -> Path:
    return Path(os.environ.get("VELA_DIR") or Path.home() / ".local/src/VELA")


def data_dirs() -> list[Path]:
    """Historial, ajustes, claves de API, caché del mapa y registros."""
    return [_home("XDG_CONFIG_HOME", ".config") / "vela", _home("XDG_DATA_HOME", ".local/share") / "vela",
            _home("XDG_STATE_HOME", ".local/state") / "vela", _home("XDG_CACHE_HOME", ".cache") / "vela"]


def _is_ours(path: Path, marker: str) -> bool:
    """El fichero es de VELA (contiene su marca), no uno del usuario que se llame igual."""
    try:
        return marker in path.read_text(errors="replace")
    except OSError:
        return False


def _clone_is_clean(path: Path) -> bool:
    try:
        p = subprocess.run(["git", "-C", str(path), "status", "--porcelain"], capture_output=True, text=True,
                           timeout=30, stdin=subprocess.DEVNULL)
        return p.returncode == 0 and not p.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False


def _safe_to_remove(path: Path) -> bool:
    """Solo carpetas que contienen el paquete vela y que no son el home, la raíz ni una carpeta de sistema."""
    try:
        path = path.resolve()
    except OSError:
        return False
    home = Path.home().resolve()
    if path in (Path("/"), home) or home not in path.parents or len(path.relative_to(home).parts) < 2:
        return False
    return (path / "vela" / "__init__.py").exists()


def plan(purge: bool = False) -> dict:
    """Qué se quitaría (solo lo que existe) y qué se conserva, con el motivo."""
    data_home = _home("XDG_DATA_HOME", ".local/share")
    files, dirs, kept = [], [], []
    for f in (autostart.unit_path(), autostart.tray_autostart_path(), data_home / f"applications/{APP_ID}.desktop",
              data_home / f"icons/hicolor/scalable/apps/{APP_ID}.svg",
              *(data_home / f"icons/hicolor/{n}x{n}/apps/{APP_ID}.png" for n in ICON_SIZES)):
        if f.exists():
            files.append(f)
    for name in ("vela", "velad"):            # solo nuestros envoltorios, no otro programa con el mismo nombre
        f = bin_dir() / name
        if f.exists() and _is_ours(f, "from vela.cli import main"):
            files.append(f)
    pre = prefix()
    if pre.exists():
        if (pre / ".git").exists():
            kept.append((pre, _("es un repositorio git: no se borra")))
        elif _safe_to_remove(pre):
            dirs.append(pre)
        else:
            kept.append((pre, _("no parece una instalación de VELA: no se borra")))
    clone = autoinstall_clone()
    if (clone / ".git").exists() and (clone / "autoinstall.sh").exists() and _safe_to_remove(clone):
        if _clone_is_clean(clone):
            dirs.append(clone)
        else:
            kept.append((clone, _("tiene cambios sin guardar: no se borra")))
    data = [d for d in data_dirs() if d.exists()] if purge else []
    if not purge:
        kept += [(d, _("tus datos: usa --purge para borrarlos")) for d in data_dirs() if d.exists()]
    return {"files": files, "dirs": dirs, "data": data, "kept": kept,
            "notes": [_("Los paquetes del sistema (GTK, Tor, OCR…) y los modelos de Ollama no se tocan: los pueden "
                        "usar otros programas.")]}


def run(purge: bool = False, dry_run: bool = False, progress=lambda m: None) -> dict:
    p = plan(purge)
    if dry_run:
        return {**p, "done": False}
    errors = []
    progress(_("parando el servicio velad"))
    try:
        if autostart.unit_path().exists() and autostart.status().get("available"):
            autostart.disable()
    except Exception as e:  # noqa: BLE001
        errors.append(f"velad: {e}")
    try:                                    # por si se arrancó a mano (vela daemon start), fuera de systemd
        import contextlib
        import io
        from .daemon import stop_daemon
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            stop_daemon()
    except Exception:  # noqa: BLE001
        pass
    progress(_("quitando el icono de la bandeja"))
    try:
        if autostart.tray_autostart_path().exists() or autostart.tray_running():
            autostart.tray_disable(stop_now=True)
    except Exception as e:  # noqa: BLE001
        errors.append(f"tray: {e}")
    progress(_("borrando lanzador, iconos y comandos"))
    for f in p["files"]:
        try:
            f.unlink(missing_ok=True)
        except OSError as e:
            errors.append(f"{f}: {e}")
    if autostart.unit_path() in p["files"] and shutil.which("systemctl"):
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True, timeout=30,
                       stdin=subprocess.DEVNULL)
    if p["data"]:
        progress(_("borrando historial, ajustes y claves"))
    for d in p["data"] + p["dirs"]:          # la copia instalada (donde puede estar este código) va la última
        try:
            shutil.rmtree(d)
        except OSError as e:
            errors.append(f"{d}: {e}")
    return {**p, "done": True, "errors": errors}


def describe(p: dict) -> list[str]:
    from .util import tilde
    out = []
    if p["files"] or p["dirs"]:
        out.append(_("Se quitará:"))
        out += [f"  - {tilde(x)}" for x in p["files"] + p["dirs"]]
    if p["data"]:
        out.append(_("Se BORRARÁN tus datos (historial, ajustes, claves de API):"))
        out += [f"  - {tilde(x)}" for x in p["data"]]
    if p["kept"]:
        out.append(_("Se conserva:"))
        out += [f"  - {tilde(x)} ({why})" for x, why in p["kept"]]
    out += p["notes"]
    return out
