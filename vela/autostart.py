"""Arranque automático de `velad` con la sesión (servicio de usuario de systemd).

Así la monitorización y el historial siguen guardándose aunque la app o la terminal estén cerradas.
No requiere root: el servicio vive en ~/.config/systemd/user/.
"""

from __future__ import annotations

import sys
from pathlib import Path

from .util import run, which

UNIT = "velad.service"


def unit_path() -> Path:
    return Path.home() / ".config/systemd/user" / UNIT


def unit_text() -> str:
    root = Path(__file__).resolve().parents[1]
    return f"""[Unit]
Description=VELA (monitorización de red y fugas)
After=network-online.target graphical-session.target

[Service]
Type=simple
Environment=PYTHONPATH={root}
ExecStart={sys.executable} -m vela daemon run
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
"""


def status() -> dict:
    if not which("systemctl"):
        return {"available": False, "enabled": False, "active": False,
                "tray_autostart": tray_autostart_enabled(), "tray_running": tray_running()}
    _ign, en, _ign = run(["systemctl", "--user", "is-enabled", UNIT])
    _ign, ac, _ign = run(["systemctl", "--user", "is-active", UNIT])
    return {"available": True, "enabled": en.strip() == "enabled", "active": ac.strip() == "active",
            "unit": str(unit_path()), "tray_autostart": tray_autostart_enabled(), "tray_running": tray_running()}


def enable() -> dict:
    from . import daemon
    p = unit_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(unit_text())
    daemon.stop_daemon()             # el daemon lanzado a mano se sustituye por el de systemd
    run(["systemctl", "--user", "daemon-reload"])
    code, _ign, err = run(["systemctl", "--user", "enable", "--now", UNIT], timeout=20)
    return {"ok": code == 0, "error": err.strip() or None, **status()}


def disable() -> dict:
    code, _ign, err = run(["systemctl", "--user", "disable", "--now", UNIT], timeout=20)
    return {"ok": code == 0, "error": err.strip() or None, **status()}


# ── icono de bandeja (autoarranque XDG, sin depender de GTK) ──

TRAY_DESKTOP = """[Desktop Entry]
Type=Application
Name=VELA (bandeja)
Comment=Icono de bandeja con el estado de la VPN, la IP y las fugas
Exec=env PYTHONPATH={root} {exe} -m vela tray
Icon={root}/vela/data/brand/vela-app-256.png
Terminal=false
X-GNOME-Autostart-enabled=true
"""


def tray_pid_path() -> Path:
    from .util import runtime_dir
    return runtime_dir() / "tray.pid"


def tray_running() -> bool:
    import os
    try:
        pid = int(tray_pid_path().read_text())
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def tray_autostart_path() -> Path:
    return Path.home() / ".config/autostart/vela-tray.desktop"


def tray_autostart_enabled() -> bool:
    return tray_autostart_path().exists()


def tray_enable(start_now: bool = True) -> str:
    import os
    import subprocess
    p = tray_autostart_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[1]
    p.write_text(TRAY_DESKTOP.format(root=root, exe=sys.executable))
    if start_now and not tray_running():
        subprocess.Popen([sys.executable, "-m", "vela", "tray"], env={**os.environ, "PYTHONPATH": str(root)},
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    return str(p)


def tray_disable(stop_now: bool = True) -> bool:
    import os
    import signal
    try:
        tray_autostart_path().unlink()
    except OSError:
        pass
    if stop_now and tray_running():
        try:
            os.kill(int(tray_pid_path().read_text()), signal.SIGTERM)
        except (OSError, ValueError):
            pass
    return True
