"""Estado de las notificaciones de VELA: activas, silenciadas temporalmente o indefinidamente.

El estado se guarda en `$XDG_CONFIG_HOME/vela/notifications.json` (0600) para que lo compartan
la app, la bandeja y el daemon. Un silencio temporal caduca solo; no hace falta un temporizador.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import threading
from pathlib import Path

from .util import now, private_dir, xdg_dir

_LOCK = threading.RLock()
DEFAULT = {"muted_until": 0.0, "indefinite": False}


def path() -> Path:
    return xdg_dir("config") / "notifications.json"


def _read() -> dict:
    try:
        raw = json.loads(path().read_text(encoding="utf-8"))
        return {**DEFAULT, **{k: raw[k] for k in DEFAULT if k in raw}}
    except (OSError, ValueError):
        return dict(DEFAULT)


def _write(value: dict) -> None:
    private_dir(path().parent)
    tmp = path().with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path())


def status() -> dict:
    with _LOCK:
        value = _read()
        t = now()
        indefinite = bool(value.get("indefinite"))
        until = float(value.get("muted_until") or 0)
        if not indefinite and until and until <= t:
            # silencio temporal caducado: limpiar sin avisar
            value = dict(DEFAULT)
            try:
                _write(value)
            except OSError:
                pass
            until = 0
        muted = indefinite or until > t
        return {"enabled": not muted, "muted": muted, "indefinite": indefinite and muted,
                "until": until if until > t and not indefinite else None,
                "remaining": max(0.0, until - t) if until > t and not indefinite else None,
                "path": str(path())}


def allowed() -> bool:
    return status()["enabled"]


def enable() -> dict:
    with _LOCK:
        _write(dict(DEFAULT))
    return status()


def disable() -> dict:
    """Silencio indefinido hasta que se reactive."""
    with _LOCK:
        _write({"muted_until": 0.0, "indefinite": True})
    return status()


def mute(seconds: float | None = None) -> dict:
    """Silencia durante `seconds`; sin valor, indefinidamente."""
    with _LOCK:
        if seconds is None:
            _write({"muted_until": 0.0, "indefinite": True})
        else:
            _write({"muted_until": now() + max(0.0, float(seconds)), "indefinite": False})
    return status()


def describe(st: dict | None = None) -> str:
    st = st or status()
    if st["enabled"]:
        return _("activadas")
    if st["indefinite"]:
        return _("silenciadas indefinidamente")
    rem = int(st.get("remaining") or 0)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if h:
        return _("silenciadas durante {h} h {m} min", h=h, m=m)
    if m:
        return _("silenciadas durante {m} min {s} s", m=m, s=s)
    return _("silenciadas durante {s} s", s=s)
