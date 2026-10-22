"""Registros persistentes de VELA: auditoría y errores.

- `audit.log`: una línea JSON por acción del usuario o del daemon (`Store.audit`).
- `errors.log`: excepciones no controladas y errores capturados por la UI/CLI.

Ambos viven en `$XDG_STATE_HOME/vela/` (por defecto `~/.local/state/vela/`), con permisos
0600 y rotación local (2 MB × 3 ficheros). No salen de la máquina.
"""

from __future__ import annotations

from .i18n import _

import json
import logging
import os
import sys
import threading
import traceback
from pathlib import Path

from .util import now, private_dir, tilde, xdg_dir

MAX_BYTES = 2 * 1024 * 1024
BACKUPS = 3
_installed = False
_lock = threading.RLock()


def state_dir() -> Path:
    return xdg_dir("state")


def audit_path() -> Path:
    return state_dir() / "audit.log"


def errors_path() -> Path:
    return state_dir() / "errors.log"


def paths() -> dict:
    return {"state": tilde(state_dir()), "audit": tilde(audit_path()), "errors": tilde(errors_path())}


def _rotate(path: Path) -> None:
    try:
        if not path.exists() or path.stat().st_size <= MAX_BYTES:
            return
        for i in range(BACKUPS, 0, -1):
            src = path if i == 1 else Path(f"{path}.{i - 1}")
            dst = Path(f"{path}.{i}")
            if src.exists():
                os.replace(src, dst)
    except OSError:
        pass


def _append(path: Path, record: dict) -> None:
    try:
        private_dir(path.parent)
        with _lock:
            _rotate(path)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    except OSError:
        pass


def _clean(value):
    """No guarda el home real del usuario en los logs (rutas, tracebacks…)."""
    home = str(Path.home())
    if isinstance(value, str):
        return value.replace(home, "~")
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_clean(v) for v in value]
    return value


def audit(actor: str, action: str, detail=None) -> None:
    _append(audit_path(), _clean({"ts": now(), "actor": actor, "action": action, "detail": detail}))


def error(message: str, exc: BaseException | None = None, context: dict | None = None) -> None:
    rec = {"ts": now(), "level": "error", "message": _clean(str(message))}
    if exc is not None:
        rec["type"] = type(exc).__name__
        rec["exception"] = _clean(str(exc))
        rec["traceback"] = _clean("".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-12000:])
    if context:
        rec["context"] = _clean(context)
    _append(errors_path(), rec)


def read(kind: str = "all", limit: int = 200) -> dict:
    """Devuelve las entradas más recientes (primero las nuevas)."""
    limit = max(1, min(int(limit), 2000))

    def load(path: Path) -> list[dict]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        out = []
        for line in lines[-limit:]:
            try:
                item = json.loads(line)
                out.append(item if isinstance(item, dict) else {"message": str(item)})
            except ValueError:
                out.append({"ts": 0, "message": line})
        return list(reversed(out))

    if kind == "audit":
        return {"audit": load(audit_path()), "paths": paths()}
    if kind == "errors":
        return {"errors": load(errors_path()), "paths": paths()}
    return {"audit": load(audit_path()), "errors": load(errors_path()), "paths": paths()}


def clear(kind: str = "all") -> dict:
    removed = []
    targets = {"audit": [audit_path()], "errors": [errors_path()],
               "all": [audit_path(), errors_path()]}.get(kind)
    if targets is None:
        raise ValueError(_("tipo de registro no válido: {kind}", kind=kind))
    for path in targets:
        try:
            path.unlink(missing_ok=True)
            for i in range(1, BACKUPS + 1):
                Path(f"{path}.{i}").unlink(missing_ok=True)
            removed.append(tilde(path))
        except OSError:
            pass
    return {"ok": True, "cleared": removed, "paths": paths()}


def setup() -> None:
    """Engancha excepciones no controladas y el logger de VELA al fichero de errores."""
    global _installed
    if _installed:
        return
    _installed = True

    def hook(exc_type, exc, tb):
        try:
            _append(errors_path(), _clean({
                "ts": now(), "level": "critical", "message": _("excepción no controlada"),
                "type": exc_type.__name__, "exception": str(exc),
                "traceback": "".join(traceback.format_exception(exc_type, exc, tb))[-12000:]}))
        finally:
            if sys.stderr is not None:
                sys.__excepthook__(exc_type, exc, tb)

    sys.excepthook = hook

    def thread_hook(args):
        hook(args.exc_type, args.exc_value, args.exc_traceback)

    threading.excepthook = thread_hook

    try:
        logger = logging.getLogger("vela")
        if not any(isinstance(h, logging.FileHandler) and
                   getattr(h, "baseFilename", "") == str(errors_path()) for h in logger.handlers):
            private_dir(errors_path().parent)
            handler = logging.FileHandler(errors_path(), encoding="utf-8", delay=True)
            handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
    except OSError:
        pass
