"""Utilidades comunes: tiempo, duraciones, redacción de secretos, comandos y rutas."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

APP = "vela"


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def fmt_duration(seconds: float | None) -> str:
    """Formato `00d 00h 00m 00s`."""
    s = max(0, int(seconds or 0))
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return f"{d:02d}d {h:02d}h {m:02d}m {s:02d}s"


def fmt_duration_short(seconds: float | None) -> str:
    """Compacto sin perder los días: `1d 19h 50m` o `19h 50m 53s`."""
    full = fmt_duration(seconds)
    return full[:-4] if not full.startswith("00d") else full[4:]


_DUR = re.compile(r"(\d+(?:\.\d+)?)\s*([smhdw]?)")
_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(value) -> float:
    """'45m', '1h30m', '90', 90 -> segundos."""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower().replace(" ", "")
    if not text:
        return 0.0
    total, pos = 0.0, 0
    for m in _DUR.finditer(text):
        if m.start() != pos:
            raise ValueError(f"duración no válida: {value!r}")
        total += float(m.group(1)) * _UNITS[m.group(2)]
        pos = m.end()
    if pos != len(text):
        raise ValueError(f"duración no válida: {value!r}")
    return total


_SECRET_PATTERNS = [
    (re.compile(r"//[^@/\s]+@"), "//***@"),
    (re.compile(r"(?i)\b(password|passwd|pass|token|secret|key|cookie|authorization)\b(\s*[=:]\s*)\S+"), r"\1\2***"),
]


def redact(value):
    """Elimina credenciales de cadenas y estructuras antes de mostrarlas o guardarlas."""
    if isinstance(value, str):
        for pat, repl in _SECRET_PATTERNS:
            value = pat.sub(repl, value)
        return value
    if isinstance(value, dict):
        return {k: ("***" if re.search(r"(?i)pass|secret|token|cookie", str(k)) else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value


# Aplicaciones instaladas como snap/flatpak no siempre están en el PATH del proceso (p. ej. ProtonVPN).
EXTRA_BIN_DIRS = ["/snap/bin", "/var/lib/flatpak/exports/bin",
                  os.path.expanduser("~/.local/share/flatpak/exports/bin"), "/usr/local/bin", "/usr/sbin", "/sbin"]


def which(name: str) -> str | None:
    return shutil.which(name) or shutil.which(name, path=os.pathsep.join(EXTRA_BIN_DIRS))


def run(cmd: list[str], timeout: float = 4, input_text: str | None = None) -> tuple[int, str, str]:
    """Ejecuta un comando sin shell. Devuelve (código, stdout, stderr); código 127 si no existe."""
    exe = which(cmd[0])
    if not exe:
        return 127, "", f"{cmd[0]}: no encontrado"
    cmd = [exe, *cmd[1:]]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=input_text,
                           stdin=None if input_text is not None else subprocess.DEVNULL,
                           env={**os.environ, "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as e:
        return 126, "", str(e)
    return p.returncode, p.stdout, p.stderr


def run_json(cmd: list[str], timeout: float = 4):
    code, out, _ = run(cmd, timeout)
    if code != 0 or not out.strip():
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def fingerprint(obj) -> str:
    """Huella corta y estable de una estructura (para reconocer reutilizaciones)."""
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(data.encode()).hexdigest()[:16]


def xdg_dir(kind: str) -> Path:
    env, default = {
        "config": ("XDG_CONFIG_HOME", "~/.config"),
        "data": ("XDG_DATA_HOME", "~/.local/share"),
        "state": ("XDG_STATE_HOME", "~/.local/state"),
    }[kind]
    base = Path(os.environ.get(env) or os.path.expanduser(default))
    return base / APP


def runtime_dir() -> Path:
    base = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}"
    if not os.path.isdir(base):
        base = str(xdg_dir("state"))
    return Path(base) / APP


def private_dir(path: Path) -> Path:
    """Crea un directorio accesible solo por el usuario y corrige permisos si ya existe."""
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path
