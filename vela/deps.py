"""Dependencias opcionales: detección, plan de instalación y ejecución con privilegios.

VELA funciona sin dependencias externas para observar la red. Las funciones que necesitan
herramientas del sistema (OCR, captura de pantalla, MAC, DNS cifrado, LLM local) comprueban
qué falta y ofrecen instalarlo con el gestor de paquetes de la distribución.

Nada se instala sin una confirmación explícita y siempre se muestra el comando. Para las
acciones que necesitan root se usa `pkexec` (diálogo del escritorio) o `sudo -n`; si ninguno
está disponible se devuelve un error con la orden exacta para ejecutarla a mano.
"""

from __future__ import annotations

from .i18n import _

import os
import subprocess
from pathlib import Path

from .util import run, which

# Cada función declara los comandos que necesita y los paquetes por familia de distribución.
# Las claves de paquetes son: deb (Debian/Ubuntu), rpm (Fedora/RHEL), arch y suse.
FEATURES: dict[str, dict] = {
    "ocr": {
        "title": _("OCR y captura de pantalla"),
        "commands": ["tesseract"],
        "languages": ["spa", "eng"],
        "packages": {
            "deb": ["tesseract-ocr", "tesseract-ocr-spa", "tesseract-ocr-eng", "gnome-screenshot"],
            "rpm": ["tesseract", "tesseract-langpack-spa", "tesseract-langpack-eng", "gnome-screenshot"],
            "arch": ["tesseract", "tesseract-data-spa", "tesseract-data-eng", "gnome-screenshot"],
            "suse": ["tesseract-ocr", "tesseract-ocr-traineddata-spanish", "tesseract-ocr-traineddata-english",
                     "gnome-screenshot"],
        },
    },
    "capture": {
        "title": _("Captura de una región de la pantalla"),
        "commands": [],
        "any_of": ["gnome-screenshot", "grim", "spectacle", "maim", "flameshot"],
        "packages": {
            "deb": ["gnome-screenshot"],
            "rpm": ["gnome-screenshot"],
            "arch": ["gnome-screenshot"],
            "suse": ["gnome-screenshot"],
        },
    },
    "mac": {
        "title": _("Cambiador de MAC"),
        "commands": ["ip"],
        "optional_commands": ["macchanger"],
        "packages": {
            "deb": ["iproute2", "macchanger"],
            "rpm": ["iproute", "macchanger"],
            "arch": ["iproute2", "macchanger"],
            "suse": ["iproute2", "macchanger"],
        },
    },
    "dns": {
        "title": _("DNS cifrado (DoT/DoH)"),
        "commands": ["resolvectl"],
        "packages": {
            "deb": ["systemd-resolved"],
            "rpm": ["systemd-resolved"],
            "arch": ["systemd"],
            "suse": ["systemd"],
        },
    },
    "cloudflared": {
        "title": _("DoH con cloudflared"),
        "commands": ["cloudflared"],
        "packages": {},
        "note": _("cloudflared no suele estar en los repositorios: descárgalo desde cloudflare.com o usa DoT."),
    },
    "llm": {
        "title": _("LLM local para traducir"),
        "commands": [],
        "any_of": ["ollama", "llama-server", "llama-cli"],
        "packages": {},
        "note": _("Ollama se instala con su instalador oficial; llama.cpp, con el paquete de tu distribución o "
                  "compilado. VELA detecta el que ya tengas."),
    },
}

PM = {
    "deb": {"cmd": ["apt-get", "install", "-y"], "query": ["dpkg", "-s"], "id": "deb"},
    "rpm": {"cmd": ["dnf", "install", "-y"], "query": ["rpm", "-q"], "id": "rpm"},
    "arch": {"cmd": ["pacman", "-S", "--needed", "--noconfirm"], "query": ["pacman", "-Q"], "id": "arch"},
    "suse": {"cmd": ["zypper", "install", "-y"], "query": ["rpm", "-q"], "id": "suse"},
}


def family() -> str | None:
    """Familia de distribución a partir del gestor de paquetes disponible."""
    for name, ident in (("apt-get", "deb"), ("dnf", "rpm"), ("pacman", "arch"), ("zypper", "suse")):
        if which(name):
            return ident
    return None


def _has_any(names: list[str] | None) -> bool:
    return bool(names) and any(which(n) for n in names)


def portal_available() -> bool:
    """¿Hay portal XDG para capturar pantalla sin herramientas externas?"""
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        return (Path("/usr/libexec/xdg-desktop-portal").exists()
                or Path("/usr/lib/xdg-desktop-portal").exists()
                or bool(which("xdg-desktop-portal")))
    except (ImportError, ValueError):
        return False


def status(feature: str | None = None) -> dict:
    """Estado de una función o de todas."""
    names = [feature] if feature else list(FEATURES)
    out = {}
    for name in names:
        spec = FEATURES.get(name)
        if not spec:
            raise KeyError(_("función desconocida: {name}", name=name))
        required = [c for c in spec.get("commands") or [] if not which(c)]
        any_of = spec.get("any_of") or []
        optional = [c for c in spec.get("optional_commands") or [] if not which(c)]
        any_ok = _has_any(any_of) or (name == "capture" and portal_available())
        missing_langs: list[str] = []
        if name == "ocr" and not required and spec.get("languages"):
            code, langs_out, _err = run(["tesseract", "--list-langs"], timeout=10)
            have = {x.strip() for x in (langs_out or "").splitlines() if x.strip()}
            missing_langs = [lang for lang in spec["languages"] if lang not in have]
        if name == "llm" and not any_ok:
            try:                                  # servidor local ya en marcha (Ollama/llama.cpp)
                import json
                import urllib.request
                with urllib.request.urlopen("http://127.0.0.1:11434/api/tags", timeout=1) as r:  # noqa: S310
                    any_ok = bool(json.loads(r.read().decode()).get("models"))
                    required = []
            except Exception:  # noqa: BLE001
                pass
        ok = not required and (not any_of or any_ok) and not missing_langs
        out[name] = {
            "title": spec["title"],
            "ok": ok,
            "missing": required + ([] if not any_of or any_ok else any_of) + missing_langs,
            "optional_missing": optional,
            "commands": list(spec.get("commands") or []) + list(any_of),
            "packages": spec["packages"].get(family() or "", []),
            "note": spec.get("note"),
        }
    return out if feature is None else out[feature]


def _install_cmd(packages: list[str]) -> list[str] | None:
    fam = family()
    if not fam or not packages:
        return None
    return [*PM[fam]["cmd"], *packages]


def plan(features: list[str] | str) -> dict:
    """Devuelve el comando de instalación sin ejecutarlo."""
    if isinstance(features, str):
        features = [features]
    missing = []
    for f in features:
        st = status(f)
        if not st["ok"]:
            missing.extend(st["packages"])
    missing = list(dict.fromkeys(missing))
    cmd = _install_cmd(missing)
    return {"features": features, "packages": missing, "command": cmd, "family": family(),
            "can_install": bool(cmd), "pkexec": bool(which("pkexec")), "sudo": bool(which("sudo"))}


def _privileged(cmd: list[str], input_text: str | None = None, timeout: float = 900) -> tuple[int, str, str]:
    """Ejecuta un comando con pkexec (preferido) o sudo -n. Devuelve (código, stdout, stderr)."""
    if os.geteuid() == 0:
        return run(cmd, timeout=timeout, input_text=input_text)
    if which("pkexec"):
        return run(["pkexec", *cmd], timeout=timeout, input_text=input_text)
    if which("sudo"):
        code, out, err = run(["sudo", "-n", *cmd], timeout=timeout, input_text=input_text)
        if code == 0:
            return code, out, err
        return code, out, (err or _("sudo necesita contraseña; ejecuta el comando a mano"))
    return 126, "", _("no hay pkexec ni sudo disponible; ejecuta el comando a mano")


def install(features: list[str] | str, yes: bool = False, runner=_privileged) -> dict:
    """Instala los paquetes que falten. Con `yes=False` solo devuelve el plan."""
    pl = plan(features)
    if not pl["packages"]:
        return {"ok": True, "plan": pl, "detail": _("no falta ningún paquete")}
    if not pl["can_install"]:
        return {"ok": False, "plan": pl, "error": _("no reconozco el gestor de paquetes; instala a mano: {packages}",
                                                    packages=", ".join(pl["packages"]))}
    if not yes:
        return {"ok": False, "plan": pl, "error": _("confirmación requerida")}
    code, out, err = runner(pl["command"])
    ok = code == 0
    return {"ok": ok, "plan": pl, "code": code, "output": (out or "")[-4000:], "error": None if ok else (err or out)[-2000:]}


def install_ollama(yes: bool = False, runner=_privileged) -> dict:
    """Instala Ollama con su instalador oficial y descarga el modelo por defecto.

    Se descarga el script a un fichero temporal y se muestra la URL antes de ejecutarlo. El
    usuario debe confirmar (`yes=True`); nunca se ejecuta en segundo plano sin avisar.
    """
    url = "https://ollama.com/install.sh"
    if not yes:
        return {"ok": False, "error": _("confirmación requerida"), "command": f"curl -fsSL {url} | sh"}
    import tempfile
    import urllib.request
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("wb", prefix="vela-ollama-", suffix=".sh", delete=False) as f:
            tmp = f.name
            with urllib.request.urlopen(url, timeout=30) as r:  # noqa: S310 - URL fija y HTTPS
                f.write(r.read())
        os.chmod(tmp, 0o700)
        code, out, err = runner(["sh", tmp])
        if code != 0:
            return {"ok": False, "code": code, "error": (err or out)[-2000:]}
        model = "qwen2.5:1.5b"
        p = subprocess.run([which("ollama") or "ollama", "pull", model], capture_output=True, text=True,
                           timeout=1800)
        return {"ok": p.returncode == 0, "model": model, "output": (p.stdout or "")[-4000:],
                "error": None if p.returncode == 0 else (p.stderr or p.stdout)[-2000:]}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def missing_for(feature: str) -> list[str]:
    return status(feature)["missing"]


def summary() -> list[dict]:
    """Lista compacta para la interfaz."""
    return [{"key": k, **v} for k, v in status().items()]
