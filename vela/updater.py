"""Actualizaciones de VELA desde su repositorio git (`vela update` y Ajustes → Actualizaciones).

Cómo funciona:
  * install.sh deja en la carpeta instalada un INSTALL.json con la carpeta de origen (tu clon del repo),
    la versión y el commit instalados.
  * Buscar = `git fetch` en ese clon. Nunca es automático: solo cuando lo pides. La conexión con el
    servidor git sale por Tor si está disponible (proxy SOCKS de git, el DNS lo resuelve Tor), si no por la
    VPN, y solo directamente si lo eliges (`--via direct`): GitHub vería tu IP real.
  * Actualizar = fusión solo hacia delante (`git merge --ff-only`) y después `install.sh --yes --no-deps`,
    que copia el programa y reinicia el servicio. Si tienes cambios locales sin guardar o tu rama se ha
    separado de la remota, no toca nada y te lo dice.
  * Se muestran los commits nuevos antes de aplicarlos. Los commits no van firmados: la confianza es la
    de tu remoto git (HTTPS a GitHub con tus credenciales), no una firma verificada.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .i18n import _

MANIFEST = "INSTALL.json"
GIT_TIMEOUT = 180


class UpdateError(Exception):
    pass


# ── dónde está instalado y de dónde viene ───────────────────────────────────

def package_root() -> Path:
    """Carpeta que contiene el paquete `vela` en ejecución (el clon o ~/.local/lib/vela)."""
    return Path(__file__).resolve().parents[1]


def read_manifest(root: Path | None = None) -> dict:
    try:
        return json.loads(((root or package_root()) / MANIFEST).read_text())
    except (OSError, ValueError):
        return {}


def source_dir(root: Path | None = None) -> Path | None:
    """Clon del repositorio del que se instaló VELA (o este mismo, si se ejecuta desde el clon)."""
    root = root or package_root()
    if (root / ".git").exists():
        return root
    src = read_manifest(root).get("source")
    if src and (Path(src) / "vela").is_dir():
        return Path(src)
    return None


def _git(src: Path, *args, timeout=GIT_TIMEOUT, extra_env=None, config=()) -> str:
    cmd = ["git"]
    for c in config:
        cmd += ["-c", c]
    cmd += ["-C", str(src), *args]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C", **(extra_env or {})}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        raise UpdateError(_("git no está instalado")) from None
    except subprocess.TimeoutExpired:
        raise UpdateError(_("git tardó demasiado ({s} s)", s=timeout)) from None
    if p.returncode:
        raise UpdateError((p.stderr or p.stdout).strip().splitlines()[-1] if (p.stderr or p.stdout).strip()
                          else _("git terminó con código {c}", c=p.returncode))
    return p.stdout.strip()


def _version_in(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip("\"'")
    return None


def status(root: Path | None = None) -> dict:
    """Qué hay instalado y en qué estado está el clon de origen (sin red)."""
    root = root or package_root()
    man = read_manifest(root)
    out = {"installed_version": man.get("version") or __version__, "installed_commit": man.get("commit"),
           "installed_at": man.get("installed"), "running_from": str(root), "source": None, "git": False}
    src = source_dir(root)
    if src is None:
        out["hint"] = _("Instalado sin un clon git: descarga la versión nueva y ejecuta ./install.sh")
        return out
    out["source"] = str(src)
    if not (src / ".git").exists():
        out["hint"] = _("La carpeta de origen no es un clon git: descarga la versión nueva y ejecuta ./install.sh")
        return out
    out["git"] = True
    try:
        out["branch"] = _git(src, "rev-parse", "--abbrev-ref", "HEAD")
        out["source_commit"] = _git(src, "rev-parse", "HEAD")
        out["source_version"] = _version_in((src / "vela" / "__init__.py").read_text())
        out["dirty"] = bool(_git(src, "status", "--porcelain", "--untracked-files=no"))
        try:
            out["upstream"] = _git(src, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
        except UpdateError:
            out["upstream"] = None
        out["remote_url"] = _git(src, "remote", "get-url", (out["upstream"] or "origin/").split("/")[0] or "origin")
    except (UpdateError, OSError) as e:
        out["error"] = str(e)
        return out
    # el clon ya tiene commits que no se han instalado (p. ej. hiciste git pull a mano)
    out["pending_install"] = bool(out["installed_commit"]) and out["installed_commit"] != out["source_commit"]
    return out


# ── red: por dónde sale la consulta al servidor git ─────────────────────────

def is_local_remote(url: str) -> bool:
    return url.startswith(("/", "file://", "./", "../")) or (os.sep in url and ":" not in url)


def git_proxy_config(url: str, via: str, env: dict | None) -> tuple[str, list[str]]:
    """(ruta, opciones -c de git). Misma política que la descarga del mapa: Tor > VPN > directo solo si se pide."""
    if is_local_remote(url):
        return "local", []
    from .osmmap import choose_route
    if env is None:
        from .discovery import discover
        env = discover()
    route, socks = choose_route(via, env)
    if socks:
        if not url.startswith("https://"):
            raise UpdateError(_("Por Tor solo puedo usar remotos HTTPS (el tuyo es {url}); usa --via vpn o cambia "
                                "el remoto a https://", url=url))
        return route, [f"http.proxy=socks5h://{socks[0]}:{socks[1]}"]
    return route, []


# ── buscar y aplicar ────────────────────────────────────────────────────────

def check(via: str = "auto", env: dict | None = None, root: Path | None = None) -> dict:
    """Trae las novedades del remoto (git fetch) y dice qué cambiaría. No modifica tu copia ni la instalación."""
    st = status(root)
    if not st["git"]:
        raise UpdateError(st.get("hint") or _("no hay clon git de origen"))
    if st.get("error"):
        raise UpdateError(st["error"])
    if not st.get("upstream"):
        raise UpdateError(_("La rama «{b}» no sigue a ninguna rama remota (git branch --set-upstream-to)", b=st["branch"]))
    src = Path(st["source"])
    remote = st["upstream"].split("/")[0]
    route, cfg = git_proxy_config(st["remote_url"], via, env)
    t0 = time.monotonic()
    _git(src, "fetch", "--quiet", remote, config=cfg)
    behind = int(_git(src, "rev-list", "--count", "HEAD..@{u}"))
    ahead = int(_git(src, "rev-list", "--count", "@{u}..HEAD"))
    log = _git(src, "log", "--format=%h%x09%cs%x09%s", "HEAD..@{u}") if behind else ""
    commits = [dict(zip(("id", "date", "subject"), line.split("\t", 2))) for line in log.splitlines() if line]
    try:
        new_version = _version_in(_git(src, "show", "@{u}:vela/__init__.py"))
    except UpdateError:
        new_version = None
    return {**st, "route": route, "seconds": round(time.monotonic() - t0, 1), "behind": behind, "ahead": ahead,
            "commits": commits, "new_version": new_version,
            "can_update": behind > 0 and ahead == 0 and not st["dirty"],
            "available": behind > 0 or st.get("pending_install", False)}


def apply(via: str = "auto", env: dict | None = None, root: Path | None = None, installer=None,
          progress=lambda f, m: None) -> dict:
    """Busca, avanza el clon solo hacia delante y reinstala. `installer(src)` permite sustituir install.sh (pruebas)."""
    progress(0.05, _("buscando novedades"))
    res = check(via, env, root)
    src = Path(res["source"])
    if res["dirty"]:
        raise UpdateError(_("Tienes cambios sin guardar en {src}: guárdalos (git stash) o descártalos antes de actualizar",
                            src=src))
    if res["ahead"]:
        raise UpdateError(_("Tu rama tiene {n} commits que no están en {u}: no actualizo para no perderlos "
                            "(resuélvelo con git)", n=res["ahead"], u=res["upstream"]))
    before = res["source_commit"]
    if res["behind"]:
        progress(0.35, _("aplicando {n} commits", n=res["behind"]))
        _git(src, "merge", "--ff-only", "--quiet", "@{u}")
    elif not res.get("pending_install"):
        return {**res, "updated": False, "message": _("Ya tienes la última versión")}
    after = _git(src, "rev-parse", "HEAD")
    progress(0.6, _("reinstalando"))
    (installer or run_installer)(src)
    progress(1.0, _("listo"))
    return {**res, "updated": True, "from_commit": before, "to_commit": after,
            "rollback": f"git -C {src} reset --keep {before} && {src}/install.sh --yes --no-deps",
            "message": _("VELA actualizado ({a} → {b}). Reabre la app para usar la versión nueva.",
                         a=before[:7], b=after[:7])}


def run_installer(src: Path):
    """Ejecuta el install.sh del clon (copia el programa y reinicia el servicio; sin instalar paquetes)."""
    script = src / "install.sh"
    if not script.exists():
        raise UpdateError(_("No encuentro {p}", p=script))
    p = subprocess.run(["bash", str(script), "--yes", "--no-deps"], capture_output=True, text=True, timeout=600,
                       stdin=subprocess.DEVNULL)
    if p.returncode:
        raise UpdateError(_("install.sh falló: {e}", e=(p.stderr or p.stdout).strip()[-400:]))


def write_manifest(prefix: Path, src: Path) -> dict:
    """Lo llama install.sh: recuerda de dónde y qué versión se instaló."""
    commit = None
    if (src / ".git").exists():
        try:
            commit = _git(src, "rev-parse", "HEAD", timeout=10)
        except UpdateError:
            commit = None
    data = {"source": str(src), "version": _version_in((src / "vela" / "__init__.py").read_text()),
            "commit": commit, "installed": time.strftime("%Y-%m-%dT%H:%M:%S%z")}
    (prefix / MANIFEST).write_text(json.dumps(data, indent=1))
    return data


if __name__ == "__main__":        # python3 -m vela.updater write-manifest PREFIX SRC  (usado por install.sh)
    if len(sys.argv) == 4 and sys.argv[1] == "write-manifest":
        write_manifest(Path(sys.argv[2]), Path(sys.argv[3]))
