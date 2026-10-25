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


# ── cambio de versión: protección mientras VELA está parado ─────────────────
#
# Actualizar tiene dos partes. La DESCARGA (git fetch + avance del clon) se hace con VELA en marcha. El CAMBIO de
# versión (copiar el programa y reiniciar el servicio) deja VELA parado unos segundos: en ese hueco no vigila ni
# puede activar el kill-switch automático ante una fuga. Por eso el usuario elige:
#   * "killswitch": se aplica el kill-switch de VELA (solo túneles, Tor y LAN) ANTES de parar la versión vieja y se
#     retira cuando la nueva responde. Si ya estaba aplicado, se deja como estaba. Si la nueva no arranca, sigue
#     puesto (lo pidió el usuario): se avisa de cómo quitarlo.
#   * "restart": se cierra y se vuelve a abrir sin protección (posible fuga de IP durante unos segundos).
PROTECT = ("killswitch", "restart")
START_TIMEOUT = 45


class UpdateGuard:
    """Kill-switch temporal mientras se cambia de versión."""

    def __init__(self, cfg: dict | None = None, once: bool = True):
        """once=True: elegir «actualizar con kill-switch» ES el consentimiento explícito, solo para este cambio de
        versión (no activa consent.allow_killswitch de forma permanente). Siguen haciendo falta nft y privilegios."""
        import copy
        from . import config, killswitch, network
        self.cfg = copy.deepcopy(cfg or config.load())
        if once:
            self.cfg.setdefault("consent", {})["allow_killswitch"] = True
        self.ks = killswitch.KillSwitch(self.cfg, tunnels_fn=lambda: network.snapshot().get("tunnels", []))
        self.was_active = bool(self.ks.state["active"])
        self.engaged = False

    def available(self) -> tuple[bool, str]:
        return self.ks.can_apply()

    def engage(self):
        if self.was_active:
            return                                   # ya protegido: no se toca
        ok, why = self.ks.can_apply()
        if not ok:
            raise UpdateError(_("No se puede aplicar el kill-switch: {why}. No se ha instalado nada; puedes elegir "
                                "«cerrar y reabrir».", why=why))
        res = self.ks.engage(reason="update")
        if not res.get("ok"):
            raise UpdateError(_("No se pudo aplicar el kill-switch ({e}). No se ha instalado nada.", e=res.get("error")))
        self.engaged = True

    def release(self) -> dict:
        if not self.engaged:
            return {"ok": True}
        res = self.ks.release(force=True)
        if res.get("ok"):
            self.engaged = False
        return res


def protection_options() -> dict:
    """Qué opciones de protección se pueden ofrecer ahora (para el diálogo de la app y la CLI)."""
    try:
        guard = UpdateGuard()
        ok, why = guard.available()
        return {"killswitch": ok or guard.was_active, "killswitch_reason": None if ok else why,
                "killswitch_already": guard.was_active}
    except Exception as e:  # noqa: BLE001
        return {"killswitch": False, "killswitch_reason": str(e), "killswitch_already": False}


def wait_daemon(timeout: float = START_TIMEOUT) -> bool:
    """¿Responde el daemon (la versión recién instalada)?"""
    from .ipc import ping
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        if ping():
            return True
        time.sleep(1)
    return False


def daemon_running() -> bool:
    try:
        from .ipc import ping
        return ping()
    except Exception:  # noqa: BLE001
        return False


def swap(src: Path, protect: str = "restart", installer=None, progress=lambda f, m: None, guard=None,
         expect_daemon: bool | None = None) -> dict:
    """Cambia a la versión ya descargada en `src`. `protect`: "killswitch" o "restart" (ver PROTECT)."""
    if protect not in PROTECT:
        raise UpdateError(_("protección desconocida: {p}", p=protect))
    expect_daemon = daemon_running() if expect_daemon is None else expect_daemon
    if protect == "killswitch":
        guard = guard or UpdateGuard()
        progress(0.62, _("aplicando el kill-switch durante el cambio de versión"))
        guard.engage()                               # si falla, se aborta ANTES de tocar la instalación
    out = {"protect": protect, "killswitch_left_on": False, "daemon_started": None}
    try:
        progress(0.7, _("instalando la versión nueva"))
        (installer or run_installer)(src)
    except Exception:
        if guard:                                    # la versión vieja sigue instalada: se quita lo que pusimos
            guard.release()
        raise
    if expect_daemon:
        progress(0.85, _("esperando a que arranque la versión nueva"))
        out["daemon_started"] = wait_daemon()
    if guard:
        if out["daemon_started"] is not False:
            rel = guard.release()
            out["killswitch_released"] = rel.get("ok")
            out["killswitch_left_on"] = not rel.get("ok")
        else:
            out["killswitch_left_on"] = guard.engaged
    return out


def apply(via: str = "auto", env: dict | None = None, root: Path | None = None, installer=None,
          progress=lambda f, m: None, protect: str = "restart", guard=None, expect_daemon: bool | None = None) -> dict:
    """Descarga (con VELA en marcha), avanza el clon solo hacia delante y cambia de versión con la protección
    elegida. `installer(src)` y `guard` permiten sustituir install.sh y el kill-switch en las pruebas."""
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
    sw = swap(src, protect, installer, progress, guard, expect_daemon)
    progress(1.0, _("listo"))
    msg = _("VELA actualizado ({a} → {b}). Reabre la app para usar la versión nueva.", a=before[:7], b=after[:7])
    if sw["killswitch_left_on"]:
        msg += " " + _("El kill-switch SIGUE ACTIVO porque la versión nueva no respondió: revisa «vela doctor» y "
                       "quítalo con «vela killswitch release» cuando quieras.")
    return {**res, **sw, "updated": True, "from_commit": before, "to_commit": after,
            "rollback": f"git -C {src} reset --keep {before} && {src}/install.sh --yes --no-deps",
            "message": msg}


def run_installer(src: Path):
    """Ejecuta el install.sh del clon (copia el programa y reinicia el servicio; sin instalar paquetes)."""
    script = src / "install.sh"
    if not script.exists():
        raise UpdateError(_("No encuentro {p}", p=script))
    # VELA_UPDATE_PROTECT=handled: la protección (kill-switch o no) ya la gestiona swap(); install.sh no pregunta
    p = subprocess.run(["bash", str(script), "--yes", "--no-deps"], capture_output=True, text=True, timeout=600,
                       stdin=subprocess.DEVNULL, env={**os.environ, "VELA_UPDATE_PROTECT": "handled"})
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


# ── usado por install.sh al instalar encima de una versión existente ─────────

GUARD_MARK = "update-guard.json"


def _guard_mark() -> Path:
    from .util import private_dir, xdg_dir
    return private_dir(xdg_dir("state")) / GUARD_MARK


def guard_engage_cli() -> int:
    """install.sh: aplica el kill-switch antes de parar la versión vieja y recuerda que lo puso él."""
    try:
        g = UpdateGuard()
        g.engage()
    except UpdateError as e:
        print(str(e), file=sys.stderr)
        return 1
    # si el daemon no estaba en marcha no hay que esperar a que «arranque la versión nueva»
    _guard_mark().write_text(json.dumps({"engaged": g.engaged, "daemon": daemon_running(), "ts": time.time()}))
    print(_("kill-switch aplicado mientras se cambia de versión") if g.engaged else
          _("el kill-switch ya estaba activo: se deja como está"))
    return 0


def guard_release_cli(timeout: float = START_TIMEOUT) -> int:
    """install.sh: espera a que responda la versión nueva y retira el kill-switch solo si lo puso guard-engage."""
    mark = _guard_mark()
    try:
        info = json.loads(mark.read_text())
    except (OSError, ValueError):
        info = {}
    if not info.get("engaged"):
        mark.unlink(missing_ok=True)
        return 0
    if info.get("daemon", True) and not wait_daemon(timeout):
        print(_("La versión nueva no responde: el kill-switch SIGUE ACTIVO. Revisa «vela doctor» y quítalo con "
                "«vela killswitch release»."), file=sys.stderr)
        return 2
    from . import config, killswitch
    res = killswitch.KillSwitch(config.load()).release(force=True)
    mark.unlink(missing_ok=True)
    if not res.get("ok"):
        print(_("No se pudo retirar el kill-switch: {e}", e=res.get("error")), file=sys.stderr)
        return 1
    print(_("versión nueva en marcha: kill-switch retirado"))
    return 0


if __name__ == "__main__":        # comandos internos de install.sh
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "write-manifest" and len(sys.argv) == 4:
        write_manifest(Path(sys.argv[2]), Path(sys.argv[3]))
    elif cmd == "guard-engage":
        sys.exit(guard_engage_cli())
    elif cmd == "guard-release":
        sys.exit(guard_release_cli())
    elif cmd == "protection-options":
        print(json.dumps(protection_options()))
