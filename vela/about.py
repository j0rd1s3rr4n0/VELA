"""Datos del About: aplicación, créditos y perfil del creador.

Por defecto todo es offline: nombre, enlaces y una ficha estática. El botón «Sincronizar
perfil» consulta la API pública de GitHub y descarga el avatar; solo funciona si el usuario
activa `[consent] about_profile_lookup = true`. La respuesta se guarda en caché 0600 para que
el resto de aperturas no hagan ninguna petición.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import platform
import sys
import urllib.request
from pathlib import Path

from . import __version__, ACRONYM, TAGLINE
from .util import now, private_dir, xdg_dir

PROFILE = {
    "login": "j0rd1s3rr4n0",
    "name": "Jordi Serrano",
    "bio": _("Ethical hacker & Threat Hunter · Configuring Whoami"),
    "location": "Barcelona",
    "blog": "https://jordiserrano.me",
    "github": "https://github.com/j0rd1s3rr4n0",
    "avatar_url": "https://avatars.githubusercontent.com/u/44474715?v=4",
    "public_repos": None,
    "followers": None,
    "following": None,
}
API = "https://api.github.com/users/j0rd1s3rr4n0"
CACHE_DIR = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vela"
CACHE = CACHE_DIR / "about.json"
AVATAR = CACHE_DIR / "avatar.jpg"
# Avatar público incluido en el paquete: el About enseña siempre una foto, incluso sin red.
BUNDLED_AVATAR = Path(__file__).resolve().parent / "data" / "brand" / "creator-256.png"


def _read_cache() -> dict:
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _write_cache(data: dict) -> None:
    private_dir(CACHE.parent)
    tmp = CACHE.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CACHE)


def profile(cfg: dict | None = None, refresh: bool = False) -> dict:
    """Perfil estático + caché. Con refresh y consentimiento consulta GitHub."""
    from . import config as config_mod
    cfg = cfg or config_mod.load()
    cached = _read_cache()
    data = {**PROFILE, **{k: v for k, v in cached.items() if k in PROFILE or k in ("synced", "avatar")}}
    if AVATAR.exists():
        data["avatar"] = str(AVATAR)
    elif BUNDLED_AVATAR.exists():
        data["avatar"] = str(BUNDLED_AVATAR)
    else:
        data["avatar"] = None
    data["synced"] = cached.get("synced")
    if not refresh:
        return data
    if not (cfg.get("consent") or {}).get("about_profile_lookup"):
        data["error"] = _("activa [consent] about_profile_lookup = true para sincronizar el perfil")
        return data
    try:
        req = urllib.request.Request(API, headers={"Accept": "application/vnd.github+json", "User-Agent": "VELA"})
        with urllib.request.urlopen(req, timeout=15) as r:  # noqa: S310 - URL fija HTTPS
            user = json.loads(r.read().decode("utf-8", errors="replace"))
        for key in ("login", "name", "bio", "location", "blog", "html_url", "public_repos", "followers", "following"):
            if key in user and user[key] is not None:
                data["github" if key == "html_url" else key] = user[key]
        avatar_url = user.get("avatar_url") or PROFILE["avatar_url"]
        private_dir(AVATAR.parent)
        req = urllib.request.Request(avatar_url, headers={"User-Agent": "VELA"})
        with urllib.request.urlopen(req, timeout=20) as r:  # noqa: S310
            raw = r.read(2 * 1024 * 1024)
        fd = os.open(AVATAR, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        data["avatar"] = str(AVATAR)
        data["synced"] = now()
        data["error"] = None
        _write_cache({k: data.get(k) for k in (*PROFILE, "synced", "avatar")})
    except Exception as e:  # noqa: BLE001
        data["error"] = str(e)
    return data


def app_info() -> dict:
    gtk = adw = None
    try:
        import gi
        gi.require_version("Gtk", "4.0")
        gi.require_version("Adw", "1")
        from gi.repository import Adw, Gtk
        gtk = f"{Gtk.get_major_version()}.{Gtk.get_minor_version()}.{Gtk.get_micro_version()}"
        adw = f"{Adw.get_major_version()}.{Adw.get_minor_version()}.{Adw.get_micro_version()}"
    except (ImportError, ValueError):
        pass
    return {
        "name": "VELA",
        "version": __version__,
        "acronym": ACRONYM,
        "tagline": TAGLINE,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "gtk": gtk,
        "libadwaita": adw,
        "repo": "https://github.com/j0rd1s3rr4n0/VELA",
        "license": _("Propietaria · todos los derechos reservados; uso con permiso escrito. "
                     "Datos de OpenStreetMap bajo ODbL."),
        "credits": [
            _("Mapa: © colaboradores de OpenStreetMap, ODbL 1.0"),
            _("Temas e identidad visual: Brand Kit de VELA"),
            _("Traducciones: comunidad de VELA"),
            _("Creador y mantenimiento: j0rd1s3rr4n0"),
        ],
    }
