"""Traducciones de VELA sin dependencias.

El texto fuente está en español y es la clave de los catálogos `vela/locale/<idioma>.json`
({"texto en español": "traducción"}). Uso:

    from .i18n import _
    _("Túnel caído")                           # texto fijo
    _("Escucha en {addr} ({owner})", addr=a, owner=o)   # con variables (str.format)

Idioma: VELA_LANG > ajuste `ui.language` (Ajustes → Idioma) > LANGUAGE/LC_ALL/LC_MESSAGES/LANG > inglés.
Se decide la primera vez que se traduce algo en cada proceso; `set_language()` lo cambia en caliente
(el daemon lo hace al cambiar el ajuste; la app de escritorio se reinicia).
Si falta una traducción se muestra el texto en español: nunca se rompe nada por un catálogo incompleto.

Comprobar los catálogos: python3 -m vela.i18n check
"""

from __future__ import annotations

import ast
import html
import json
import os
import re
import sys
import threading
from pathlib import Path

LANGS = {"es": "Español", "en": "English", "ca": "Català", "pt": "Português", "fr": "Français", "de": "Deutsch"}
LOCALES = {"es": "es-ES", "en": "en-GB", "ca": "ca-ES", "pt": "pt-PT", "fr": "fr-FR", "de": "de-DE"}
SOURCE = "es"
FALLBACK = "en"
LOCALE_DIR = Path(__file__).resolve().parent / "locale"

_lock = threading.RLock()
_lang: str | None = None
_catalogs: dict[str, dict[str, str]] = {}


def _from_env() -> str | None:
    for var in ("LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"):
        for part in (os.environ.get(var) or "").split(":"):
            code = part.split(".")[0].split("_")[0].split("-")[0].lower()
            if code in LANGS:
                return code
    if os.name == "nt":            # Windows no define LANG: idioma de la cuenta de usuario («es-ES»)
        try:
            import ctypes
            buf = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buf, 85):
                code = buf.value.split("-")[0].lower()
                if code in LANGS:
                    return code
        except (OSError, AttributeError):
            pass
    return None


def settings_file() -> Path:
    """Misma ruta que config.settings_path(), sin importar config (que a su vez usa _())."""
    env = os.environ.get("VELA_SETTINGS") or os.environ.get("OPSEC_SETTINGS")
    if env:
        return Path(env)
    if os.name == "nt":
        return Path(os.environ.get("APPDATA") or os.path.expanduser("~")) / "vela" / "app-settings.toml"
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "vela" / "app-settings.toml"


def _from_settings() -> str | None:
    try:
        import tomllib
        with open(settings_file(), "rb") as f:
            v = str(((tomllib.load(f).get("ui") or {}).get("language")) or "auto").lower()
        return v if v in LANGS else None
    except (OSError, ValueError):     # sin ajustes o ilegibles: idioma del sistema
        return None


def detect() -> str:
    env = (os.environ.get("VELA_LANG") or "").lower()
    if env in LANGS:
        return env
    return _from_settings() or _from_env() or FALLBACK


def language() -> str:
    global _lang
    if _lang is None:
        with _lock:
            if _lang is None:
                _lang = detect()
    return _lang


def set_language(code: str | None) -> str:
    """Fija el idioma del proceso (None o 'auto' = volver a detectarlo)."""
    global _lang
    with _lock:
        _lang = code if code in LANGS else None
    return language()


def catalog(code: str) -> dict[str, str]:
    if code == SOURCE:
        return {}
    cat = _catalogs.get(code)
    if cat is None:
        try:
            cat = json.loads((LOCALE_DIR / f"{code}.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cat = {}
        _catalogs[code] = cat
    return cat


def _(msg: str, **kw) -> str:
    """Traduce `msg` (español) al idioma activo y rellena las variables {nombre}."""
    out = catalog(language()).get(msg) or msg
    if kw:
        try:
            return out.format(**kw)
        except (KeyError, IndexError, ValueError):
            return msg.format(**kw)       # traducción defectuosa: mejor el original que un error
    return out


def N_(msg: str) -> str:
    """Marca un texto para traducir más tarde (constantes); no traduce."""
    return msg


# textos definidos como constantes en otros módulos (se traducen al mostrarlos con _(CONST))
EXTRA = [N_("Tu identidad de red, siempre en vela"),
         # identificadores guardados o comparados en español que se traducen al mostrarlos
         N_("wifi"), N_("lan"), N_("vpn"), N_("bloqueo"), N_("máquinas virtuales"), N_("contenedores"), N_("virtual"),
         N_("bloqueado"), N_("expuesto"), N_("baja"), N_("media"), N_("alta"),
         N_("daemon detenido"), N_("cambio de {what}")]


# ── herramientas de mantenimiento ───────────────────────────────────────────

def placeholders(s: str) -> set[str]:
    return {m.group(1) for m in re.finditer(r"(?<!\{)\{([A-Za-z_]\w*)[^{}]*\}(?!\})", s)}


def extract(root: Path | None = None) -> dict[str, list[str]]:
    """Todos los textos marcados con _() / N_() en el código: {texto: [fichero:línea, …]}."""
    root = root or Path(__file__).resolve().parent
    out: dict[str, list[str]] = {}
    for f in sorted(root.rglob("*.py")):
        try:
            tree = ast.parse(f.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in ("_", "N_")
                    and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                out.setdefault(node.args[0].value, []).append(f"{f.relative_to(root.parent)}:{node.lineno}")
    js = root / "gui" / "static" / "app.js"
    page = root / "gui" / "static" / "index.html"
    for f in (js, page):
        if f.exists():
            text = f.read_text(encoding="utf-8")
            if f.suffix == ".js":
                found = [(m.start(), json.loads(f'"{m.group(1)}"')) for m in re.finditer(r'\btr\(\s*"((?:[^"\\]|\\.)*)"', text)]
            else:                                    # HTML: nodos de texto y atributos title/placeholder/aria-label
                body = text[text.find("<body"):]
                off = len(text) - len(body)
                found = [(off + m.start(1), html.unescape(m.group(1).strip()))
                         for m in re.finditer(r">([^<>]*[A-Za-zÁÉÍÓÚáéíóúñÑ]{2,}[^<>]*)<", body)]
                found += [(m.start(2), html.unescape(m.group(2)))
                          for m in re.finditer(r'\b(title|placeholder|aria-label)="([^"]*[A-Za-zÁÉÍÓÚáéíóúñ]{2,}[^"]*)"', text)
                          if "<title" not in text[max(0, m.start() - 7):m.start()]]
            for pos, s in found:
                if s:
                    out.setdefault(s, []).append(f"{f.relative_to(root.parent)}:{text.count(chr(10), 0, pos) + 1}")
    return out


def check(verbose: bool = True) -> dict:
    """Faltan / sobran / variables distintas en cada catálogo."""
    keys = extract()
    report = {}
    for code in LANGS:
        if code == SOURCE:
            continue
        cat = catalog(code)
        missing = [k for k in keys if k not in cat]
        extra = [k for k in cat if k not in keys]
        bad = [k for k in keys if k in cat and placeholders(k) != placeholders(cat[k])]
        report[code] = {"missing": missing, "extra": extra, "bad_placeholders": bad}
        if verbose:
            print(f"{code}: {len(keys) - len(missing)}/{len(keys)} traducidos · faltan {len(missing)} · "
                  f"sobran {len(extra)} · variables distintas {len(bad)}")
    return report


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "check"
    if cmd == "extract":
        print(json.dumps(sorted(extract()), ensure_ascii=False, indent=1))
    else:
        rep = check()
        sys.exit(1 if any(r["missing"] or r["bad_placeholders"] for r in rep.values()) else 0)
