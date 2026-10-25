"""Iconos de la bandeja (ajuste `ui.tray_icon`).

Estilos:
  * "vela"       → el emblema de VELA (Brand Kit) con una insignia de estado en la esquina. La insignia cambia
                   de COLOR y de FORMA (✔ protegido, ▲ exposición media, ✖ alerta, — daemon detenido), así el
                   estado no depende solo del color, igual que en la app.
  * "vela_plain" → solo el emblema; con el daemon detenido se ve atenuado.
  * "status"     → los símbolos genéricos del sistema (escudo), como antes.

Los PNG se generan una vez con cairo en ~/.local/share/vela/tray-icons/ (sin GTK: se puede probar sin escritorio).
"""

from __future__ import annotations

import math
from pathlib import Path

STATES = ("ok", "warn", "alert", "off")
STYLES = ("vela", "vela_plain", "status")
DEFAULT_STYLE = "vela"
SYMBOLIC = {"ok": "security-high-symbolic", "warn": "security-medium-symbolic", "alert": "security-low-symbolic",
            "off": "network-offline-symbolic"}
# colores de estado: los del tema (vela/themes.py, modo oscuro: luminosos, se distinguen sobre paneles oscuros y,
# con el borde marino + blanco, también sobre paneles claros)
BADGE = {"ok": "#4ACB7F", "warn": "#F0CC48", "alert": "#FF5A7A", "off": "#8C9DB2"}
INK = "#061C3A"          # marino de la marca: glifo de la insignia y anillo interior
SIZE = 64
VERSION = 1              # súbelo si cambia el dibujo: los nombres de fichero cambian y el panel no usa una caché vieja

BRAND = Path(__file__).resolve().parent / "data" / "brand"


def icon_dir() -> Path:
    from .util import xdg_dir
    return xdg_dir("data") / "tray-icons"


def _rgb(h: str):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def _emblem(cr, size: int, alpha: float = 1.0):
    import cairo
    src = BRAND / "vela-symbol-128.png"
    img = cairo.ImageSurface.create_from_png(str(src))
    k = size / max(img.get_width(), img.get_height())
    cr.save()
    cr.scale(k, k)
    cr.set_source_surface(img, 0, 0)
    cr.get_source().set_filter(cairo.FILTER_BEST)
    cr.paint_with_alpha(alpha)
    cr.restore()


def _badge(cr, size: int, state: str):
    r = size * 0.22
    cx, cy = size - r - 1, size - r - 1
    for rad, col in ((r + 2.0, "#FFFFFF"), (r + 0.8, INK)):        # anillo blanco + marino: visible en cualquier panel
        cr.set_source_rgb(*_rgb(col))
        cr.arc(cx, cy, rad, 0, 2 * math.pi)
        cr.fill()
    cr.set_source_rgb(*_rgb(BADGE[state]))
    cr.arc(cx, cy, r - 0.6, 0, 2 * math.pi)
    cr.fill()
    cr.set_source_rgb(*_rgb(INK))
    cr.set_line_width(max(2.0, r * 0.32))
    cr.set_line_cap(1)
    cr.set_line_join(1)
    u = r * 0.5
    if state == "ok":                       # ✔
        cr.move_to(cx - u, cy + 0.05 * r)
        cr.line_to(cx - 0.2 * u, cy + 0.75 * u)
        cr.line_to(cx + u, cy - 0.65 * u)
        cr.stroke()
    elif state == "warn":                   # ▲ (con el signo de admiración en hueco)
        cr.move_to(cx, cy - 1.05 * u)
        cr.line_to(cx + 1.05 * u, cy + 0.8 * u)
        cr.line_to(cx - 1.05 * u, cy + 0.8 * u)
        cr.close_path()
        cr.fill()
    elif state == "alert":                  # ✖
        for sx in (1, -1):
            cr.move_to(cx - u, cy - sx * u)
            cr.line_to(cx + u, cy + sx * u)
        cr.stroke()
    else:                                   # — detenido
        cr.move_to(cx - u, cy)
        cr.line_to(cx + u, cy)
        cr.stroke()


def render(state: str, style: str = DEFAULT_STYLE, size: int = SIZE, out_dir: Path | None = None) -> Path:
    """Genera (si falta) el PNG del icono y devuelve su ruta."""
    import cairo
    if state not in STATES:
        raise ValueError(state)
    if style not in ("vela", "vela_plain"):
        raise ValueError(style)
    d = out_dir or icon_dir()
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"vela-tray-{style}-{state}-v{VERSION}-{size}.png"
    if path.exists():
        return path
    surf = cairo.ImageSurface(cairo.FORMAT_ARGB32, size, size)
    cr = cairo.Context(surf)
    cr.set_antialias(cairo.ANTIALIAS_BEST)
    if style == "vela":
        _emblem(cr, size)
        _badge(cr, size, state)
    else:
        _emblem(cr, size, 0.45 if state == "off" else 1.0)
    tmp = path.with_suffix(".tmp")
    surf.write_to_png(str(tmp))
    tmp.replace(path)
    return path


def icon_for(state: str, style: str | None = None) -> str:
    """Nombre de icono (estilo «status») o ruta absoluta del PNG para AppIndicator/notificaciones."""
    style = style if style in STYLES else DEFAULT_STYLE
    if style == "status":
        return SYMBOLIC.get(state, SYMBOLIC["off"])
    try:
        return str(render(state, style))
    except Exception:  # noqa: BLE001  (sin cairo o sin permisos: se vuelve a los símbolos del sistema)
        return SYMBOLIC.get(state, SYMBOLIC["off"])


def current_style() -> str:
    try:
        from .config import ui_pref
        v = ui_pref("tray_icon", DEFAULT_STYLE)
    except Exception:  # noqa: BLE001
        v = DEFAULT_STYLE
    return v if v in STYLES else DEFAULT_STYLE
