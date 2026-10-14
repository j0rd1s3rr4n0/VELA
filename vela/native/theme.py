"""Gestor de temas de la app GTK: aplica los tokens de vela/themes.py a GTK 4 + libadwaita.

* Modo claro / oscuro / sistema → Adw.StyleManager (FORCE_LIGHT, FORCE_DARK o DEFAULT, que sigue al
  escritorio); si el escritorio cambia, `notify::dark` vuelve a aplicar los tokens del modo resultante.
* Colores → un ÚNICO Gtk.CssProvider generado a partir de los tokens: los colores con nombre de
  libadwaita (variables CSS en GTK ≥ 4.16, @define-color en versiones anteriores) y las clases propias
  de VELA (.card, .pill-*, .th/.td, .cmd…). Cambiar de tema solo recarga ese proveedor: no se reconstruye
  ninguna ventana ni se toca el daemon.
* Gráficos y mapa (cairo) → la paleta compartida charts.P se actualiza en sitio y se redibuja.
* Movimiento reducido → gtk-enable-animations de este proceso.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from .. import themes  # noqa: E402
from . import charts  # noqa: E402


def gtk_has_css_vars() -> bool:
    return (Gtk.get_major_version(), Gtk.get_minor_version()) >= (4, 16)


def _a(color: str, alpha: float) -> str:
    """alpha() de GTK con un color literal (válido en todas las versiones de GTK 4)."""
    return f"alpha({color}, {alpha})"


def adw_colors(t: dict) -> dict[str, str]:
    """Colores con nombre de libadwaita → tokens de VELA (así los widgets estándar también siguen el tema)."""
    return {
        "accent_bg_color": t["accent"], "accent_fg_color": t["accent_fg"], "accent_color": t["accent_text"],
        "destructive_bg_color": t["destructive"], "destructive_fg_color": t["destructive_fg"],
        "destructive_color": t["destructive_text"],
        "success_bg_color": t["success"], "success_fg_color": t["inverse"], "success_color": t["success"],
        "warning_bg_color": t["warning"], "warning_fg_color": t["inverse"], "warning_color": t["warning"],
        "error_bg_color": t["destructive"], "error_fg_color": t["destructive_fg"], "error_color": t["danger"],
        "window_bg_color": t["bg"], "window_fg_color": t["ink"],
        "view_bg_color": t["surface"], "view_fg_color": t["ink"],
        "headerbar_bg_color": t["header"], "headerbar_fg_color": t["ink"], "headerbar_border_color": t["border"],
        "headerbar_backdrop_color": t["header"], "headerbar_shade_color": _a("#000000", 0.12),
        "sidebar_bg_color": t["sidebar"], "sidebar_fg_color": t["ink"], "sidebar_backdrop_color": t["sidebar"],
        "sidebar_border_color": t["border"], "sidebar_shade_color": _a("#000000", 0.10),
        "secondary_sidebar_bg_color": t["sidebar"], "secondary_sidebar_fg_color": t["ink"],
        "card_bg_color": t["surface"], "card_fg_color": t["ink"], "card_shade_color": _a("#000000", 0.10),
        "dialog_bg_color": t["elevated"], "dialog_fg_color": t["ink"],
        "popover_bg_color": t["overlay"], "popover_fg_color": t["ink"], "popover_shade_color": _a("#000000", 0.20),
        "thumbnail_bg_color": t["elevated"], "thumbnail_fg_color": t["ink"],
        "shade_color": _a("#000000", 0.20), "scrollbar_outline_color": _a(t["bg"], 0.5),
    }


def build_css(t: dict, density: str = "comfortable", css_vars: bool | None = None) -> str:
    css_vars = gtk_has_css_vars() if css_vars is None else css_vars
    d = themes.DENSITY.get(density) or themes.DENSITY["comfortable"]
    pad_v, pad_h = d["card_pad"]
    row = d["row_pad"]
    nav = d["nav_pad"]
    named = adw_colors(t)
    if css_vars:
        head = ":root {\n" + "".join(f"  --{k.replace('_', '-')}: {v};\n" for k, v in named.items()) + "}\n"
    else:
        head = "".join(f"@define-color {k} {v};\n" for k, v in named.items())
    mono = themes.TYPOGRAPHY["monospace"]
    pill_a = themes.PILL_ALPHA
    pills = "".join(
        f".vela .pill-{st} {{ color: {t[tok]}; background-color: {_a(t[tok], pill_a)}; border: 1px solid {_a(t[tok], 0.35)}; }}\n"
        for st, tok in (("good", "success"), ("warning", "warning"), ("serious", "serious"), ("critical", "danger"),
                        ("info", "info")))
    sev = "".join(
        f".vela .callout-{st} {{ border-left: 3px solid {t[tok]}; }}\n.vela .callout-{st} > image {{ color: {t[tok]}; }}\n"
        for st, tok in (("good", "success"), ("warning", "warning"), ("serious", "serious"), ("critical", "danger"),
                        ("neutral", "border_strong"), ("info", "info")))
    nets = "".join(f".vela .hop-{k} {{ border-left-color: {t[tok]}; }}\n" for k, tok in (
        ("vpn", "net_protected"), ("tor", "net_tor"), ("home", "ink2"), ("proxy", "net_proxy"), ("direct", "net_direct")))
    return head + f"""
window.vela, window.vela .content-bg {{ background-color: {t['bg']}; color: {t['ink']}; }}
.vela .sidebar-pane, .vela .sidebar-pane headerbar {{ background-color: {t['sidebar']}; }}
.vela .sidebar-pane {{ border-right: 1px solid {t['border']}; }}
.vela .content-bg headerbar {{ background-color: {t['header']}; box-shadow: inset 0 -1px {t['border']}; }}
.vela .navlist {{ background: transparent; }}
.vela .navlist row {{ border-radius: 8px; margin: 1px 8px; padding: {nav}px 8px; min-height: 0; color: {t['ink2']}; }}
.vela .navlist row:hover {{ background-color: {_a(t['ink'], 0.06)}; color: {t['ink']}; }}
.vela .navlist row:selected {{ background-color: {t['selected']}; color: {t['ink']};
                               box-shadow: inset 3px 0 {t['accent_text']}; }}
.vela .navlist row:selected image {{ color: {t['accent_text']}; }}
.vela .navlist row:focus-visible {{ outline: 2px solid {t['focus']}; outline-offset: -2px; }}
.vela *:focus-visible {{ outline-color: {t['focus']}; }}
.vela .brand {{ font-weight: 800; font-size: 12.5pt; letter-spacing: 0.14em; color: {t['ink']}; }}
.vela .brand-sub {{ font-size: 7.5pt; color: {t['muted']}; letter-spacing: 0.02em; }}
.vela .side-status {{ font-size: 8pt; color: {t['muted']}; border-top: 1px solid {t['separator']}; padding-top: 10px; }}
.vela .card {{ background-color: {t['surface']}; border: 1px solid {t['border']}; border-radius: {themes.SPACING['radius']}px;
               padding: {pad_v}px {pad_h}px; box-shadow: none; color: {t['ink']}; }}
.vela .card-title {{ font-size: 8pt; font-weight: 700; letter-spacing: 0.08em; color: {t['muted']}; }}
.vela .kpi-value {{ font-size: 15pt; font-weight: 700; color: {t['ink']}; font-feature-settings: "tnum"; }}
.vela .kpi-sub {{ font-size: 8.5pt; color: {t['ink2']}; }}
.vela .kpi-hint {{ font-size: 8pt; color: {t['muted']}; }}
.vela .pill {{ font-size: 8pt; font-weight: 700; border-radius: 99px; padding: 1px 8px; }}
{pills}.vela .pill-neutral {{ color: {t['ink2']}; background-color: {_a(t['ink'], 0.07)}; border: 1px solid {t['border']}; }}
.vela .vtable > .th {{ font-size: 8pt; font-weight: 700; color: {t['muted']}; letter-spacing: 0.05em; margin-bottom: 6px; }}
.vela .th {{ font-size: 8pt; font-weight: 700; color: {t['muted']}; letter-spacing: 0.05em; }}
.vela .td {{ font-size: 9pt; color: {t['ink2']}; }}
.vela .td-strong {{ font-size: 9pt; color: {t['ink']}; font-weight: 600; }}
.vela .cell {{ margin-top: {row}px; margin-bottom: {row}px; }}
.vela .mono {{ font-family: {mono}; font-size: 8.5pt; font-feature-settings: "tnum"; }}
.vela .num {{ font-feature-settings: "tnum"; }}
.vela .rowsep {{ background-color: {t['separator']}; min-height: 1px; }}
.vela .hop {{ background-color: {t['elevated']}; border-radius: 8px; padding: 6px 10px;
               border-left: 3px solid {t['accent_text']}; }}
{nets}.vela .legend {{ font-size: 8.5pt; color: {t['ink2']}; }}
.vela .page-title {{ font-size: 13pt; font-weight: 700; color: {t['ink']}; }}
.vela .cmd {{ font-family: {mono}; font-size: 8.5pt; color: {t['ink']}; background-color: {t['inset']};
               border: 1px solid {t['border']}; border-radius: 6px; padding: 5px 9px; }}
.vela .cmd-tag {{ font-size: 7.5pt; font-weight: 700; border-radius: 4px; padding: 0 5px; }}
.vela .cmd-tag-root {{ color: {t['warning']}; border: 1px solid {_a(t['warning'], 0.5)}; }}
.vela .cmd-tag-disruptive {{ color: {t['danger']}; border: 1px solid {_a(t['danger'], 0.5)}; }}
.vela .cmd-tag-read {{ color: {t['ink2']}; border: 1px solid {t['border']}; }}
{sev}.vela .callout {{ background-color: {t['surface']}; }}
.vela .mini {{ min-height: 18px; min-width: 18px; padding: 1px 4px; }}
.vela .badge {{ font-size: 7.5pt; font-weight: 800; color: {t['destructive_fg']}; background-color: {t['destructive']};
                 border-radius: 99px; padding: 0 6px; }}
.vela .empty {{ color: {t['muted']}; font-size: 9pt; padding: 14px 0; }}
.vela .emergency {{ font-weight: 700; }}
.vela button.emergency {{ background-color: {t['destructive']}; color: {t['destructive_fg']}; }}
.vela button.emergency:hover {{ background-color: {themes.mix(t['destructive'], '#000000', 0.12)}; }}
.vela .profile-active {{ border: 1px solid {t['accent_text']}; box-shadow: inset 0 3px {t['accent_text']}; }}
.vela .swatch {{ border-radius: 8px; border: 1px solid {t['border']}; }}
.vela .theme-card {{ padding: 0; }}
.vela .theme-card.selected {{ border: 2px solid {t['focus']}; }}
.vela frame {{ border-color: {t['border']}; border-radius: 8px; }}
.vela tooltip, tooltip.background {{ background-color: {t['tooltip']}; color: {t['tooltip_fg']}; }}
"""


class ThemeManager:
    """Fuente única del tema en la app. `listeners` reciben (tokens, dark) tras cada cambio."""

    def __init__(self, display=None):
        self.display = display or Gdk.Display.get_default()
        self.prefs = themes.load_prefs()
        self.provider = Gtk.CssProvider()
        Gtk.StyleContext.add_provider_for_display(self.display, self.provider,
                                                  Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
        self.sm = Adw.StyleManager.get_default()
        self.sm.connect("notify::dark", lambda *_ign: self._refresh())
        self.listeners: list = []
        self.dark = True
        self.tokens: dict = {}
        self._key = None
        self._anim_default = Gtk.Settings.get_default().get_property("gtk-enable-animations")
        self.apply()

    def apply(self, **changes) -> dict:
        """Cambia y aplica preferencias (theme, appearance, density, motion). Devuelve las preferencias válidas."""
        self.prefs = themes.clean_prefs({**self.prefs, **changes})
        scheme = {"light": Adw.ColorScheme.FORCE_LIGHT, "dark": Adw.ColorScheme.FORCE_DARK}.get(
            self.prefs["appearance"], Adw.ColorScheme.DEFAULT)
        if self.sm.get_color_scheme() != scheme:
            self.sm.set_color_scheme(scheme)        # puede disparar notify::dark → _refresh
        settings = Gtk.Settings.get_default()
        anim = {"reduced": False, "full": True}.get(self.prefs["motion"], self._anim_default)
        if settings.get_property("gtk-enable-animations") != anim:
            settings.set_property("gtk-enable-animations", anim)
        self._refresh()
        return dict(self.prefs)

    def _refresh(self):
        dark = themes.resolve_dark(self.prefs["appearance"], self.sm.get_dark())
        key = f"{self.prefs['theme']}:{'dark' if dark else 'light'}:{self.prefs['density']}"
        if key == self._key:
            return
        self._key = key
        self.dark = dark
        self.tokens = themes.tokens(self.prefs["theme"], dark)
        charts.set_palette(self.tokens, key, dark)
        self.provider.load_from_string(build_css(self.tokens, self.prefs["density"]))
        for fn in list(self.listeners):
            fn(self.tokens, dark)

    @property
    def key(self) -> str:
        return self._key or ""


def redraw_tree(widget):
    """Pide redibujar todas las áreas de dibujo (gráficos, mapa, muestras de leyenda) bajo `widget`,
    también las de páginas no visibles: pintan con la paleta nueva cuando se muestren."""
    stack = [widget]
    while stack:
        w = stack.pop()
        if isinstance(w, Gtk.DrawingArea):
            inv = getattr(w, "theme_changed", None)
            if inv:
                inv()
            w.queue_draw()
        c = w.get_first_child()
        while c is not None:
            stack.append(c)
            c = c.get_next_sibling()
