"""Motor de temas de VELA: design tokens, registro de temas y comprobación de contraste.

Este módulo no depende de GTK: es la ÚNICA fuente de verdad de los colores de la app y lo usan
la GUI GTK (native/theme.py genera su CSS y la paleta de los gráficos), la GUI web (/theme.css)
y las pruebas (que verifican el contraste WCAG de cada combinación relevante).

Un tema = identidad (id, nombre, descripción) + dos juegos de tokens: «light» y «dark».
El modo «system» no es un tercer juego de colores: elige light o dark según el escritorio.

Separación de significados (regla de la marca):
  * brand_*      → identidad visual de VELA (logotipo, detalles de marca). Nunca indica un estado.
  * accent*      → acciones e interacción (botón principal, selección, foco).
  * success/warning/serious/danger/info/neutral → estados y severidades.
  * net_*        → tipos de conexión: protegida (túnel), directa (IP real), proxy, Tor, fuga, desconocida.
Los colores pueden variar por tema para mantener el contraste, pero el SIGNIFICADO de cada token no.
"""

from __future__ import annotations

import math
import os

from .i18n import N_

# ── colores ─────────────────────────────────────────────────────────────────

def hex_rgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def rgb_hex(rgb) -> str:
    return "#" + "".join(f"{max(0, min(255, round(c * 255))):02x}" for c in rgb)


def mix(a: str, b: str, t: float) -> str:
    """Mezcla lineal en sRGB: t = 0 → a, t = 1 → b."""
    ra, rb = hex_rgb(a), hex_rgb(b)
    return rgb_hex(tuple(x + (y - x) * t for x, y in zip(ra, rb)))


def over(fg: str, alpha: float, bg: str) -> str:
    """Color resultante de pintar `fg` con opacidad `alpha` sobre `bg` (para comprobar fondos tintados)."""
    return mix(bg, fg, alpha)


def _lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(h: str) -> float:
    r, g, b = (_lin(c) for c in hex_rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(a: str, b: str) -> float:
    """Relación de contraste WCAG 2.x entre dos colores opacos."""
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def oklab(h: str) -> tuple[float, float, float]:
    r, g, b = (_lin(c) for c in hex_rgb(h))
    l_ = 0.4122214708 * r + 0.5363325363 * g + 0.0514459929 * b
    m_ = 0.2119034982 * r + 0.6806995451 * g + 0.1073969566 * b
    s_ = 0.0883024619 * r + 0.2817188376 * g + 0.6299787005 * b
    l_, m_, s_ = (math.copysign(abs(x) ** (1 / 3), x) for x in (l_, m_, s_))
    return (0.2104542553 * l_ + 0.7936177850 * m_ - 0.0040720468 * s_,
            1.9779984951 * l_ - 2.4285922050 * m_ + 0.4505937099 * s_,
            0.0259040371 * l_ + 0.7827717662 * m_ - 0.8086757660 * s_)


def delta_e(a: str, b: str) -> float:
    """Distancia perceptual OKLab ×100 (≈ ΔE): < 10 cuesta distinguir dos colores de un vistazo."""
    return 100 * math.dist(oklab(a), oklab(b))


# ── tokens ──────────────────────────────────────────────────────────────────

# Todos los tokens que debe tener cada modo de cada tema (agrupados como en la documentación).
TOKEN_GROUPS: dict[str, tuple[str, ...]] = {
    "surfaces": ("bg", "sidebar", "header", "surface", "elevated", "overlay", "selected", "inset"),
    "text": ("ink", "ink2", "muted", "inverse", "link"),
    "borders": ("border", "border_strong", "focus", "separator"),
    "actions": ("accent", "accent_fg", "accent_hover", "accent_text", "destructive", "destructive_fg",
                "destructive_text", "disabled"),
    "semantic": ("success", "warning", "serious", "danger", "info", "neutral"),
    "network": ("net_protected", "net_direct", "net_proxy", "net_tor", "net_leak", "net_unknown"),
    "visualization": ("grid", "axis", "tooltip", "tooltip_fg", "highlight", "series1", "series2", "series3",
                      "series4"),
    "map": ("map_ocean", "map_land", "map_coast", "map_grid", "map_label", "map_label_strong", "map_dot"),
    "brand": ("brand_navy", "brand_blue", "brand_cyan"),
}
TOKENS: tuple[str, ...] = tuple(t for g in TOKEN_GROUPS.values() for t in g)

# Paleta de la marca (extraída del logotipo aprobado del Brand Kit: navy, azul y cian del emblema).
BRAND = {"navy": "#061C3A", "deep": "#073C88", "blue": "#137EE9", "electric": "#168FFF", "cyan": "#00C5E8",
         "ice": "#A4E8F7", "white": "#F8FBFF"}

# Estados y tipos de conexión: mismos significados en todos los temas (solo cambia la luminosidad).
SEMANTIC_DARK = {"success": "#4ACB7F", "warning": "#F0CC48", "serious": "#FF8A45", "danger": "#FF5A7A",
                 "info": "#4CC9EE", "net_proxy": "#7E95FF", "net_tor": "#D88CF0"}
SEMANTIC_LIGHT = {"success": "#116F37", "warning": "#7A6200", "serious": "#B04300", "danger": "#B0124F",
                  "info": "#0A6C8C", "net_proxy": "#2F4FD0", "net_tor": "#8A2FB8"}

TYPOGRAPHY = {
    "font": "Sans",             # la fuente de interfaz del sistema (Cantarell, Inter, Noto Sans…); nada se descarga
    "monospace": "Monospace",   # IPs, puertos, comandos, rutas, hashes e identificadores
    "sizes": {"page_title": 13, "section": 8, "metric": 15, "body": 9, "table": 9, "label": 8, "aux": 8.5},
    "weights": {"regular": 400, "semibold": 600, "bold": 700, "heavy": 800},
}
SPACING = {"unit": 4, "radius": 10, "radius_small": 6, "radius_pill": 99}
DENSITY = {"comfortable": {"card_pad": (12, 14), "row_pad": 5, "gap": 12, "nav_pad": 6},
           "compact": {"card_pad": (8, 10), "row_pad": 3, "gap": 8, "nav_pad": 4}}


def _derive(base: dict, dark: bool) -> dict:
    """Completa los tokens que se deducen de la base de un tema (y que el tema puede sobrescribir)."""
    sem = dict(SEMANTIC_DARK if dark else SEMANTIC_LIGHT)
    ink, bg, surface = base["ink"], base["bg"], base["surface"]
    t = {
        "header": base["sidebar"] if dark else base["bg"],
        "overlay": base["elevated"],
        "selected": mix(surface, base["accent"], 0.20 if dark else 0.12),
        "inset": mix(bg, "#000000", 0.25) if dark else mix(base["sidebar"], bg, 0.5),
        "inverse": bg,
        "link": base["accent_text"],
        "border_strong": mix(base["border"], ink, 0.45 if dark else 0.42),
        "focus": base["accent_text"],
        "separator": mix(surface, ink, 0.10 if dark else 0.10),
        "accent_fg": "#FFFFFF",
        "accent_hover": mix(base["accent"], "#000000", 0.14),
        "destructive": "#C42B2B" if dark else "#B3261E",
        "destructive_fg": "#FFFFFF",
        "destructive_text": sem["danger"],
        "disabled": mix(base["muted"], surface, 0.45),
        "success": sem["success"], "warning": sem["warning"], "serious": sem["serious"],
        "danger": sem["danger"], "info": sem["info"], "neutral": base["muted"],
        "net_protected": sem["success"], "net_direct": sem["serious"], "net_proxy": sem["net_proxy"],
        "net_tor": sem["net_tor"], "net_leak": sem["danger"], "net_unknown": base["muted"],
        "grid": mix(surface, ink, 0.09 if dark else 0.08),
        "axis": mix(surface, ink, 0.20 if dark else 0.22),
        "tooltip": base["elevated"] if dark else "#18263A",
        "tooltip_fg": ink if dark else "#F1F6FD",
        "highlight": base["accent_text"],
        "series1": base["accent_text"], "series2": "#E7A04E" if dark else "#9A5B0C",
        "series3": "#3FC1AE" if dark else "#0D7A6C", "series4": "#C792EA" if dark else "#7A44B8",
        "map_ocean": mix(bg, "#000000", 0.18) if dark else mix(bg, base["accent"], 0.06),
        "map_land": mix(surface, ink, 0.07) if dark else mix(surface, base["border"], 0.85),
        "map_coast": mix(surface, ink, 0.22) if dark else mix(base["border"], ink, 0.30),
        "map_grid": mix(bg, ink, 0.035) if dark else mix(bg, base["border"], 0.45),
        "map_label": base["muted"] if dark else base["ink2"],
        "map_label_strong": base["ink2"] if dark else base["ink"],
        "map_dot": mix(base["muted"], surface, 0.25),
        "brand_navy": BRAND["navy"], "brand_blue": BRAND["blue"], "brand_cyan": BRAND["cyan"],
    }
    t.update(base)
    return t


def _mode(dark: bool, **base) -> dict:
    return _derive(base, dark)


THEMES: dict[str, dict] = {
    "signature": {
        "name": "VELA Signature",
        "description": N_("Tema oficial: azul marino, azul de marca y cian del emblema de VELA."),
        "dark": _mode(True, bg="#0A101B", sidebar="#0D1727", surface="#121E30", elevated="#19283B",
                      border="#293C52", ink="#F1F6FD", ink2="#B6C5D6", muted="#8C9DB2",
                      accent="#1670D4", accent_text="#4DB2FF", brand_cyan="#23C7E8",
                      map_ocean="#08101D", map_land="#1A283B", map_coast="#304760"),
        "light": _mode(False, bg="#F4F7FC", sidebar="#EAF1FA", surface="#FFFFFF", elevated="#FFFFFF",
                       border="#D1DCE9", ink="#10233C", ink2="#455D78", muted="#56708C",
                       accent="#075CB5", accent_text="#075CB5",
                       map_ocean="#E2ECF8", map_land="#CCD9E7", map_coast="#9FB2C8"),
    },
    "obsidian": {
        "name": "VELA Obsidian",
        "description": N_("Para analistas SOC: grafito, acero y azul; máxima legibilidad de tablas."),
        "dark": _mode(True, bg="#0C0D0F", sidebar="#111316", surface="#16181C", elevated="#1D2025",
                      border="#2C3036", ink="#ECEEF1", ink2="#B4B9C1", muted="#8E949D",
                      accent="#3A6EA8", accent_text="#79A9DC", inset="#08090A"),
        "light": _mode(False, bg="#F3F3F1", sidebar="#E8E8E5", surface="#FCFCFB", elevated="#FFFFFF",
                       border="#D2D3D0", ink="#1C1E21", ink2="#44484F", muted="#5C6169",
                       accent="#2F5F93", accent_text="#2F5F93"),
    },
    "glacier": {
        "name": "VELA Glacier",
        "description": N_("Analítico y luminoso: pizarra, azul hielo y grises azulados; pensado para mapas y estadísticas."),
        "dark": _mode(True, bg="#111A26", sidebar="#15202E", surface="#1A2636", elevated="#213044",
                      border="#33465E", ink="#EAF2FB", ink2="#B5C6DA", muted="#90A5BD",
                      accent="#2B78BC", accent_text="#86CBF7", danger="#FF7590", net_leak="#FF7590",
                      destructive_text="#FF7590"),
        "light": _mode(False, bg="#F2F7FB", sidebar="#E5EEF6", surface="#FBFDFF", elevated="#FFFFFF",
                       border="#CADAE7", ink="#13283D", ink2="#3D5670", muted="#526B85",
                       accent="#11619E", accent_text="#11619E"),
    },
    "sentinel": {
        "name": "VELA Sentinel",
        "description": N_("Vigilancia: verde petróleo, carbón y turquesa. El turquesa de la marca no se usa para «protegido»."),
        "dark": _mode(True, bg="#08110F", sidebar="#0C1715", surface="#111E1C", elevated="#172724",
                      border="#26403B", ink="#E8F3F1", ink2="#AAC3BE", muted="#839E99",
                      accent="#0F7A74", accent_text="#3DCBD8",
                      # «protegido» en un verde más amarillo que el turquesa de marca para no confundirlos
                      success="#8FD35A", net_protected="#8FD35A"),
        "light": _mode(False, bg="#F2F7F6", sidebar="#E4EEEC", surface="#FBFDFC", elevated="#FFFFFF",
                       border="#C8DAD6", ink="#0E2A27", ink2="#395752", muted="#4C6B66",
                       accent="#085F73", accent_text="#085F73",
                       success="#2F7000", net_protected="#2F7000"),
    },
    "contrast": {
        "name": "VELA High Contrast",
        "description": N_("Máxima legibilidad: contraste reforzado, bordes y foco muy visibles, pocos tonos intermedios."),
        "dark": _mode(True, bg="#000000", sidebar="#000000", surface="#0B0B0B", elevated="#141414",
                      border="#9A9A9A", border_strong="#FFFFFF", ink="#FFFFFF", ink2="#F0F0F0",
                      muted="#D2D2D2", accent="#0055C4", accent_text="#6EC2FF", focus="#FFD43B",
                      separator="#5A5A5A", selected="#00305E", inset="#000000",
                      success="#5EF08F", warning="#FFD43B", serious="#FFA24C", danger="#FF7A7A",
                      info="#6EE0FF", net_protected="#5EF08F", net_direct="#FFA24C", net_proxy="#9DB6FF",
                      net_tor="#F2A0F0", net_leak="#FF7A7A", net_unknown="#D2D2D2", destructive_text="#FF7A7A",
                      grid="#3A3A3A", axis="#8A8A8A", map_ocean="#000000", map_land="#262626",
                      map_coast="#A0A0A0", map_grid="#141414", map_label="#E6E6E6", map_label_strong="#FFFFFF",
                      map_dot="#BDBDBD", series1="#6EC2FF", series2="#FFC067", series3="#5EE6CF", series4="#E1B4FF",
                      tooltip="#000000", tooltip_fg="#FFFFFF"),
        "light": _mode(False, bg="#FFFFFF", sidebar="#FFFFFF", surface="#FFFFFF", elevated="#FFFFFF",
                       border="#4A4A4A", border_strong="#000000", ink="#000000", ink2="#141414",
                       muted="#383838", accent="#0041A3", accent_text="#0041A3", focus="#B35C00",
                       separator="#8A8A8A", selected="#D5E5FF", inset="#F0F0F0",
                       success="#005A23", warning="#6A4200", serious="#8C3300", danger="#9A0045",
                       info="#00556E", net_protected="#005A23", net_direct="#8C3300", net_proxy="#1B3AA0",
                       net_tor="#5A1A9E", net_leak="#9A0045", net_unknown="#383838", destructive_text="#9A0045",
                       grid="#C8C8C8", axis="#4A4A4A", map_ocean="#FFFFFF", map_land="#D9D9D9",
                       map_coast="#3A3A3A", map_grid="#E8E8E8", map_label="#1E1E1E", map_label_strong="#000000",
                       map_dot="#3A3A3A", series1="#0041A3", series2="#8C4A00", series3="#00675A", series4="#6A2AB0",
                       tooltip="#000000", tooltip_fg="#FFFFFF"),
    },
}

DEFAULT_THEME = "signature"
APPEARANCES = ("system", "light", "dark")
DENSITIES = ("comfortable", "compact")
MOTION = ("system", "reduced", "full")


def ids() -> list[str]:
    return list(THEMES)


def get(theme: str | None) -> dict:
    return THEMES.get(theme or DEFAULT_THEME) or THEMES[DEFAULT_THEME]


def tokens(theme: str | None, dark: bool) -> dict:
    return dict(get(theme)["dark" if dark else "light"])


def resolve_dark(appearance: str, system_dark: bool) -> bool:
    return {"light": False, "dark": True}.get(appearance, bool(system_dark))


# ── preferencias (persisten en el fichero de ajustes de la app, como el idioma) ──

PREF_KEYS = {"ui.theme": tuple(THEMES), "ui.appearance": APPEARANCES, "ui.density": DENSITIES,
             "ui.motion": MOTION}
PREF_DEFAULTS = {"theme": DEFAULT_THEME, "appearance": "system", "density": "comfortable", "motion": "system"}


def clean_prefs(raw: dict | None) -> dict:
    """Normaliza las preferencias: un valor desconocido o corrupto vuelve al predeterminado (nunca rompe la app)."""
    raw = raw or {}
    out = dict(PREF_DEFAULTS)
    for key, allowed in PREF_KEYS.items():
        short = key.split(".", 1)[1]
        v = str(raw.get(short) or "").lower()
        if v in allowed:
            out[short] = v
    return out


def load_prefs() -> dict:
    """Lee las preferencias de aspecto directamente del fichero de ajustes (sin depender del daemon)
    para aplicar el tema ANTES de mostrar la ventana. VELA_THEME / VELA_APPEARANCE las sobrescriben."""
    raw = {}
    try:
        import tomllib
        from .i18n import settings_file
        with open(settings_file(), "rb") as f:
            raw = dict(tomllib.load(f).get("ui") or {})
    except (OSError, ValueError, ImportError):
        pass
    if os.environ.get("VELA_THEME"):
        raw["theme"] = os.environ["VELA_THEME"]
    if os.environ.get("VELA_APPEARANCE"):
        raw["appearance"] = os.environ["VELA_APPEARANCE"]
    return clean_prefs(raw)


# ── contraste: lo que se comprueba (y documenta) para cada tema y modo ──────

TEXT_BGS = ("bg", "sidebar", "header", "surface", "elevated")
PILL_ALPHA = 0.14          # fondo tintado de las píldoras de estado (native/theme.py usa el mismo valor)


def contrast_checks(theme: str, dark: bool) -> list[tuple[str, str, str, float, float]]:
    """Lista de (descripción, color, fondo, mínimo exigido, contraste obtenido)."""
    t = tokens(theme, dark)
    hc = theme == "contrast"
    text_min = 7.0 if hc else 4.5           # el tema de alto contraste apunta a WCAG AAA en el texto
    out = []

    def chk(desc, fg, bg, need):
        out.append((desc, fg, bg, need, contrast(fg, bg)))

    for bgk in TEXT_BGS:
        for fgk in ("ink", "ink2"):
            chk(f"{fgk} / {bgk}", t[fgk], t[bgk], text_min)
        chk(f"muted / {bgk}", t["muted"], t[bgk], 4.5)
        chk(f"accent_text / {bgk}", t["accent_text"], t[bgk], 4.5)
    for k in ("success", "warning", "serious", "danger", "info", "destructive_text"):
        for bgk in ("surface", "bg", "elevated"):
            chk(f"{k} / {bgk}", t[k], t[bgk], 4.5)
        chk(f"{k} / píldora", t[k], over(t[k], PILL_ALPHA, t["surface"]), 4.5)
    chk("ink / selected", t["ink"], t["selected"], text_min)
    chk("accent_fg / accent", t["accent_fg"], t["accent"], 4.5)
    chk("accent_fg / accent_hover", t["accent_fg"], t["accent_hover"], 4.5)
    chk("destructive_fg / destructive", t["destructive_fg"], t["destructive"], 4.5)
    chk("ink / inset", t["ink"], t["inset"], text_min)
    chk("tooltip_fg / tooltip", t["tooltip_fg"], t["tooltip"], text_min)
    chk("focus / surface", t["focus"], t["surface"], 3.0)
    chk("focus / bg", t["focus"], t["bg"], 3.0)
    chk("border_strong / surface", t["border_strong"], t["surface"], 3.0)
    for k in TOKEN_GROUPS["network"]:
        for bgk in ("surface", "map_ocean", "map_land"):
            chk(f"{k} / {bgk}", t[k], t[bgk], 3.0)
    for k in ("series1", "series2", "series3", "series4"):
        chk(f"{k} / surface", t[k], t["surface"], 3.0)
    for k in ("map_label", "map_label_strong"):
        for bgk in ("map_land", "map_ocean"):
            chk(f"{k} / {bgk}", t[k], t[bgk], 4.5)
    return out


def distinct_checks(theme: str, dark: bool, floor: float = 10.0) -> list[tuple[str, str, float]]:
    """Pares de tipos de conexión demasiado parecidos (ΔE OKLab < floor). Siempre van con icono y texto."""
    t = tokens(theme, dark)
    keys = ["net_protected", "net_direct", "net_proxy", "net_tor", "net_leak", "net_unknown"]
    bad = []
    for i, a in enumerate(keys):
        for b in keys[i + 1:]:
            d = delta_e(t[a], t[b])
            if d < floor:
                bad.append((a, b, d))
    return bad


# ── GUI web: los mismos tokens como variables CSS del navegador (vela/gui/static/app.css las usa) ──

WEB_VARS = {"--bg": "bg", "--panel": "surface", "--panel2": "elevated", "--line": "border", "--text": "ink",
            "--muted": "muted", "--accent": "accent_text", "--accent-bg": "accent", "--accent-fg": "accent_fg",
            "--ok": "success", "--warn": "warning", "--bad": "danger", "--crit": "destructive", "--focus": "focus",
            "--land": "map_land", "--sea": "map_ocean", "--grid": "map_grid", "--c-public": "highlight",
            "--c-wan": "ink2", "--c-vpn": "net_protected", "--c-proxy": "net_proxy", "--c-tor": "net_tor",
            "--c-guard": "series4", "--c-home": "ink", "--c-direct": "net_direct", "--c-leak": "net_leak",
            "--c-unknown": "net_unknown"}


def web_css(theme: str | None) -> str:
    """Hoja de estilo con las variables del tema para la GUI web (modo claro y oscuro)."""
    out = [f"/* {get(theme)['name']} · generado por vela/themes.py */"]
    for mode in ("dark", "light"):
        t = tokens(theme, mode == "dark")
        sel = ":root, :root[data-theme=\"dark\"]" if mode == "dark" else ":root[data-theme=\"light\"]"
        out.append(sel + " {\n" + "".join(f"  {k}: {t[v]};\n" for k, v in WEB_VARS.items()) + "}")
    out.append(":focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }")
    return "\n".join(out) + "\n"


def report() -> str:
    lines = []
    for th in THEMES:
        for dark in (False, True):
            res = contrast_checks(th, dark)
            fails = [r for r in res if r[4] < r[3]]
            worst = min(res, key=lambda r: r[4] / r[3])
            lines.append(f"{THEMES[th]['name']:<20} {'dark ' if dark else 'light'}  {len(res) - len(fails)}/{len(res)} OK"
                         f"  · más justo: {worst[0]} {worst[4]:.2f}:1 (mín. {worst[3]})")
            for d, fg, bg, need, got in fails:
                lines.append(f"    FALLA {d}: {fg} sobre {bg} = {got:.2f}:1 (mín. {need})")
            for a, b, d in distinct_checks(th, dark):
                lines.append(f"    PARECIDOS {a} ~ {b}: ΔE {d:.1f}")
    return "\n".join(lines)


if __name__ == "__main__":       # python3 -m vela.themes  → informe de contraste de todos los temas
    print(report())
