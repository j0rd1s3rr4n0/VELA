"""Gráficos nativos (cairo + Pango) con los colores del tema activo (claro u oscuro).

Reglas aplicadas: marcas finas (líneas de 2px, barras con extremo redondeado de 4px), rejilla
recesiva, el texto siempre en tinta (nunca del color de la serie), estados con icono + texto,
tooltips por marca con zonas de acierto mayores que la marca, separaciones de 2px entre rellenos.
"""

from __future__ import annotations

from ..i18n import _

import math

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
gi.require_version("PangoCairo", "1.0")
from gi.repository import Gtk, Pango, PangoCairo  # noqa: E402

from .. import themes  # noqa: E402


def hexrgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


# Paleta ACTIVA: los tokens del tema en uso (vela/themes.py). native/theme.py la actualiza EN SITIO al
# cambiar de tema o de modo claro/oscuro, y todo se dibuja consultándola en el momento de pintar, así
# que basta con redibujar: nada guarda colores copiados. Los colores se piden por nombre de token.
P: dict[str, str] = dict(themes.tokens(themes.DEFAULT_THEME, True))
P["_key"] = "signature:dark"
P["_dark"] = True
# Estado → (icono, token): el estado nunca depende solo del color.
STATUS = {"good": ("✔", "success"), "warning": ("▲", "warning"), "serious": ("◆", "serious"),
          "critical": ("✖", "danger"), "neutral": ("●", "muted"), "info": ("ℹ", "info")}


def set_palette(tokens: dict, key: str, dark: bool):
    P.clear()
    P.update(tokens)
    P["_key"] = key
    P["_dark"] = dark


def color(c: str) -> str:
    """Nombre de token («net_tor», «ink2»…) o color literal «#rrggbb» → color literal."""
    return c if c.startswith("#") else P.get(c, P["muted"])


def set_rgb(cr, h, a=1.0):
    cr.set_source_rgba(*hexrgb(color(h)), a)


def text(cr, x, y, s, size=9.0, color="ink2", bold=False, align="left", valign="top", tabular=False, mono=False):
    layout = PangoCairo.create_layout(cr)
    family = themes.TYPOGRAPHY["monospace"] if mono else themes.TYPOGRAPHY["font"]
    fd = Pango.FontDescription.from_string(f"{family} {'Bold ' if bold else ''}{size}")
    layout.set_font_description(fd)
    if tabular:
        attrs = Pango.AttrList()
        attrs.insert(Pango.attr_font_features_new("tnum=1"))
        layout.set_attributes(attrs)
    layout.set_text(str(s), -1)
    w, h = layout.get_pixel_size()
    dx = {"left": 0, "center": -w / 2, "right": -w}[align]
    dy = {"top": 0, "middle": -h / 2, "bottom": -h}[valign]
    set_rgb(cr, color)
    cr.move_to(x + dx, y + dy)
    PangoCairo.show_layout(cr, layout)
    return w, h


def measure(cr, s, size=9.0, bold=False):
    layout = PangoCairo.create_layout(cr)
    layout.set_font_description(Pango.FontDescription.from_string(f"{themes.TYPOGRAPHY['font']} {'Bold ' if bold else ''}{size}"))
    layout.set_text(str(s), -1)
    return layout.get_pixel_size()


def rounded_bar(cr, x, y, w, h, r=4, horizontal=True):
    """Barra con el extremo de datos redondeado y el de la base recto (anclada a la línea base)."""
    if w <= 0 or h <= 0:
        return
    r = min(r, (h if horizontal else w) / 2, (w if horizontal else h))
    if horizontal:
        cr.move_to(x, y)
        cr.line_to(x + w - r, y)
        cr.arc(x + w - r, y + r, r, -math.pi / 2, 0)
        cr.line_to(x + w, y + h - r)
        cr.arc(x + w - r, y + h - r, r, 0, math.pi / 2)
        cr.line_to(x, y + h)
    else:
        cr.move_to(x, y + h)
        cr.line_to(x, y + r)
        cr.arc(x + r, y + r, r, math.pi, 1.5 * math.pi)
        cr.line_to(x + w - r, y)
        cr.arc(x + w - r, y + r, r, 1.5 * math.pi, 2 * math.pi)
        cr.line_to(x + w, y + h)
    cr.close_path()
    cr.fill()


class Chart(Gtk.DrawingArea):
    """Base: zonas de acierto para tooltips."""

    def __init__(self, height=160, width=-1):
        super().__init__(hexpand=True)
        self.set_content_height(height)
        if width > 0:
            self.set_content_width(width)
        self.hits: list[tuple[float, float, float, float, str]] = []
        self.mouse = None
        self.set_has_tooltip(True)
        self.connect("query-tooltip", self._tip)
        mc = Gtk.EventControllerMotion()
        mc.connect("motion", self._motion)
        mc.connect("leave", self._leave)
        self.add_controller(mc)
        self.set_draw_func(self._draw)

    def _motion(self, _c, x, y):
        self.mouse = (x, y)
        if self.wants_crosshair:
            self.queue_draw()

    def _leave(self, *_ign):
        self.mouse = None
        if self.wants_crosshair:
            self.queue_draw()

    wants_crosshair = False

    def _tip(self, _w, x, y, _kb, tooltip):
        for x0, y0, x1, y1, t in self.hits:
            if x0 <= x <= x1 and y0 <= y <= y1:
                tooltip.set_text(t)
                return True
        return False

    def _draw(self, _a, cr, w, h):
        self.hits = []
        self.draw(cr, w, h)

    def draw(self, cr, w, h):
        pass


class Gauge(Chart):
    """Medidor de exposición 0–100: arco de 240°, color de estado + etiqueta textual."""

    def __init__(self):
        super().__init__(height=150)
        self.value, self.level, self.status = 0, "—", "neutral"

    def set(self, value, level, status):
        self.value, self.level, self.status = value, level, status
        self.queue_draw()

    def draw(self, cr, w, h):
        cx, cy, r = w / 2, h * 0.58, min(w / 2 - 12, h * 0.52)
        a0, a1 = math.radians(150), math.radians(390)
        cr.set_line_width(10)
        cr.set_line_cap(1)  # ROUND
        set_rgb(cr, "grid")
        cr.arc(cx, cy, r, a0, a1)
        cr.stroke()
        frac = max(0, min(1, self.value / 100))
        if frac > 0:
            set_rgb(cr, STATUS[self.status][1])
            cr.arc(cx, cy, r, a0, a0 + (a1 - a0) * frac)
            cr.stroke()
        text(cr, cx, cy - 4, f"{self.value}", 26, "ink", bold=True, align="center", valign="middle")
        icon, _ign = STATUS[self.status]
        text(cr, cx, cy + 20, _("{icon} exposición {level}", icon=icon, level=_(self.level)), 9, "ink2", align="center", valign="middle")
        text(cr, cx - r * 0.86, cy + r * 0.62, "0", 8, "muted", align="center")
        text(cr, cx + r * 0.86, cy + r * 0.62, "100", 8, "muted", align="center")
        self.hits.append((0, 0, w, h, _("Exposición observable {value}/100 ({level}). Indicador orientativo: no mide anonimato.", value=self.value, level=self.level)))


class Donut(Chart):
    """Anillo de partes de un total; huecos de 2px; total en el centro. La leyenda va fuera (widgets)."""

    def __init__(self, center_caption="conexiones"):
        super().__init__(height=150)
        self.segments: list[tuple[str, float, str]] = []
        self.caption = center_caption

    def set(self, segments):
        self.segments = [s for s in segments if s[1] > 0]
        self.queue_draw()

    def draw(self, cr, w, h):
        cx, cy, r = w / 2, h / 2, min(w, h) / 2 - 6
        thick = 14
        total = sum(v for _ign, v, _ign in self.segments)
        cr.set_line_width(thick)
        if not total:
            set_rgb(cr, "grid")
            cr.arc(cx, cy, r - thick / 2, 0, 2 * math.pi)
            cr.stroke()
        else:
            gap = (2.0 / (r - thick / 2)) if len(self.segments) > 1 else 0
            a = -math.pi / 2
            for name, v, color in self.segments:
                span = 2 * math.pi * v / total
                set_rgb(cr, color)
                cr.arc(cx, cy, r - thick / 2, a + gap / 2, a + span - gap / 2)
                cr.stroke()
                self.hits.append((0, 0, w, h, ""))
                a += span
            self.hits = [(0, 0, w, h, "\n".join(f"{n}: {int(v)} ({100 * v / total:.0f}%)" for n, v, _ign in self.segments))]
        text(cr, cx, cy - 6, f"{int(total)}", 20, "ink", bold=True, align="center", valign="middle")
        text(cr, cx, cy + 14, self.caption, 8, "muted", align="center", valign="middle")


class LineChart(Chart):
    """Series temporales (≤ 4), líneas de 2px, rejilla de 3 líneas finas, cruceta + tooltip al pasar."""
    wants_crosshair = True

    def __init__(self, height=150, fmt=lambda v: f"{v:.0f}"):
        super().__init__(height=height)
        self.series: list[tuple[str, str, list[float]]] = []
        self.fmt = fmt
        self.xlabels = ("", "")

    def set(self, series, xlabels=("", "")):
        self.series = series
        self.xlabels = xlabels
        self.queue_draw()

    def draw(self, cr, w, h):
        left, right, top, bottom = 66, 10, 8, 18
        pw, ph = w - left - right, h - top - bottom
        n = max((len(v) for _ign, _ign, v in self.series), default=0)
        vmax = max((max(v) for _ign, _ign, v in self.series if v), default=0)
        nice = _nice(vmax)
        cr.set_line_width(1)
        for i in range(4):
            y = top + ph * i / 3
            set_rgb(cr, "grid" if i < 3 else "axis")
            cr.move_to(left, y + 0.5)
            cr.line_to(w - right, y + 0.5)
            cr.stroke()
            text(cr, left - 6, y, self.fmt(nice * (3 - i) / 3), 8, "muted", align="right", valign="middle", tabular=True)
        text(cr, left, h - 2, self.xlabels[0], 8, "muted", valign="bottom")
        text(cr, w - right, h - 2, self.xlabels[1], 8, "muted", align="right", valign="bottom")
        if n < 2 or nice <= 0:
            text(cr, left + pw / 2, top + ph / 2, _("recogiendo datos…"), 9, "muted", align="center", valign="middle")
            return
        X = lambda i: left + pw * i / (n - 1)  # noqa: E731
        Y = lambda v: top + ph * (1 - v / nice)  # noqa: E731
        cr.set_line_width(2)
        cr.set_line_join(1)
        for name, color, vals in self.series:
            set_rgb(cr, color)
            off = n - len(vals)
            for i, v in enumerate(vals):
                (cr.move_to if i == 0 else cr.line_to)(X(i + off), Y(v))
            cr.stroke()
        if self.mouse and left <= self.mouse[0] <= w - right:
            i = round((self.mouse[0] - left) / pw * (n - 1))
            set_rgb(cr, "axis")
            cr.set_line_width(1)
            cr.move_to(X(i) + 0.5, top)
            cr.line_to(X(i) + 0.5, top + ph)
            cr.stroke()
            lines = []
            for name, color, vals in self.series:
                off = n - len(vals)
                if 0 <= i - off < len(vals):
                    v = vals[i - off]
                    set_rgb(cr, "surface")
                    cr.arc(X(i), Y(v), 5, 0, 2 * math.pi)
                    cr.fill()
                    set_rgb(cr, color)
                    cr.arc(X(i), Y(v), 3.5, 0, 2 * math.pi)
                    cr.fill()
                    lines.append(f"{name}: {self.fmt(v)}")
            self.hits = [(0, 0, w, h, "\n".join(lines))]


class HBars(Chart):
    """Barras horizontales de una sola serie: etiqueta (tinta), barra, valor (tinta)."""

    def __init__(self, color="series1", row_h=20, label_w=120):
        super().__init__(height=60)
        self.items: list[tuple[str, float, str]] = []
        self.color, self.row_h, self.label_w = color, row_h, label_w

    def set(self, items):
        self.items = items
        self.set_content_height(max(40, len(items) * self.row_h + 4))
        self.queue_draw()

    def draw(self, cr, w, h):
        if not self.items:
            text(cr, 4, 8, _("sin datos"), 9, "muted")
            return
        vmax = max(v for _ign, v, _ign in self.items) or 1
        bar_w = w - self.label_w - 96
        for i, (lab, v, vtxt) in enumerate(self.items):
            y = i * self.row_h + 2
            text(cr, 0, y + self.row_h / 2 - 1, _ellip(lab, 20), 9, "ink2", valign="middle")
            set_rgb(cr, self.color)
            rounded_bar(cr, self.label_w, y + 4, max(2, bar_w * v / vmax), self.row_h - 9)
            text(cr, self.label_w + bar_w * v / vmax + 6, y + self.row_h / 2 - 1, vtxt, 9, "ink",
                 valign="middle", tabular=True)
            self.hits.append((0, y, w, y + self.row_h, f"{lab}: {vtxt}"))


class Columns(Chart):
    """Columnas apiladas por estado a lo largo del tiempo (huecos de 2px entre segmentos)."""

    def __init__(self, height=120):
        super().__init__(height=height)
        self.buckets: list[dict] = []
        self.keys: list[tuple[str, str, str]] = []   # (clave, etiqueta, color)
        self.xlabels = ("", "")

    def set(self, buckets, keys, xlabels=("", "")):
        self.buckets, self.keys, self.xlabels = buckets, keys, xlabels
        self.queue_draw()

    def draw(self, cr, w, h):
        left, right, top, bottom = 30, 6, 6, 16
        pw, ph = w - left - right, h - top - bottom
        n = len(self.buckets)
        totals = [sum(b.get(k, 0) for k, _ign, _ign in self.keys) for b in self.buckets]
        nice = _nice(max(totals, default=0)) or 1
        cr.set_line_width(1)
        for i in range(3):
            y = top + ph * i / 2
            set_rgb(cr, "grid" if i < 2 else "axis")
            cr.move_to(left, y + 0.5)
            cr.line_to(w - right, y + 0.5)
            cr.stroke()
            text(cr, left - 5, y, f"{nice * (2 - i) / 2:.0f}", 8, "muted", align="right", valign="middle", tabular=True)
        text(cr, left, h - 1, self.xlabels[0], 8, "muted", valign="bottom")
        text(cr, w - right, h - 1, self.xlabels[1], 8, "muted", align="right", valign="bottom")
        if not n:
            return
        slot = pw / n
        bw = max(2, slot - 2)
        for i, b in enumerate(self.buckets):
            x = left + i * slot + 1
            y = top + ph
            parts = []
            for k, lab, color in self.keys:
                v = b.get(k, 0)
                if not v:
                    continue
                hh = ph * v / nice
                set_rgb(cr, color)
                is_top = all(not b.get(k2, 0) for k2, _ign, _ign in self.keys[self.keys.index((k, lab, color)) + 1:])
                if is_top:
                    rounded_bar(cr, x, y - hh, bw, hh - (2 if parts else 0), r=3, horizontal=False)
                else:
                    cr.rectangle(x, y - hh, bw, hh - (2 if parts else 0))
                    cr.fill()
                y -= hh
                parts.append(f"{lab}: {v}")
            self.hits.append((x - 1, top, x + slot, top + ph, f"{b.get('label', '')}\n" + ("\n".join(parts) or _("sin eventos"))))


def _nice(v: float) -> float:
    if v <= 0:
        return 0
    exp = 10 ** math.floor(math.log10(v))
    for m in (1, 2, 2.5, 5, 10):
        if v <= m * exp:
            return m * exp
    return 10 * exp


def _ellip(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1] + "…"


class Sankey(Chart):
    """Diagrama de flujo en columnas: nodos (barras) y bandas proporcionales al nº de conexiones.

    Colores por tipo de ruta (tokens net_*): túnel VPN, directo / IP real, proxy y Tor. La columna «Capa
    local» solo dice si el programa usa un proxy: «sin proxy» se pinta neutro porque ahí todavía no se
    sabe si saldrá por el túnel o con tu IP real (eso lo decide la columna siguiente).
    Al pasar el ratón por una banda o un nodo se resalta lo que está conectado y se atenúa el resto."""

    KIND_TOKEN = {"vpn": "net_protected", "direct": "net_direct", "proxy": "net_proxy", "tor": "net_tor",
                  "leak": "net_leak", "app": "axis", "local": "net_unknown"}
    KIND_NOTE = {
        "vpn": _("Sale por el túnel VPN: el destino ve la IP de la VPN."),
        "direct": _("Sale sin túnel: el destino ve tu IP real."),
        "proxy": _("Pasa por un proxy: el destino ve la salida del proxy (y esta sigue la ruta del sistema)."),
        "tor": _("Va por Tor: el destino ve un exit de Tor."),
        "local": _("Sin proxy: la salida la decide la ruta del sistema (columna siguiente)."),
    }
    COL_TITLES = (_("Programa"), _("Capa local"), _("Salida de red"), _("Lo que ve el destino"))

    def __init__(self, height=360):
        super().__init__(height=height)
        self.nodes, self.links = [], []
        self.bands: list[tuple] = []      # (índice de enlace, x0, y0, ta, x1, y1, tb)
        self.boxes: list[tuple] = []      # (id de nodo, x0, y0, x1, y1)
        self.hover = None                 # ("link", i) | ("node", id)

    def set(self, nodes, links, max_apps=12):
        apps = sorted([n for n in nodes if n["col"] == 0], key=lambda n: -n["value"])
        keep = {n["id"] for n in apps[:max_apps]}
        other = sum(n["value"] for n in apps[max_apps:])
        nodes = [n for n in nodes if n["col"] != 0 or n["id"] in keep]
        if other:
            nodes.append({"id": "app:otros", "col": 0, "label": _("otros ({v1})", v1=len(apps) - max_apps), "kind": "app",
                          "value": other})
            merged = {}
            for l in links:
                src = l["source"] if not l["source"].startswith("app:") or l["source"] in keep else "app:otros"
                k = (src, l["target"])
                e = merged.setdefault(k, {**l, "source": src, "value": 0, "details": list(l.get("details", []))})
                e["value"] += l["value"]
            links = list(merged.values())
        self.nodes, self.links = nodes, links
        self.byid = {n["id"]: n for n in nodes}
        self.hover = None
        self.set_content_height(max(260, 40 + 34 * max([sum(1 for n in nodes if n["col"] == c) for c in range(4)] + [1])))
        self.queue_draw()

    # ── tipo visual (presentación; no cambia la clasificación del motor) ──
    def node_kind(self, n):
        return "local" if n["col"] == 1 and n["kind"] == "direct" else n["kind"]

    def link_kind(self, l):
        tgt = self.byid.get(l["target"])
        return "local" if tgt and tgt["col"] == 1 and l["kind"] == "direct" else l["kind"]

    # ── interacción ──
    def _motion(self, _c, x, y):
        self.mouse = (x, y)
        hov = None
        for nid, x0, y0, x1, y1 in self.boxes:
            if x0 - 3 <= x <= x1 + 3 and y0 <= y <= y1:
                hov = ("node", nid)
                break
        if hov is None and self.bands:
            import cairo
            cr = cairo.Context(cairo.ImageSurface(cairo.FORMAT_A8, 1, 1))
            for i, x0, y0, ta, x1, y1, tb in reversed(self.bands):     # las finas se pintan encima
                self._band_path(cr, x0, y0, ta, x1, y1, tb)
                if cr.in_fill(x, y):
                    hov = ("link", i)
                    break
                cr.new_path()
        if hov != self.hover:
            self.hover = hov
            self.queue_draw()

    def _leave(self, *_ign):
        self.mouse = None
        if self.hover is not None:
            self.hover = None
            self.queue_draw()

    def _tip(self, _w, x, y, _kb, tooltip):
        if not self.hover:
            return False
        kind, ref = self.hover
        if kind == "link":
            l = self.links[ref]
            a, b = self.byid.get(l["source"], {}), self.byid.get(l["target"], {})
            lines = [_("{a} → {b}: {n} conexiones", a=a.get("label"), b=b.get("label"), n=l["value"])]
            note = self.KIND_NOTE.get(self.link_kind(l))
            if note:
                lines.append(note)
            if l.get("details"):
                lines += l["details"][:8] + ([_("… y {n} más", n=len(l["details"]) - 8)] if len(l["details"]) > 8 else [])
        else:
            n = self.byid.get(ref, {})
            lines = [_("{label}: {n} conexiones", label=n.get("label"), n=n.get("value"))]
            note = self.KIND_NOTE.get(self.node_kind(n)) if n.get("col", 0) > 0 else None
            if note:
                lines.append(note)
        tooltip.set_text("\n".join(str(x) for x in lines))
        return True

    def _related(self):
        """(enlaces resaltados, nodos resaltados) según lo que hay bajo el cursor; None = nada resaltado."""
        if not self.hover:
            return None
        kind, ref = self.hover
        if kind == "link":
            l = self.links[ref]
            return {ref}, {l["source"], l["target"]}
        ls = {i for i, l in enumerate(self.links) if ref in (l["source"], l["target"])}
        return ls, {ref} | {x for i in ls for x in (self.links[i]["source"], self.links[i]["target"])}

    @staticmethod
    def _band_path(cr, x0, y0, ta, x1, y1, tb):
        mx = (x0 + x1) / 2
        cr.move_to(x0, y0)
        cr.curve_to(mx, y0, mx, y1, x1, y1)
        cr.line_to(x1, y1 + tb)
        cr.curve_to(mx, y1 + tb, mx, y0 + ta, x0, y0 + ta)
        cr.close_path()

    def draw(self, cr, w, h):
        self.bands, self.boxes = [], []
        if not self.nodes:
            text(cr, w / 2, h / 2, _("sin conexiones que mostrar"), 9, "muted", align="center", valign="middle")
            return
        top, bottom, nw = 22, 6, 10
        colx = [8, w * 0.30, w * 0.56, w - 8 - nw]
        for c, t in enumerate(self.COL_TITLES):
            text(cr, colx[c] + (nw if c == 3 else 0), 2, t.upper(), 7.5, "muted", bold=True,
                 align="right" if c == 3 else "left")
        avail = h - top - bottom
        pos = {}
        for c in range(4):
            col = sorted([n for n in self.nodes if n["col"] == c], key=lambda n: -n["value"])
            total = sum(max(n["value"], 1) for n in col) or 1
            gap = 8
            scale = (avail - gap * (len(col) - 1)) / total
            y = top
            for n in col:
                hh = max(4, max(n["value"], 1) * scale)
                pos[n["id"]] = [colx[c], y, hh, 0.0, 0.0]          # x, y, alto, offset salida, offset entrada
                y += hh + gap
        rel = self._related()
        base_a = 0.34 if P.get("_dark", True) else 0.30
        # bandas
        order = sorted(range(len(self.links)), key=lambda i: -self.links[i]["value"])
        for i in order:
            l = self.links[i]
            a, b = pos.get(l["source"]), pos.get(l["target"])
            na, nb = self.byid.get(l["source"]), self.byid.get(l["target"])
            if not a or not b or not na or not nb:
                continue
            ta = a[2] * l["value"] / max(na["value"], 1)
            tb = b[2] * l["value"] / max(nb["value"], 1)
            y0, y1 = a[1] + a[3], b[1] + b[4]
            a[3] += ta
            b[4] += tb
            x0, x1 = a[0] + nw, b[0]
            alpha = base_a if rel is None else (0.66 if i in rel[0] else 0.12)
            set_rgb(cr, self.KIND_TOKEN.get(self.link_kind(l), "muted"), alpha)
            self._band_path(cr, x0, y0, ta, x1, y1, tb)
            cr.fill()
            self.bands.append((i, x0, y0, ta, x1, y1, tb))
        # nodos y etiquetas
        for n in self.nodes:
            x, y, hh = pos[n["id"]][:3]
            on = rel is None or n["id"] in rel[1]
            set_rgb(cr, self.KIND_TOKEN.get(self.node_kind(n), "muted"), 1.0 if on else 0.35)
            cr.rectangle(x, y, nw, hh)
            cr.fill()
            label = f"{n['label']}  ({n['value']})"
            ink = "ink" if on else "muted"
            if n["col"] == 3:
                text(cr, x - 6, y + hh / 2, label, 8.5, ink, align="right", valign="middle", bold=on and rel is not None)
            else:
                text(cr, x + nw + 6, y + hh / 2, label, 8.5, ink, valign="middle", bold=on and rel is not None)
            self.boxes.append((n["id"], x, y, x + nw, y + hh))
