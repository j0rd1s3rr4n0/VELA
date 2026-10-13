"""Gráficos nativos (cairo + Pango) con la paleta de referencia validada (modo oscuro).

Reglas aplicadas: marcas finas (líneas de 2px, barras con extremo redondeado de 4px), rejilla
recesiva, el texto siempre en tinta (nunca del color de la serie), estados con icono + texto,
tooltips por marca con zonas de acierto mayores que la marca, separaciones de 2px entre rellenos.
"""

from __future__ import annotations

import math

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Pango", "1.0")
gi.require_version("PangoCairo", "1.0")
from gi.repository import Gtk, Pango, PangoCairo  # noqa: E402


def hexrgb(h: str) -> tuple[float, float, float]:
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


# Paleta de referencia (oscura) — validada con validate_palette.js
P = {
    "page": "#0f1012", "surface": "#1a1a19", "surface2": "#202020", "grid": "#2c2c2a", "axis": "#383835",
    "ink": "#ffffff", "ink2": "#c3c2b7", "muted": "#898781",
    "s1": "#3987e5", "s2": "#d95926", "s3": "#199e70", "s4": "#c98500",
    "good": "#0ca30c", "warning": "#fab219", "serious": "#ec835a", "critical": "#d03b3b",
}
STATUS = {"good": ("✔", P["good"]), "warning": ("▲", P["warning"]), "serious": ("◆", P["serious"]),
          "critical": ("✖", P["critical"]), "neutral": ("●", P["muted"])}


def set_rgb(cr, h, a=1.0):
    cr.set_source_rgba(*hexrgb(h), a)


def text(cr, x, y, s, size=9.0, color=P["ink2"], bold=False, align="left", valign="top", tabular=False):
    layout = PangoCairo.create_layout(cr)
    fd = Pango.FontDescription.from_string(f"Sans {'Bold ' if bold else ''}{size}")
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
    layout.set_font_description(Pango.FontDescription.from_string(f"Sans {'Bold ' if bold else ''}{size}"))
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

    def _leave(self, *_):
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
        set_rgb(cr, P["grid"])
        cr.arc(cx, cy, r, a0, a1)
        cr.stroke()
        frac = max(0, min(1, self.value / 100))
        if frac > 0:
            set_rgb(cr, STATUS[self.status][1])
            cr.arc(cx, cy, r, a0, a0 + (a1 - a0) * frac)
            cr.stroke()
        text(cr, cx, cy - 4, f"{self.value}", 26, P["ink"], bold=True, align="center", valign="middle")
        icon, _ = STATUS[self.status]
        text(cr, cx, cy + 20, f"{icon} exposición {self.level}", 9, P["ink2"], align="center", valign="middle")
        text(cr, cx - r * 0.86, cy + r * 0.62, "0", 8, P["muted"], align="center")
        text(cr, cx + r * 0.86, cy + r * 0.62, "100", 8, P["muted"], align="center")
        self.hits.append((0, 0, w, h, f"Exposición observable {self.value}/100 ({self.level}). Indicador orientativo: "
                                       "no mide anonimato."))


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
        total = sum(v for _, v, _ in self.segments)
        cr.set_line_width(thick)
        if not total:
            set_rgb(cr, P["grid"])
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
            self.hits = [(0, 0, w, h, "\n".join(f"{n}: {int(v)} ({100 * v / total:.0f}%)" for n, v, _ in self.segments))]
        text(cr, cx, cy - 6, f"{int(total)}", 20, P["ink"], bold=True, align="center", valign="middle")
        text(cr, cx, cy + 14, self.caption, 8, P["muted"], align="center", valign="middle")


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
        n = max((len(v) for _, _, v in self.series), default=0)
        vmax = max((max(v) for _, _, v in self.series if v), default=0)
        nice = _nice(vmax)
        cr.set_line_width(1)
        for i in range(4):
            y = top + ph * i / 3
            set_rgb(cr, P["grid"] if i < 3 else P["axis"])
            cr.move_to(left, y + 0.5)
            cr.line_to(w - right, y + 0.5)
            cr.stroke()
            text(cr, left - 6, y, self.fmt(nice * (3 - i) / 3), 8, P["muted"], align="right", valign="middle", tabular=True)
        text(cr, left, h - 2, self.xlabels[0], 8, P["muted"], valign="bottom")
        text(cr, w - right, h - 2, self.xlabels[1], 8, P["muted"], align="right", valign="bottom")
        if n < 2 or nice <= 0:
            text(cr, left + pw / 2, top + ph / 2, "recogiendo datos…", 9, P["muted"], align="center", valign="middle")
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
            set_rgb(cr, P["axis"])
            cr.set_line_width(1)
            cr.move_to(X(i) + 0.5, top)
            cr.line_to(X(i) + 0.5, top + ph)
            cr.stroke()
            lines = []
            for name, color, vals in self.series:
                off = n - len(vals)
                if 0 <= i - off < len(vals):
                    v = vals[i - off]
                    set_rgb(cr, P["surface"])
                    cr.arc(X(i), Y(v), 5, 0, 2 * math.pi)
                    cr.fill()
                    set_rgb(cr, color)
                    cr.arc(X(i), Y(v), 3.5, 0, 2 * math.pi)
                    cr.fill()
                    lines.append(f"{name}: {self.fmt(v)}")
            self.hits = [(0, 0, w, h, "\n".join(lines))]


class HBars(Chart):
    """Barras horizontales de una sola serie: etiqueta (tinta), barra, valor (tinta)."""

    def __init__(self, color=P["s1"], row_h=20, label_w=120):
        super().__init__(height=60)
        self.items: list[tuple[str, float, str]] = []
        self.color, self.row_h, self.label_w = color, row_h, label_w

    def set(self, items):
        self.items = items
        self.set_content_height(max(40, len(items) * self.row_h + 4))
        self.queue_draw()

    def draw(self, cr, w, h):
        if not self.items:
            text(cr, 4, 8, "sin datos", 9, P["muted"])
            return
        vmax = max(v for _, v, _ in self.items) or 1
        bar_w = w - self.label_w - 96
        for i, (lab, v, vtxt) in enumerate(self.items):
            y = i * self.row_h + 2
            text(cr, 0, y + self.row_h / 2 - 1, _ellip(lab, 20), 9, P["ink2"], valign="middle")
            set_rgb(cr, self.color)
            rounded_bar(cr, self.label_w, y + 4, max(2, bar_w * v / vmax), self.row_h - 9)
            text(cr, self.label_w + bar_w * v / vmax + 6, y + self.row_h / 2 - 1, vtxt, 9, P["ink"],
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
        totals = [sum(b.get(k, 0) for k, _, _ in self.keys) for b in self.buckets]
        nice = _nice(max(totals, default=0)) or 1
        cr.set_line_width(1)
        for i in range(3):
            y = top + ph * i / 2
            set_rgb(cr, P["grid"] if i < 2 else P["axis"])
            cr.move_to(left, y + 0.5)
            cr.line_to(w - right, y + 0.5)
            cr.stroke()
            text(cr, left - 5, y, f"{nice * (2 - i) / 2:.0f}", 8, P["muted"], align="right", valign="middle", tabular=True)
        text(cr, left, h - 1, self.xlabels[0], 8, P["muted"], valign="bottom")
        text(cr, w - right, h - 1, self.xlabels[1], 8, P["muted"], align="right", valign="bottom")
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
                is_top = all(not b.get(k2, 0) for k2, _, _ in self.keys[self.keys.index((k, lab, color)) + 1:])
                if is_top:
                    rounded_bar(cr, x, y - hh, bw, hh - (2 if parts else 0), r=3, horizontal=False)
                else:
                    cr.rectangle(x, y - hh, bw, hh - (2 if parts else 0))
                    cr.fill()
                y -= hh
                parts.append(f"{lab}: {v}")
            self.hits.append((x - 1, top, x + slot, top + ph, f"{b.get('label', '')}\n" + ("\n".join(parts) or "sin eventos")))


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
    Colores por tipo de ruta: túnel VPN (verde), directo/IP real (naranja), proxy (azul), Tor (violeta)."""

    KIND_COLOR = {"vpn": P["good"], "direct": P["serious"], "proxy": P["s1"], "tor": "#9085e9", "app": P["muted"]}
    COL_TITLES = ("Programa", "Capa local", "Salida de red", "Lo que ve el destino")

    def __init__(self, height=360):
        super().__init__(height=height)
        self.nodes, self.links = [], []

    def set(self, nodes, links, max_apps=12):
        apps = sorted([n for n in nodes if n["col"] == 0], key=lambda n: -n["value"])
        keep = {n["id"] for n in apps[:max_apps]}
        other = sum(n["value"] for n in apps[max_apps:])
        nodes = [n for n in nodes if n["col"] != 0 or n["id"] in keep]
        if other:
            nodes.append({"id": "app:otros", "col": 0, "label": f"otros ({len(apps) - max_apps})", "kind": "app",
                          "value": other})
            merged = {}
            for l in links:
                src = l["source"] if not l["source"].startswith("app:") or l["source"] in keep else "app:otros"
                k = (src, l["target"])
                e = merged.setdefault(k, {**l, "source": src, "value": 0, "details": list(l.get("details", []))})
                e["value"] += l["value"]
            links = list(merged.values())
        self.nodes, self.links = nodes, links
        self.set_content_height(max(260, 40 + 34 * max([sum(1 for n in nodes if n["col"] == c) for c in range(4)] + [1])))
        self.queue_draw()

    def draw(self, cr, w, h):
        if not self.nodes:
            text(cr, w / 2, h / 2, "sin conexiones que mostrar", 9, P["muted"], align="center", valign="middle")
            return
        top, bottom, nw = 22, 6, 10
        colx = [8, w * 0.30, w * 0.56, w - 8 - nw]
        for c, t in enumerate(self.COL_TITLES):
            text(cr, colx[c] + (nw if c == 3 else 0), 2, t.upper(), 7.5, P["muted"], bold=True,
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
        # bandas
        for l in sorted(self.links, key=lambda l: -l["value"]):
            a, b = pos.get(l["source"]), pos.get(l["target"])
            if not a or not b:
                continue
            na = next(n for n in self.nodes if n["id"] == l["source"])
            nb = next(n for n in self.nodes if n["id"] == l["target"])
            ta = a[2] * l["value"] / max(na["value"], 1)
            tb = b[2] * l["value"] / max(nb["value"], 1)
            y0, y1 = a[1] + a[3], b[1] + b[4]
            a[3] += ta
            b[4] += tb
            x0, x1 = a[0] + nw, b[0]
            mx = (x0 + x1) / 2
            set_rgb(cr, self.KIND_COLOR.get(l["kind"], P["muted"]), 0.38)
            cr.move_to(x0, y0)
            cr.curve_to(mx, y0, mx, y1, x1, y1)
            cr.line_to(x1, y1 + tb)
            cr.curve_to(mx, y1 + tb, mx, y0 + ta, x0, y0 + ta)
            cr.close_path()
            cr.fill()
            tip = f"{na['label']} → {nb['label']}: {l['value']} conexiones"
            if l.get("details"):
                tip += "\n" + "\n".join(l["details"][:8])
            self.hits.append((x0, min(y0, y1), x1, max(y0 + ta, y1 + tb), tip))
        # nodos y etiquetas
        for n in self.nodes:
            x, y, hh = pos[n["id"]][:3]
            set_rgb(cr, self.KIND_COLOR.get(n["kind"], P["muted"]))
            cr.rectangle(x, y, nw, hh)
            cr.fill()
            label = f"{n['label']}  ({n['value']})"
            if n["col"] == 3:
                text(cr, x - 6, y + hh / 2, label, 8.5, P["ink"], align="right", valign="middle")
            else:
                text(cr, x + nw + 6, y + hh / 2, label, 8.5, P["ink"], valign="middle")
            self.hits.append((x - 2, y, x + nw + 2, y + hh, f"{n['label']}: {n['value']} conexiones"))
