"""VELA — aplicación nativa GTK 4 + libadwaita (diseño corporativo).

Ventana de escritorio propia (sin navegador ni servidor web): habla con `velad` por el socket UNIX
(o con el motor local si el daemon no está en marcha). Las consultas se hacen en hilos de fondo y la
interfaz se actualiza con GLib.idle_add. El panel de mando usa widgets persistentes que solo cambian
sus datos (sin parpadeo); las demás páginas se reconstruyen solo cuando cambian sus datos.
"""

from __future__ import annotations

import hashlib
import json
import math
import sys
import threading
import time
from collections import deque
from pathlib import Path

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gio, GLib, Gtk  # noqa: E402

import cairo  # noqa: E402

from .. import ACRONYM, TAGLINE, osmmap, worldmap  # noqa: E402
from .. import APP_ID as VELA_APP_ID  # noqa: E402
from ..ipc import connect  # noqa: E402
from ..util import fmt_duration, fmt_duration_short, iso, tilde  # noqa: E402
from .charts import P, STATUS, Columns, Donut, Gauge, HBars, LineChart, Sankey, measure, set_rgb, text  # noqa: E402

APP_ID = VELA_APP_ID
ICON = Path(__file__).resolve().parents[1] / "data" / "vela.svg"
SEV_STATUS = {"critical": "critical", "high": "critical", "medium": "serious", "warning": "warning",
              "low": "warning", "info": "neutral"}
VERDICT = {"fuga": ("critical", "Fuga"), "directa": ("serious", "Directa"), "protegida": ("good", "Protegida"),
           "permitida": ("neutral", "Permitida"), "otra": ("neutral", "Otra")}
VERDICT_COLOR = {"fuga": P["critical"], "directa": P["serious"], "protegida": P["good"], "permitida": P["s1"],
                 "otra": P["muted"]}
CATEGORY_ORDER = ["wifi", "lan", "vpn", "bloqueo", "máquinas virtuales", "contenedores", "virtual"]

CSS = f"""
window.vela, window.vela .content-bg {{ background-color: {P['page']}; }}
.vela .sidebar-pane {{ background-color: #141517; }}
.vela .navlist {{ background: transparent; }}
.vela .navlist row {{ border-radius: 8px; margin: 1px 8px; padding: 6px 8px; min-height: 0; }}
.vela .navlist row:selected {{ background-color: alpha({P['s1']}, 0.18); }}
.vela .brand {{ font-weight: 800; font-size: 12pt; letter-spacing: 0.02em; }}
.vela .brand-sub {{ font-size: 8pt; color: {P['muted']}; }}
.vela .card {{ background-color: {P['surface']}; border: 1px solid rgba(255,255,255,0.08);
                border-radius: 10px; padding: 12px 14px; box-shadow: none; }}
.vela .card-title {{ font-size: 8pt; font-weight: 700; letter-spacing: 0.08em; color: {P['muted']}; }}
.vela .kpi-value {{ font-size: 15pt; font-weight: 700; color: {P['ink']}; }}
.vela .kpi-sub {{ font-size: 8.5pt; color: {P['ink2']}; }}
.vela .pill {{ font-size: 8pt; font-weight: 700; border-radius: 99px; padding: 1px 8px; }}
.vela .pill-good {{ color: {P['good']}; background-color: alpha({P['good']}, 0.14); }}
.vela .pill-warning {{ color: {P['warning']}; background-color: alpha({P['warning']}, 0.14); }}
.vela .pill-serious {{ color: {P['serious']}; background-color: alpha({P['serious']}, 0.14); }}
.vela .pill-critical {{ color: #ff6b6b; background-color: alpha({P['critical']}, 0.18); }}
.vela .pill-neutral {{ color: {P['ink2']}; background-color: rgba(255,255,255,0.07); }}
.vela .th {{ font-size: 8pt; font-weight: 700; color: {P['muted']}; letter-spacing: 0.05em; }}
.vela .td {{ font-size: 9pt; color: {P['ink2']}; }}
.vela .td-strong {{ font-size: 9pt; color: {P['ink']}; font-weight: 600; }}
.vela .rowsep {{ background-color: rgba(255,255,255,0.05); min-height: 1px; }}
.vela .hop {{ background-color: {P['surface2']}; border-radius: 8px; padding: 6px 10px;
               border-left: 3px solid {P['s1']}; }}
.vela .hop-tor {{ border-left-color: #9085e9; }}
.vela .hop-home {{ border-left-color: {P['ink2']}; }}
.vela .hop-vpn {{ border-left-color: {P['good']}; }}
.vela .legend {{ font-size: 8.5pt; color: {P['ink2']}; }}
.vela .page-title {{ font-size: 13pt; font-weight: 700; }}
.vela .cmd {{ font-family: monospace; font-size: 8.5pt; color: {P['ink']}; background-color: #101113;
               border-radius: 6px; padding: 4px 8px; }}
.vela .mini {{ min-height: 18px; min-width: 18px; padding: 1px 4px; }}
.vela .badge {{ font-size: 7.5pt; font-weight: 800; color: #fff; background-color: {P['critical']};
                 border-radius: 99px; padding: 0 6px; }}
"""


# ── utilidades de UI ────────────────────────────────────────────────────────

def lbl(text_, css="td", xalign=0.0, wrap=False, ellipsize=False, selectable=False, width=None):
    w = Gtk.Label(label="—" if text_ is None else str(text_), xalign=xalign, wrap=wrap, selectable=selectable)
    if wrap:
        w.set_wrap_mode(2)
    if ellipsize:
        w.set_ellipsize(3)  # END
        w.set_max_width_chars(width or 40)
    for c in css.split():
        w.add_css_class(c)
    return w


def pill(status: str, label_: str):
    icon = STATUS.get(status, STATUS["neutral"])[0]
    return lbl(f"{icon} {label_}", f"pill pill-{status}")


def card(title: str | None = None, child=None, suffix=None):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.add_css_class("card")
    if title:
        head = Gtk.Box(spacing=8)
        head.append(lbl(title.upper(), "card-title"))
        if suffix is not None:
            head.append(Gtk.Box(hexpand=True))
            head.append(suffix)
        box.append(head)
    if child is not None:
        box.append(child)
    return box


def clear(box):
    c = box.get_first_child()
    while c is not None:
        n = c.get_next_sibling()
        box.remove(c)
        c = n


def table(columns: list[tuple[str, float]], rows: list[list], max_rows=200):
    """Tabla compacta: columns = [(título, peso)], celdas = texto | widget."""
    grid = Gtk.Grid(column_spacing=14, row_spacing=0)
    for j, (title, weight) in enumerate(columns):
        h = lbl(title.upper(), "th")
        h.set_hexpand(weight > 1)
        h.set_margin_bottom(6)
        grid.attach(h, j, 0, 1, 1)
    r = 1
    for row in rows[:max_rows]:
        sep = Gtk.Box()
        sep.add_css_class("rowsep")
        grid.attach(sep, 0, r, len(columns), 1)
        r += 1
        for j, cell in enumerate(row):
            w = cell if isinstance(cell, Gtk.Widget) else lbl(cell, "td" if j else "td-strong", ellipsize=True,
                                                               width=int(columns[j][1] * 14))
            w.set_margin_top(5)
            w.set_margin_bottom(5)
            w.set_halign(Gtk.Align.START)
            w.set_valign(Gtk.Align.CENTER)
            if not isinstance(cell, Gtk.Widget):
                w.set_tooltip_text(str(cell))
            grid.attach(w, j, r, 1, 1)
        r += 1
    if not rows:
        grid.attach(lbl("sin datos", "td"), 0, 1, len(columns), 1)
    return grid


PROXY_GUIDE = [
    "Las capas se apilan: el proxy decide a QUIÉN envía tu programa el tráfico; la VPN decide POR DÓNDE sale del "
    "equipo. Todo lo que no es loopback (incluido lo que envía un proxy) sigue la ruta del sistema: por el túnel si la "
    "VPN está conectada.",
    "Proxy LOCAL (en tu equipo: mitmproxy, Burp, privoxy…): solo reenvía. El destino sigue viendo la IP de la VPN (o "
    "tu IP real sin VPN). No añade anonimato, pero ve y puede modificar todo lo que pasa por él.",
    "Proxy REMOTO por encima de la VPN (tú → VPN → proxy → destino): el destino ve la IP del proxy; el proxy ve la IP "
    "de la VPN, no la tuya; la VPN ve que te conectas al proxy (y su contenido si no va cifrado).",
    "Proxy + Tor: «Tor → proxy» (salir de Tor a un proxy) evita bloqueos a exits de Tor, pero ese proxy ve todo y "
    "puede correlacionarte. «Proxy → Tor» (Socks5Proxy/HTTPSProxy en torrc) oculta el uso de Tor a tu red.",
    "DNS: usa socks5h:// (o torsocks / proxy_dns en proxychains) para que los nombres los resuelva el proxy; con "
    "socks5:// o http sin CONNECT, el DNS sale por tu resolver y revela los dominios.",
    "Los programas que ignoran el proxy salen «Directo»: el diagrama lo muestra. Con el kill-switch de la VPN, si el "
    "túnel cae, el proxy local también se queda sin salida (no expone tu IP).",
]


def tor_pill(t):
    """Celda Tor: exit / relay / no, con el detalle de las fuentes en el tooltip."""
    t = t or {}
    v = t.get("verdict")
    w = pill({"exit": "serious", "relay": "warning", "no": "good"}.get(v, "neutral"),
             {"exit": "Tor exit", "relay": "Tor relay", "no": "No"}.get(v, "?"))
    tip = []
    if t.get("relays"):
        tip.append("Relays: " + ", ".join(f"{r['nick']} ({' '.join(r['flags'][:4])})" for r in t["relays"]))
    tip.append("Consenso local: " + ("sí" if t.get("consensus") else "no"))
    tip.append("Lista oficial de salidas: " + ("sí" if t.get("in_exit_list") else "no"))
    exo = t.get("exonerator")
    if exo:
        tip.append(f"ExoneraTor ({exo.get('date')}): " + (exo.get("result") or exo.get("detail") or "—"))
    else:
        tip.append("ExoneraTor: no consultado")
    w.set_tooltip_text("\n".join(tip))
    return w


def cc_flag(cc) -> str:
    if not cc or len(cc) != 2 or not str(cc).isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc.upper())


def legend(items):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    for name, color, value in items:
        row = Gtk.Box(spacing=6)
        sw = Gtk.DrawingArea(content_width=10, content_height=10, valign=Gtk.Align.CENTER)
        sw.set_draw_func(lambda a, cr, w, h, c=color: (set_rgb(cr, c), cr.arc(w / 2, h / 2, 4.5, 0, 6.3), cr.fill()))
        row.append(sw)
        row.append(lbl(name, "legend"))
        if value != "":
            row.append(Gtk.Box(hexpand=True))
            row.append(lbl(value, "td-strong"))
        box.append(row)
    return box


def legend_row(items):
    b = Gtk.Box(spacing=16)
    for name, color in items:
        b.append(legend([(name, color, "")]))
    return b


def human_bps(v):
    if v is None:
        return "—"
    for u in ("B/s", "KB/s", "MB/s", "GB/s"):
        if v < 1024:
            return f"{v:.0f} {u}" if u == "B/s" or v >= 100 else f"{v:.1f} {u}"
        v /= 1024
    return f"{v:.1f} TB/s"


def scroller(child):
    sc = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
    sc.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    child.set_margin_top(14)
    child.set_margin_bottom(20)
    child.set_margin_start(18)
    child.set_margin_end(18)
    sc.set_child(child)
    return sc


def vbox(spacing=12):
    return Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=spacing)


def hbox(spacing=12, homogeneous=False):
    return Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=spacing, homogeneous=homogeneous)


class KPI:
    def __init__(self, title):
        self.value = lbl("—", "kpi-value", ellipsize=True, width=22)
        self.sub = lbl("", "kpi-sub", ellipsize=True, width=34)
        self.pill_box = hbox(0)
        inner = vbox(3)
        inner.append(self.value)
        inner.append(self.sub)
        self.widget = card(title, inner, self.pill_box)
        self.widget.set_hexpand(True)

    def set(self, value, sub, status, status_label):
        self.value.set_text(str(value))
        self.value.set_tooltip_text(str(value))
        self.sub.set_text(str(sub or ""))
        self.sub.set_tooltip_text(str(sub or ""))
        clear(self.pill_box)
        self.pill_box.append(pill(status, status_label))


# Estilo propio del mapa base (oscuro, discreto: los datos van encima)
MAP_STYLE = {"ocean": "#121419", "land": "#20242a", "coast": "#353b44", "grid": "#1b1e23",
             "country": "#6f7682", "city": "#9aa1ad", "dot": "#59606b"}
MAP_YTOP = osmmap.lonlat_to_norm(0, 82)[1]
MAP_YBOT = osmmap.lonlat_to_norm(0, -60)[1]
MAP_YSPAN = MAP_YBOT - MAP_YTOP


class MapView(Gtk.DrawingArea):
    """Mapa mundial interactivo (cairo).

    Rueda: zoom centrado en el cursor · arrastrar: desplazar · doble clic: acercar · clic: seleccionar.
    Capas: conexiones en vivo (agrupadas por ubicación), cadena actual, Tor, historial y mapa de calor.
    Los marcadores tienen tamaño fijo en pantalla: al acercar se separan los grupos.

    Mapa base: Web Mercator dibujado con datos de OpenStreetMap preprocesados en local (osmmap), con
    varios niveles de detalle y estilo propio. No pide teselas a ningún servidor mientras lo usas.
    El fondo se dibuja en una imagen en caché; al arrastrar se desplaza la imagen y se redibuja al parar."""

    VCOL = {"fuga": P["critical"], "directa": P["serious"], "protegida": P["good"], "permitida": P["s1"],
            "otra": P["muted"]}
    RANK = {"fuga": 4, "directa": 3, "otra": 2, "permitida": 1, "protegida": 0}

    def __init__(self, height=480, on_select=None):
        super().__init__(hexpand=True)
        self.set_content_height(height)
        self.data, self.flows, self.points = None, [], []
        self.s, self.ox, self.oy = 1.0, 0.0, None
        self.mouse = (0.0, 0.0)
        self._base = None          # (clave, superficie, ox, oy)
        self._base_timer = None
        self.tip = None
        self.selected = None
        self.on_select = on_select
        self.layers = {"live": True, "chain": True, "tor": True, "history": False, "heat": True}
        self.set_draw_func(self.draw)
        mc = Gtk.EventControllerMotion()
        mc.connect("motion", self._motion)
        self.add_controller(mc)
        sc = Gtk.EventControllerScroll(flags=Gtk.EventControllerScrollFlags.VERTICAL)
        sc.connect("scroll", self._scroll)
        self.add_controller(sc)
        dr = Gtk.GestureDrag()
        dr.connect("drag-begin", self._drag_begin)
        dr.connect("drag-update", self._drag_update)
        self.add_controller(dr)
        ck = Gtk.GestureClick()
        ck.connect("released", self._click)
        self.add_controller(ck)
        self.set_has_tooltip(True)
        self.connect("query-tooltip", lambda w, x, y, kb, tt: (tt.set_text(self.tip), True)[1] if self.tip else False)
        self.set_cursor(Gdk.Cursor.new_from_name("grab"))

    # ── datos / vista ──
    def set_data(self, d=None, flows=None):
        if d is not None:
            self.data = d
        if flows is not None:
            self.flows = flows
        self.queue_draw()

    # ── proyección (Web Mercator, recortado a 82°N–60°S) ──
    @staticmethod
    def _k(w, h):
        """Píxeles por ancho del mundo con zoom 1 (el mundo ocupa todo el ancho)."""
        return max(1.0, float(w))

    def _smin(self, w, h):
        return min(1.0, h / (MAP_YSPAN * self._k(w, h))) if w and h else 1.0

    def _smax(self):
        return 40.0 if osmmap.load() else 24.0

    def proj(self, lon, lat, w, h):
        nx, ny = osmmap.lonlat_to_norm(lon, lat)
        ks = self._k(w, h) * self.s
        if self.oy is None:
            self._clamp(w, h)
        return nx * ks + self.ox, (ny - MAP_YTOP) * ks + self.oy

    def _clamp(self, w=None, h=None):
        w = w or self.get_width()
        h = h or self.get_height()
        ks = self._k(w, h) * self.s
        W, H = ks, MAP_YSPAN * ks
        if self.oy is None:            # vista inicial: centrada en las latitudes con más tráfico (~35°N)
            self.oy = h / 2 - (osmmap.lonlat_to_norm(0, 35)[1] - MAP_YTOP) * ks
        self.ox = (w - W) / 2 if W <= w else min(0.0, max(w - W, self.ox))
        self.oy = (h - H) / 2 if H <= h else min(0.0, max(h - H, self.oy))

    def zoom(self, factor, cx=None, cy=None):
        w, h = self.get_width(), self.get_height()
        cx = w / 2 if cx is None else cx
        cy = h / 2 if cy is None else cy
        if self.oy is None:
            self._clamp(w, h)
        ns = max(self._smin(w, h), min(self._smax(), self.s * factor))
        self.ox = cx - (cx - self.ox) * ns / self.s
        self.oy = cy - (cy - self.oy) * ns / self.s
        self.s = ns
        self._clamp()
        self.queue_draw()

    def reset(self):
        """Ver el mundo entero."""
        w, h = self.get_width(), self.get_height()
        self.s = self._smin(w, h)
        self.ox = self.oy = 0.0
        self._clamp()
        self.queue_draw()

    def focus(self, lon, lat, scale=6.0):
        w, h = self.get_width(), self.get_height()
        self.s = max(self._smin(w, h), min(self._smax(), scale))
        x, y = self.proj(lon, lat, w, h)
        self.ox += w / 2 - x
        self.oy += h / 2 - y
        self._clamp()
        self.queue_draw()

    def zoom_level(self, w=None, h=None):
        """Zoom equivalente al de OSM (0 = mundo en una tesela de 256 px)."""
        return math.log2(self._k(w or self.get_width(), h or self.get_height()) * self.s / 256)

    # ── mapa base ──
    def _draw_base(self, cr, w, h):
        """Pinta el mapa base usando la caché si la escala no ha cambiado."""
        bm = osmmap.load()
        key = (w, h, round(self.s, 6), id(bm), self.get_scale_factor(), self._marker_geo())
        cache = self._base
        if cache and cache[0] == key:
            dx, dy = self.ox - cache[2], self.oy - cache[3]
            if dx or dy:
                set_rgb(cr, MAP_STYLE["ocean"])
                cr.paint()
                self._schedule_base()
            cr.set_source_surface(cache[1], dx, dy)
            cr.paint()
            return
        surf = self._render_base(w, h, bm)
        self._base = (key, surf, self.ox, self.oy)
        cr.set_source_surface(surf, 0, 0)
        cr.paint()

    def _schedule_base(self):
        if self._base_timer:
            GLib.source_remove(self._base_timer)

        def fire():
            self._base_timer = None
            self._base = None
            self.queue_draw()
            return False
        self._base_timer = GLib.timeout_add(140, fire)

    def _render_base(self, w, h, bm):
        sf = self.get_scale_factor()
        surf = cairo.ImageSurface(cairo.FORMAT_RGB24, max(1, int(w * sf)), max(1, int(h * sf)))
        surf.set_device_scale(sf, sf)
        cr = cairo.Context(surf)
        set_rgb(cr, MAP_STYLE["ocean"])
        cr.paint()
        ks = self._k(w, h) * self.s
        z = self.zoom_level(w, h)
        # retícula: más densa al acercar
        step = 30 if z < 4 else 10 if z < 6 else 5
        set_rgb(cr, MAP_STYLE["grid"])
        cr.set_line_width(1)
        for lon in range(-180, 181, step):
            x, _ = self.proj(lon, 0, w, h)
            if 0 <= x <= w:
                cr.move_to(round(x) + 0.5, 0)
                cr.line_to(round(x) + 0.5, h)
        for lat in range(-60, 85, step):
            _, y = self.proj(0, lat, w, h)
            if 0 <= y <= h:
                cr.move_to(0, round(y) + 0.5)
                cr.line_to(w, round(y) + 0.5)
        cr.stroke()
        if bm is None:
            self._render_fallback(cr, w, h)
            return surf
        lod = osmmap.lod_for_zoom(z)
        x0, x1 = -self.ox / ks, (w - self.ox) / ks
        y0, y1 = MAP_YTOP - self.oy / ks, MAP_YTOP + (h - self.oy) / ks
        tiles = list(bm.visible(lod, x0, y0, x1, y1))
        f = ks / bm.q
        mat = cairo.Matrix(f, 0, 0, f, self.ox, self.oy - MAP_YTOP * ks)

        def path(seq_of_arrays, close):
            cr.save()
            cr.transform(mat)
            mt, lt = cr.move_to, cr.line_to
            for arr in seq_of_arrays:
                it = iter(arr)
                mt(next(it), next(it))
                for x in it:
                    lt(x, next(it))
                if close:
                    cr.close_path()
            cr.restore()

        cr.set_fill_rule(cairo.FILL_RULE_EVEN_ODD)
        set_rgb(cr, MAP_STYLE["land"])
        for _tx, _ty, rings in tiles:      # un único trazado: sin costuras de antialiasing entre teselas
            path(rings, True)
        cr.fill()
        set_rgb(cr, MAP_STYLE["coast"])
        cr.set_line_width(0.8 if z < 4 else 1.0)
        cr.set_line_join(cairo.LINE_JOIN_ROUND)
        for tx, ty, _rings in tiles:
            path(bm.coast(lod, tx, ty), False)
        cr.stroke()
        self._render_labels(cr, w, h, bm, z, ks)
        return surf

    def _render_fallback(self, cr, w, h):
        """Sin mapa OSM instalado: contorno simplificado embebido con el mismo estilo."""
        set_rgb(cr, MAP_STYLE["land"])
        for poly in worldmap.LAND.values():
            for i, (lo, la) in enumerate(poly):
                x, y = self.proj(lo, la, w, h)
                (cr.move_to if i == 0 else cr.line_to)(x, y)
            cr.close_path()
        cr.fill_preserve()
        set_rgb(cr, MAP_STYLE["coast"])
        cr.set_line_width(0.8)
        cr.stroke()

    def _marker_geo(self):
        """Posiciones (lon, lat, radio px) de los marcadores de datos: los nombres del mapa base las esquivan."""
        d = self.data or {}
        out = []
        home = d.get("home") or {}
        if home.get("lat") is not None:
            out.append((round(home["lon"], 2), round(home["lat"], 2), 12))
        if self.layers["live"]:
            for g in self.clusters():
                out.append((round(g["lon"], 2), round(g["lat"], 2), int(9 + 2.2 * math.sqrt(len(g["flows"])))))
        for layer, chain in (("chain", d.get("chain") or []), ("tor", d.get("tor_chain") or [])):
            if self.layers[layer]:
                out += [(round(x["lon"], 2), round(x["lat"], 2), 10) for x in chain if x.get("lat") is not None]
        return tuple(sorted(set(out)))

    def _render_labels(self, cr, w, h, bm, z, ks):
        """Países, capitales y ciudades (OSM place=*), sin solaparse entre sí ni con los marcadores;
        cuanto más cerca, más nombres (primero los más poblados)."""
        taken = []
        for lon, lat, r in self._marker_geo():
            x, y = self.proj(lon, lat, w, h)
            taken.append((x - r, y - r, x + r, y + r + 12))
        shown = 0

        def free(r):
            return all(r[0] > q[2] or r[2] < q[0] or r[1] > q[3] or r[3] < q[1] for q in taken)

        min_city = 6_000_000 if z < 4.6 else 2_000_000 if z < 5.4 else 900_000 if z < 6.2 else \
            300_000 if z < 7 else 0
        min_country = 8_000_000 if z < 2.6 else 1_000_000 if z < 3.6 else 0
        for p in bm.places:
            kind = p["kind"]
            if kind == "country" and (z >= 5.6 or p["pop"] < min_country):
                continue
            if kind == "capital" and z < 3.3:
                continue
            if kind == "city" and (z < 4.2 or p["pop"] < min_city):
                continue
            x = p["x"] * ks + self.ox
            y = (p["y"] - MAP_YTOP) * ks + self.oy
            if not (-40 <= x <= w + 40 and -10 <= y <= h + 10):
                continue
            if kind == "country":
                name = p["name"].upper()
                size = 7.5 if z < 3 else 8.5
                tw, th = measure(cr, name, size, True)
                r = (x - tw / 2 - 2, y - th / 2 - 1, x + tw / 2 + 2, y + th / 2 + 1)
                if free(r):
                    taken.append(r)
                    text(cr, x, y, name, size, MAP_STYLE["country"], bold=True, align="center", valign="middle")
                    shown += 1
            else:
                size = 8.0 if kind == "capital" else 7.5
                tw, th = measure(cr, p["name"], size, kind == "capital")
                r = (x - 3, y - th / 2 - 1, x + 6 + tw + 2, y + th / 2 + 1)
                if free(r):
                    taken.append(r)
                    set_rgb(cr, MAP_STYLE["dot"] if kind == "city" else MAP_STYLE["city"])
                    cr.arc(x, y, 2.2 if kind == "capital" else 1.7, 0, 2 * math.pi)
                    cr.fill()
                    text(cr, x + 5, y, p["name"], size, MAP_STYLE["city"] if kind == "capital" else MAP_STYLE["country"],
                         bold=kind == "capital", valign="middle")
                    shown += 1
            if shown >= 220:
                break

    def clusters(self):
        groups = {}
        for f in self.flows:
            if f.get("lat") is None:
                continue
            key = (round(f["lat"], 2), round(f["lon"], 2))
            g = groups.setdefault(key, {"lat": f["lat"], "lon": f["lon"], "country": f.get("country"),
                                        "name": f.get("country_name"), "flows": []})
            g["flows"].append(f)
        for g in groups.values():
            g["worst"] = max((x["verdict"] for x in g["flows"]), key=lambda v: self.RANK.get(v, 0))
            g["tor"] = sum(1 for x in g["flows"] if x.get("tor"))
            g["vt_bad"] = sum(1 for x in g["flows"] if (x.get("vt") or {}).get("malicious"))
        return list(groups.values())

    # ── dibujo ──
    def draw(self, _a, cr, w, h):
        if self.oy is None:
            self._clamp(w, h)
        self._draw_base(cr, w, h)
        self.points = []
        d = self.data or {}
        home = d.get("home") or {}
        start = self.proj(home["lon"], home["lat"], w, h) if home.get("lat") is not None else None
        if self.layers["heat"]:
            heat = d.get("heat") or []
            mx = max([x["seconds"] for x in heat] + [1])
            for x in heat:
                if x.get("lat") is None:
                    continue
                px, py = self.proj(x["lon"], x["lat"], w, h)
                r = 5 + 24 * math.sqrt(x["seconds"] / mx)
                set_rgb(cr, P["s1"], 0.13)
                cr.arc(px, py, r, 0, 2 * math.pi)
                cr.fill()
                self.points.append((px, py, r, "heat", x))
        if self.layers["history"]:
            for it in d.get("history") or []:
                px, py = self.proj(it["lon"], it["lat"], w, h)
                set_rgb(cr, "#9085e9" if it["layer"].startswith("tor") else P["s1"], 0.65)
                cr.arc(px, py, 2.5, 0, 2 * math.pi)
                cr.fill()
                self.points.append((px, py, 6, "history", it))
        if self.layers["live"]:
            cl = self.clusters()
            if start:
                for g in cl:
                    p = self.proj(g["lon"], g["lat"], w, h)
                    if math.dist(p, start) < 2:
                        continue
                    set_rgb(cr, self.VCOL.get(g["worst"], P["muted"]), 0.35 if self.selected is not g else 0.9)
                    cr.set_line_width(1.5 if self.selected is not g else 2.5)
                    mx_, my_ = (start[0] + p[0]) / 2, (start[1] + p[1]) / 2 - min(90, math.dist(start, p) * 0.25)
                    cr.move_to(*start)
                    cr.curve_to(mx_, my_, mx_, my_, *p)
                    cr.stroke()
            for g in cl:
                px, py = self.proj(g["lon"], g["lat"], w, h)
                n = len(g["flows"])
                r = 5 + 2.2 * math.sqrt(n)
                set_rgb(cr, P["surface"])
                cr.arc(px, py, r + 2, 0, 2 * math.pi)
                cr.fill()
                set_rgb(cr, self.VCOL.get(g["worst"], P["muted"]))
                cr.arc(px, py, r, 0, 2 * math.pi)
                cr.fill()
                if g["vt_bad"]:
                    set_rgb(cr, P["critical"])
                    cr.set_line_width(2)
                    cr.arc(px, py, r + 4, 0, 2 * math.pi)
                    cr.stroke()
                if n > 1:
                    text(cr, px, py, str(n), 7.5, "#000000", bold=True, align="center", valign="middle")
                if g["tor"]:
                    text(cr, px + r + 1, py - r - 2, "🧅", 8, P["ink"], valign="middle")
                if self.s >= 3:
                    text(cr, px, py + r + 3, f"{g['country'] or '?'}", 8, P["ink2"], align="center")
                self.points.append((px, py, r + 3, "cluster", g))
        for layer, chain, color in (("chain", d.get("chain") or [], P["s1"]), ("tor", d.get("tor_chain") or [], "#9085e9")):
            if not self.layers[layer]:
                continue
            prev = start
            for hop in chain:
                if hop.get("lat") is None:
                    continue
                p = self.proj(hop["lon"], hop["lat"], w, h)
                c = P["good"] if hop["type"] == "vpn" else color
                if prev and math.dist(prev, p) > 2:
                    set_rgb(cr, c, 0.95)
                    cr.set_line_width(2.5)
                    cr.set_dash([6, 4])
                    mx_, my_ = (prev[0] + p[0]) / 2, (prev[1] + p[1]) / 2 - min(70, math.dist(prev, p) * 0.3)
                    cr.move_to(*prev)
                    cr.curve_to(mx_, my_, mx_, my_, *p)
                    cr.stroke()
                    cr.set_dash([])
                set_rgb(cr, P["surface"])
                cr.rectangle(p[0] - 6, p[1] - 6, 12, 12)
                cr.fill()
                set_rgb(cr, c)
                cr.rectangle(p[0] - 4.5, p[1] - 4.5, 9, 9)
                cr.fill()
                self.points.append((p[0], p[1], 9, "hop", hop))
                prev = p
        if start:
            set_rgb(cr, P["ink"])
            cr.arc(start[0], start[1], 5, 0, 2 * math.pi)
            cr.fill()
            set_rgb(cr, P["surface"])
            cr.arc(start[0], start[1], 2, 0, 2 * math.pi)
            cr.fill()
            self.points.append((start[0], start[1], 9, "home", home))
        z = self.zoom_level(w, h)
        text(cr, w - 8, h - 6, f"zoom {z:.1f} · ×{self.s:.1f}", 8, P["muted"], align="right", valign="bottom")
        note = (osmmap.ATTRIBUTION if osmmap.load() else
                "Mapa básico · genera el mapa OpenStreetMap en Ajustes → Mapa")
        tw, th = measure(cr, note, 7.5)
        set_rgb(cr, MAP_STYLE["ocean"], 0.8)
        cr.rectangle(0, h - th - 6, tw + 14, th + 6)
        cr.fill()
        text(cr, 7, h - 3, note, 7.5, P["muted"], valign="bottom")

    # ── interacción ──
    def _hit(self, x, y):
        best = None
        for px, py, r, kind, payload in self.points:
            dd = math.hypot(px - x, py - y)
            if dd <= max(r, 6) and (best is None or (kind != "heat", -dd) > (best[0] != "heat", -best[2])):
                best = (kind, payload, dd)
        return best

    def _motion(self, _c, x, y):
        self.mouse = (x, y)
        hit = self._hit(x, y)
        self.tip = self._describe(*hit[:2]) if hit else None
        self.set_cursor(Gdk.Cursor.new_from_name("pointer" if hit and hit[0] != "heat" else "grab"))

    def _describe(self, kind, p):
        if kind == "cluster":
            procs = {}
            for f in p["flows"]:
                procs[f["process"]] = procs.get(f["process"], 0) + 1
            ips = list(dict.fromkeys(f["remote"] for f in p["flows"]))
            verd = {}
            for f in p["flows"]:
                verd[f["verdict"]] = verd.get(f["verdict"], 0) + 1
            return (f"{cc_flag(p['country'])} {p['name'] or '?'} — {len(p['flows'])} conexiones\n"
                    + " · ".join(f"{k}: {v}" for k, v in verd.items()) + "\n"
                    + "Programas: " + ", ".join(f"{k} ({v})" for k, v in sorted(procs.items(), key=lambda kv: -kv[1])[:5])
                    + "\nIPs: " + ", ".join(ips[:5]) + (" …" if len(ips) > 5 else "")
                    + (f"\n🧅 {p['tor']} conexiones a nodos Tor" if p["tor"] else "")
                    + (f"\n⚠ {p['vt_bad']} marcadas en VirusTotal" if p["vt_bad"] else "")
                    + "\nClic para ver el detalle")
        if kind == "hop":
            return f"{p['type']}: {p.get('label')}\n{p.get('ip') or ''} · {p.get('country') or '?'} (ubicación estimada)"
        if kind == "history":
            return f"{p['layer']}: {p['label']} ({p.get('country') or '?'})\n{iso(p['started'])} → " \
                   f"{iso(p['ended']) if p['ended'] else 'activo'}"
        if kind == "heat":
            return f"{p['name']}: {fmt_duration(p['seconds'])} de salida (7 días)"
        if kind == "home":
            return f"Tu origen (estimado por {p.get('geo_source')})"
        return None

    def _scroll(self, _c, _dx, dy):
        self.zoom(1.25 if dy < 0 else 0.8, *self.mouse)
        return True

    def _drag_begin(self, _g, x, y):
        self._drag0 = (self.ox, self.oy)
        self._dragged = False

    def _drag_update(self, _g, dx, dy):
        if abs(dx) + abs(dy) > 3:
            self._dragged = True
            self.set_cursor(Gdk.Cursor.new_from_name("grabbing"))
        self.ox, self.oy = self._drag0[0] + dx, self._drag0[1] + dy
        self._clamp()
        self.queue_draw()

    def _click(self, _g, n_press, x, y):
        if getattr(self, "_dragged", False):
            self._dragged = False
            self.set_cursor(Gdk.Cursor.new_from_name("grab"))
            return
        if n_press == 2:
            self.zoom(2.0, x, y)
            return
        hit = self._hit(x, y)
        self.selected = hit[1] if hit and hit[0] == "cluster" else None
        self.queue_draw()
        if self.on_select:
            self.on_select(hit[0] if hit else None, hit[1] if hit else None)


# ── ventana ─────────────────────────────────────────────────────────────────

PAGES = [("dash", "Panel de mando", "utilities-system-monitor-symbolic"),
         ("live", "Tiempo real", "network-transmit-receive-symbolic"),
         ("nets", "Redes", "network-wired-symbolic"),
         ("map", "Mapa", "mark-location-symbolic"),
         ("hist", "Historial", "document-open-recent-symbolic"),
         ("fix", "Alertas y acciones", "dialog-warning-symbolic"),
         ("intel", "Threat intel", "security-high-symbolic"),
         ("prof", "Perfiles", "system-users-symbolic"),
         ("settings", "Ajustes", "emblem-system-symbolic")]
KEY_ROWS = [("virustotal", "VirusTotal", "virustotal"), ("shodan", "Shodan", "shodan"),
            ("greynoise", "GreyNoise (opcional: sin clave usa la API comunitaria)", "greynoise"),
            ("censys_token", "Censys · token de la Platform", "censys"),
            ("censys_org", "Censys · ID de organización (opcional)", None)]


def state_path() -> Path:
    from ..util import xdg_dir
    return xdg_dir("config") / "app-state.json"


def load_state() -> dict:
    try:
        return json.loads(state_path().read_text())
    except (OSError, ValueError):
        return {}


def save_state(st: dict):
    import os
    from ..util import private_dir
    p = state_path()
    private_dir(p.parent)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(st, f)


def ensure_daemon(timeout: float = 10) -> bool:
    """Si velad no está en marcha lo arranca: sin daemon no se guarda historial."""
    import os
    import subprocess
    from ..ipc import ping
    if ping():
        return True
    root = Path(__file__).resolve().parents[2]
    subprocess.Popen([sys.executable, "-m", "vela", "daemon", "start"],
                     env={**os.environ, "PYTHONPATH": str(root)}, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
    t0 = time.monotonic()
    while time.monotonic() - t0 < timeout:
        time.sleep(0.25)
        if ping():
            return True
    return False


class Window(Adw.ApplicationWindow):
    def __init__(self, app, backend):
        super().__init__(application=app, title="VELA")
        self.add_css_class("vela")
        self.state = load_state()
        self.set_default_size(self.state.get("width", 1360), self.state.get("height", 880))
        if self.state.get("maximized"):
            self.maximize()
        self.connect("close-request", self._save_state)
        self.b = backend
        self.data: dict = {}
        self.busy = False
        self.sig: dict[str, str] = {}
        self.traffic = {"rx": deque(maxlen=120), "tx": deque(maxlen=120)}
        self._last_counters = None

        # barra lateral
        side = vbox(0)
        brand = hbox(10)
        brand.set_margin_top(4)
        brand.set_margin_start(16)
        brand.set_margin_bottom(14)
        brand.set_tooltip_text(f"VELA — {ACRONYM}\n{TAGLINE}")
        logo = Gtk.Image.new_from_file(str(ICON))
        logo.set_pixel_size(34)
        brand.append(logo)
        names = vbox(0)
        names.set_valign(Gtk.Align.CENTER)
        names.append(lbl("VELA", "brand"))
        names.append(lbl(ACRONYM, "brand-sub"))
        brand.append(names)
        side.append(brand)
        self.nav = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
        self.nav.add_css_class("navlist")
        self.badges = {}
        for key, title, icon in PAGES:
            row = Gtk.ListBoxRow()
            row.key = key
            b = hbox(10)
            b.append(Gtk.Image.new_from_icon_name(icon))
            b.append(lbl(title, "td-strong"))
            b.append(Gtk.Box(hexpand=True))
            badge = lbl("", "badge")
            badge.set_visible(False)
            self.badges[key] = badge
            b.append(badge)
            row.set_child(b)
            self.nav.append(row)
        self.nav.connect("row-selected", self.on_nav)
        side.append(self.nav)
        side.append(Gtk.Box(vexpand=True))
        self.side_status = lbl("", "brand-sub", wrap=True)
        self.side_status.set_margin_start(18)
        self.side_status.set_margin_end(12)
        self.side_status.set_margin_bottom(14)
        side.append(self.side_status)
        side_tv = Adw.ToolbarView()
        side_tv.add_top_bar(Adw.HeaderBar(show_title=False))
        side_tv.set_content(side)
        side_tv.add_css_class("sidebar-pane")

        # contenido
        self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.NONE)
        self.pages = {}
        for key, _title, _ in PAGES:
            box = vbox(12)
            self.pages[key] = box
            self.stack.add_named(scroller(box), key)
        header = Adw.HeaderBar()
        self.title = lbl("Panel de mando", "page-title")
        header.set_title_widget(self.title)
        self.profile_dd = Gtk.DropDown(tooltip_text="Perfil OPSEC activo")
        self._profiles = []
        self._profile_handler = self.profile_dd.connect("notify::selected", self.on_profile)
        header.pack_start(self.profile_dd)
        self.head_pill = hbox(0)
        header.pack_start(self.head_pill)
        panic = Gtk.Button(label="Emergencia")
        panic.add_css_class("destructive-action")
        panic.connect("clicked", self.on_panic)
        header.pack_end(panic)
        ref = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Actualizar")
        ref.connect("clicked", lambda *_: self.refresh(full=True))
        header.pack_end(ref)
        self.toasts = Adw.ToastOverlay(child=self.stack)
        content_tv = Adw.ToolbarView()
        content_tv.add_top_bar(header)
        self.banner = Adw.Banner(title="MODO EMERGENCIA ACTIVO — rotaciones detenidas", button_label="Reanudar")
        self.banner.connect("button-clicked", lambda *_: self.call_bg("resume", {}, lambda r: self.toast("Emergencia desactivada")))
        content_tv.add_top_bar(self.banner)
        content_tv.set_content(self.toasts)
        content_tv.add_css_class("content-bg")

        split = Adw.NavigationSplitView(min_sidebar_width=210, max_sidebar_width=240)
        split.set_sidebar(Adw.NavigationPage(child=side_tv, title="VELA"))
        split.set_content(Adw.NavigationPage(child=content_tv, title="Panel"))
        self.set_content(split)

        self.build_dash()
        self.build_map()
        keys = [k for k, _, _ in PAGES]
        start = keys.index(self.state["page"]) if self.state.get("page") in keys else 0
        self.nav.select_row(self.nav.get_row_at_index(start))
        GLib.timeout_add_seconds(4, lambda: (self.refresh(), True)[1])
        GLib.timeout_add_seconds(2, self._fast)
        GLib.timeout_add_seconds(1, self._clock)
        self.refresh(full=True)
        threading.Thread(target=self._events, daemon=True).start()

    def _save_state(self, *_):
        w, h = self.get_default_size()
        save_state({"width": w, "height": h, "maximized": self.is_maximized(), "page": self.current()})
        return False

    # ── navegación / datos ──
    def current(self):
        return self.stack.get_visible_child_name()

    def on_nav(self, _lb, row):
        if row is None:
            return
        self.stack.set_visible_child_name(row.key)
        self.title.set_text(dict((k, t) for k, t, _ in PAGES)[row.key])
        self.sig.pop(row.key, None)
        self.render()
        if row.key == "live" and "routes" not in self.data:
            self.refresh()

    def call_bg(self, method, params, done=None):
        def work():
            try:
                r = self.b.call(method, **params)
                if done:
                    GLib.idle_add(done, r)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(self.toast, f"Error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def refresh(self, full=False):
        if self.busy:
            return
        self.busy = True

        def work():
            d = {}
            try:
                if not getattr(self.b, "remote", False):
                    self.b.engine.tick()
                d["status"] = self.b.call("status")
                if self.current() == "live":
                    try:
                        d["routes"] = self.b.call("routes")
                    except Exception as e:  # noqa: BLE001
                        d["routes_error"] = str(e)
                d["leakwatch"] = self.b.call("leakwatch")
                if full or time.monotonic() - self.data.get("_slow", 0) > 20:
                    for k, m, p in (("networks", "networks", {}), ("map", "map", {}), ("sessions", "sessions", {"limit": 80}),
                                    ("counters", "counters", {}), ("timeline", "timeline", {"limit": 600}),
                                    ("fixes", "fixes", {}), ("profiles", "profiles", {}), ("intel", "intel_results", {}),
                                    ("intel_keys", "intel_keys", {}), ("stats", "stats", {"period": "week"}),
                                    ("settings", "settings_get", {})):
                        try:
                            d[k] = self.b.call(m, **p)
                        except Exception as e:  # noqa: BLE001
                            d[k + "_error"] = str(e)
                    d["_slow"] = time.monotonic()
            except Exception as e:  # noqa: BLE001
                d["error"] = str(e)
            GLib.idle_add(self._apply, d)
        threading.Thread(target=work, daemon=True).start()

    def _apply(self, d):
        self.busy = False
        self.data.update(d)
        self.render()
        return False

    def _fast(self):
        """Tráfico en vivo desde los contadores del kernel de la interfaz de salida (cada 2 s)."""
        st = self.data.get("status") or {}
        dev = (((st.get("net") or {}).get("egress") or {}).get("ipv4") or {}).get("dev")
        if dev:
            try:
                base = Path("/sys/class/net", dev, "statistics")
                rx, tx = int((base / "rx_bytes").read_text()), int((base / "tx_bytes").read_text())
                t = time.monotonic()
                if self._last_counters and self._last_counters[0] == dev:
                    _, t0, rx0, tx0 = self._last_counters
                    dt = max(0.1, t - t0)
                    self.traffic["rx"].append(max(0, (rx - rx0) / dt))
                    self.traffic["tx"].append(max(0, (tx - tx0) / dt))
                self._last_counters = (dev, t, rx, tx)
                span = len(self.traffic["rx"]) * 2
                self.traffic_chart.set([("Descarga", P["s1"], list(self.traffic["rx"])),
                                        ("Subida", P["s2"], list(self.traffic["tx"]))],
                                       (f"hace {span // 60} min {span % 60} s" if span >= 60 else f"hace {span} s", "ahora"))
                last = lambda k: self.traffic[k][-1] if self.traffic[k] else None  # noqa: E731
                self.traffic_dev.set_text(f"{dev} · ↓ {human_bps(last('rx'))}   ↑ {human_bps(last('tx'))}")
            except OSError:
                pass
        if self.current() in ("live", "map") and not getattr(self, "_lw_busy", False):
            self._lw_busy = True

            def done(r):
                self._lw_busy = False
                self.data["leakwatch"] = r
                self.render()
            self.call_bg("leakwatch", {}, done)
            GLib.timeout_add_seconds(30, lambda: (setattr(self, "_lw_busy", False), False)[1])
        return True

    def _clock(self):
        st = self.data.get("status") or {}
        if st.get("session"):
            self.kpi_session.value.set_text(fmt_duration(st["session"]["duration"] + (time.time() - st["ts"])))
        return True

    def _events(self):
        try:
            for ev in self.b.subscribe():
                if ev.get("severity") in ("high", "critical"):
                    GLib.idle_add(self._notify, ev)
        except Exception:  # noqa: BLE001
            pass

    def _notify(self, ev):
        from ..autostart import tray_running
        if tray_running():                   # la bandeja ya notifica: evita avisos duplicados
            self.toast(f"{ev['kind']}: {json.dumps(ev['data'], ensure_ascii=False)[:110]}")
            return False
        n = Gio.Notification.new(f"VELA · {ev['kind']}")
        n.set_body(json.dumps(ev["data"], ensure_ascii=False)[:200])
        n.set_priority(Gio.NotificationPriority.URGENT if ev["severity"] == "critical" else Gio.NotificationPriority.HIGH)
        self.get_application().send_notification(None, n)
        self.toast(f"{ev['kind']}: {json.dumps(ev['data'], ensure_ascii=False)[:110]}")
        return False

    def toast(self, t):
        self.toasts.add_toast(Adw.Toast(title=GLib.markup_escape_text(str(t)), timeout=5))
        return False

    def copy(self, t, msg="Comando copiado al portapapeles"):
        Gdk.Display.get_default().get_clipboard().set(t)
        self.toast(msg)

    # ── acciones ──
    def on_profile(self, dd, _p):
        i = dd.get_selected()
        if 0 <= i < len(self._profiles) and self._profiles[i] != (self.data.get("status") or {}).get("profile"):
            name = self._profiles[i]
            self.call_bg("profile_activate", {"name": name}, lambda r: (self.toast(f"Perfil activo: {name}"),
                                                                      self.refresh(full=True)))

    def on_panic(self, *_):
        dlg = Adw.AlertDialog(heading="¿Activar el modo de emergencia?",
                              body="Detiene las rotaciones y, si está permitido, bloquea las conexiones no verificadas. "
                                   "No borra datos ni cambia la configuración.")
        dlg.add_response("cancel", "Cancelar")
        dlg.add_response("panic", "Activar")
        dlg.set_response_appearance("panic", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.connect("response", lambda d, r: r == "panic" and self.call_bg("panic", {}, lambda res: (
            self.toast("Emergencia activa · kill-switch " + ("aplicado" if res["killswitch"].get("ok") else "no aplicado")),
            self.refresh(full=True))))
        dlg.present(self)

    # ── render común ──
    def render(self):
        st = self.data.get("status")
        if not st:
            return
        ex = st["exposure"]
        stx = {"baja": "good", "media": "warning", "alta": "critical"}[ex["level"]]
        clear(self.head_pill)
        self.head_pill.append(pill(stx, f"Exposición {ex['score']}/100"))
        self.banner.set_revealed(bool(st.get("emergency")))
        prof = self.data.get("profiles")
        if prof:
            names = list(prof["profiles"])
            self.profile_dd.handler_block(self._profile_handler)
            if names != self._profiles:
                self._profiles = names
                self.profile_dd.set_model(Gtk.StringList.new(names))
            if st["profile"] in names:
                self.profile_dd.set_selected(names.index(st["profile"]))
            self.profile_dd.handler_unblock(self._profile_handler)
        nfix = sum(1 for f in st.get("findings") or [] if f["status"] == "fail")
        self.badges["fix"].set_text(str(nfix))
        self.badges["fix"].set_visible(nfix > 0)
        lw = self.data.get("leakwatch") or {}
        nleak = (lw.get("summary") or {}).get("fugas", 0)
        self.badges["live"].set_text(str(nleak))
        self.badges["live"].set_visible(nleak > 0)
        self.side_status.set_text(f"{'daemon conectado' if getattr(self.b, 'remote', False) else 'motor local'}\n"
                                  f"actualizado {time.strftime('%H:%M:%S')}")
        page = self.current()
        if page == "dash":
            self.update_dash()
            return
        if page == "map":
            self.render_map()
            return
        payload = {"live": ("leakwatch", "routes"), "nets": "networks", "map": "map", "hist": "timeline", "fix": "fixes",
                   "intel": ("intel", "intel_keys"), "prof": "profiles", "settings": "settings"}[page]
        blob = [self.data.get(p) for p in payload] if isinstance(payload, tuple) else self.data.get(payload)
        sig = hashlib.md5(json.dumps(blob, sort_keys=True, default=str).encode()).hexdigest()
        if self.sig.get(page) == sig:
            return
        self.sig[page] = sig
        getattr(self, f"render_{page}")()

    # ── panel de mando (widgets persistentes) ──
    def build_dash(self):
        box = self.pages["dash"]
        row1 = hbox(12, homogeneous=True)
        self.kpi_tunnel, self.kpi_ip, self.kpi_ks, self.kpi_dns, self.kpi_session = (
            KPI("Túnel VPN"), KPI("IP pública"), KPI("Kill-switch"), KPI("DNS"), KPI("Sesión actual"))
        for k in (self.kpi_tunnel, self.kpi_ip, self.kpi_ks, self.kpi_dns, self.kpi_session):
            row1.append(k.widget)
        box.append(row1)

        row2 = hbox(12)
        self.gauge = Gauge()
        g = card("Exposición observable", self.gauge)
        g.set_size_request(250, -1)
        row2.append(g)
        dn = hbox(14)
        self.donut = Donut("conexiones")
        self.donut.set_size_request(150, 150)
        self.donut.set_hexpand(False)
        dn.append(self.donut)
        self.donut_legend = vbox(4)
        self.donut_legend.set_valign(Gtk.Align.CENTER)
        self.donut_legend.set_hexpand(True)
        dn.append(self.donut_legend)
        c = card("Conexiones a Internet ahora", dn)
        c.set_size_request(330, -1)
        row2.append(c)
        tv = vbox(6)
        self.traffic_chart = LineChart(height=140, fmt=human_bps)
        self.traffic_dev = lbl("", "kpi-sub")
        tv.append(self.traffic_chart)
        leg = hbox(16)
        leg.append(legend_row([("Descarga", P["s1"]), ("Subida", P["s2"])]))
        leg.append(Gtk.Box(hexpand=True))
        leg.append(self.traffic_dev)
        tv.append(leg)
        tc = card("Tráfico de la interfaz de salida", tv)
        tc.set_hexpand(True)
        row2.append(tc)
        box.append(row2)

        self.chain_box = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=10,
                                     column_spacing=8, row_spacing=8, homogeneous=False)
        box.append(card("Topología de salida", self.chain_box))

        row3 = hbox(12)
        self.alerts_box = vbox(0)
        a = card("Alertas activas", self.alerts_box)
        a.set_hexpand(True)
        row3.append(a)
        self.proc_bars = HBars(color=P["s1"], label_w=130)
        pc = card("Procesos con más conexiones", self.proc_bars)
        pc.set_size_request(420, -1)
        row3.append(pc)
        box.append(row3)

        row4 = hbox(12)
        self.events_chart = Columns(height=120)
        ev = vbox(6)
        ev.append(self.events_chart)
        ev.append(legend_row([("Crítico / alto", P["critical"]), ("Aviso", P["warning"]), ("Info", P["muted"])]))
        e = card("Eventos · últimas 24 h", ev)
        e.set_hexpand(True)
        row4.append(e)
        self.country_bars = HBars(color=P["s1"], label_w=110)
        cc = card("Tiempo por país de salida · 7 días", self.country_bars)
        cc.set_size_request(420, -1)
        row4.append(cc)
        box.append(row4)

    def update_dash(self):
        st = self.data["status"]
        net, obs = st["net"], st.get("obs") or {}
        lw = self.data.get("leakwatch") or {}
        # KPIs
        if net["via_tunnel"].get("ipv4"):
            vpn = obs.get("vpn") or {}
            self.kpi_tunnel.set(vpn.get("label") or ", ".join(net["tunnels"]), f"salida por {net['egress']['ipv4']['dev']}",
                                "good", "Conectado")
        else:
            self.kpi_tunnel.set("Desconectado", f"salida directa por {(net['egress'].get('ipv4') or {}).get('dev')}",
                                "critical", "Sin túnel")
        pub = (st.get("public") or {}).get("default") or {}
        if pub.get("ok"):
            g = pub.get("geo") or {}
            real = pub.get("is_real_ip")
            stx, lab = (("critical", "IP real") if real and pub.get("via_tunnel") else
                        ("good", "IP de la VPN") if pub.get("via_tunnel") else ("serious", "IP real"))
            self.kpi_ip.set(pub["ip"], f"{g.get('country_name') or '?'} · {pub.get('endpoint')} · hace "
                                       f"{int(time.time() - pub['ts'])} s", stx, lab)
        else:
            self.kpi_ip.set("—", pub.get("error") or "pendiente", "neutral", "Sin dato")
        kx = (st.get("killswitch") or {}).get("external") or {}
        rp = kx.get("route_protection") or {}
        if rp:
            ok4 = rp["ipv4"]["state"] == "bloqueado"
            active = ok4 and net["tunnels"]
            self.kpi_ks.set(", ".join(kx.get("declared_by") or []) or "Ninguno",
                            f"si cae el túnel: IPv4 {rp['ipv4']['state']} · IPv6 {rp['ipv6']['state']}",
                            "good" if active else ("serious" if not net["tunnels"] else "critical"),
                            "Activo" if active else "Inactivo")
        d = st.get("dns") or {}
        res = (d.get("encryption") or {}).get("resolvers") or []
        main = res[0] if res else {}
        enc = d.get("encrypted")
        self.kpi_dns.set(main.get("provider") or (main.get("addr") or "—"),
                         ", ".join(f"{r['addr']} {r['transport']}" for r in res)[:60],
                         "good" if enc else ("critical" if enc is False else "neutral"),
                         "Cifrado" if enc else ("En claro" if enc is False else "?"))
        s = st.get("session")
        self.kpi_session.set(fmt_duration(s["duration"]) if s else "—",
                             f"perfil {st['profile']}" + (f" · desde {iso(s['started'])[11:16]}" if s else ""),
                             "neutral", st["profile"])
        # medidor + donut
        ex = st["exposure"]
        self.gauge.set(ex["score"], ex["level"], {"baja": "good", "media": "warning", "alta": "critical"}[ex["level"]])
        sm = lw.get("summary") or {}
        segs = [(VERDICT[k][1], sm.get(n, 0), VERDICT_COLOR[k]) for k, n in
                (("protegida", "protegidas"), ("fuga", "fugas"), ("directa", "directas"), ("permitida", "permitidas"))]
        self.donut.set(segs)
        clear(self.donut_legend)
        self.donut_legend.append(legend([(n, c, str(int(v))) for n, v, c in segs]))
        hint = ("Sin VPN: todas muestran tu IP real" if not lw.get("tunnel_up") and sm.get("directas") else
                "Hay conexiones fuera del túnel" if sm.get("fugas") else "Todo el tráfico va por el túnel")
        self.donut_legend.append(lbl(hint, "kpi-sub", wrap=True))
        # topología
        clear(self.chain_box)
        for chain, tor in ((obs.get("chain") or [], False), (obs.get("tor_chain") or [], True)):
            for h in chain:
                hop = vbox(1)
                hop.add_css_class("hop")
                hop.add_css_class("hop-tor" if tor else ("hop-vpn" if h["type"] == "vpn" else
                                                          "hop-home" if h["type"] in ("device", "router") else "hop"))
                hop.append(lbl(h["type"].replace("tor-", "Tor ").upper(), "card-title"))
                hop.append(lbl(h.get("ip") or h.get("label"), "td-strong", ellipsize=True, width=26))
                hop.append(lbl(" · ".join(str(x) for x in (h.get("country"), h.get("iface")) if x) or " ", "kpi-sub"))
                self.chain_box.append(hop)
        # alertas
        clear(self.alerts_box)
        order = ["critical", "high", "medium", "low", "info"]
        fs = sorted(st.get("findings") or [], key=lambda f: order.index(f["severity"]))
        self.alerts_box.append(table([("Severidad", 0.8), ("Alerta", 2.6), ("Observado", 2.4)],
                                     [[pill(SEV_STATUS[f["severity"]], f["severity"].upper()), f["title"], f["observed"]]
                                      for f in fs], max_rows=8))
        # procesos
        counts = {}
        for f in lw.get("flows") or []:
            counts[f["process"]] = counts.get(f["process"], 0) + 1
        self.proc_bars.set([(p, n, str(n)) for p, n in sorted(counts.items(), key=lambda kv: -kv[1])[:7]])
        # eventos 24 h
        now_ = time.time()
        buckets = [{"label": time.strftime("%H:00", time.localtime(now_ - (24 - i) * 3600)), "crit": 0, "warn": 0,
                    "info": 0} for i in range(24)]
        for e in self.data.get("timeline") or []:
            k = int((e["ts"] - (now_ - 24 * 3600)) // 3600)
            if 0 <= k < 24:
                sev = e["severity"]
                buckets[k]["crit" if sev in ("critical", "high") else
                           "warn" if sev in ("warning", "medium", "low") else "info"] += 1
        self.events_chart.set(buckets, [("info", "Info", P["muted"]), ("warn", "Aviso", P["warning"]),
                                        ("crit", "Crítico / alto", P["critical"])], ("hace 24 h", "ahora"))
        stats = self.data.get("stats") or {}
        merged = {}
        for x in (stats.get("time_by_country") or []) + (stats.get("time_by_tor_country") or []):
            merged[x["label"]] = merged.get(x["label"], 0) + x["seconds"]
        self.country_bars.set([(k, v, fmt_duration_short(v)) for k, v in sorted(merged.items(), key=lambda kv: -kv[1])[:6]])

    # ── páginas ──
    def render_live(self):
        box = self.pages["live"]
        clear(box)
        r = self.data.get("leakwatch") or {}
        if not r:
            return
        s = r.get("summary") or {}
        live = r.get("intel_live") or {}
        row = hbox(12, homogeneous=True)
        for title, val, status, lab in (
                ("Túnel", ", ".join(r.get("tunnels") or []) or "ninguno", "good" if r.get("tunnel_up") else "critical",
                 "Activo" if r.get("tunnel_up") else "Caído"),
                ("Fugas", s.get("fugas", 0), "critical" if s.get("fugas") else "good",
                 "Fuera del túnel" if s.get("fugas") else "Sin fugas"),
                ("Directas", s.get("directas", 0), "serious" if s.get("directas") else "good",
                 "Con tu IP real" if s.get("directas") else "Ninguna"),
                ("Marcadas en VirusTotal", r.get("vt_flagged", 0), "critical" if r.get("vt_flagged") else "good",
                 "Revisar" if r.get("vt_flagged") else "Ninguna")):
            k = KPI(title)
            k.set(val, "", status, lab)
            row.append(k.widget)
        box.append(row)
        rt = self.data.get("routes")
        if rt:
            sk = Sankey()
            sk.set(rt["nodes"], rt["links"])
            inner = vbox(10)
            inner.append(sk)
            inner.append(legend_row([("Por el túnel VPN", P["good"]), ("Directo · IP real", P["serious"]),
                                     ("Proxy", P["s1"]), ("Tor", "#9085e9")]))
            for line in rt.get("explain") or []:
                inner.append(lbl("• " + line, "td", wrap=True))
            guide = Gtk.Expander(label="Cómo encaja un proxy con la VPN y Tor")
            g = vbox(4)
            for t in PROXY_GUIDE:
                g.append(lbl("• " + t, "kpi-sub", wrap=True))
            guide.set_child(g)
            inner.append(guide)
            box.append(card("Cómo viaja tu tráfico ahora (pasa el ratón por las bandas)", inner))
        order = ["fuga", "directa", "otra", "permitida", "protegida"]
        flows = sorted(r.get("flows") or [], key=lambda f: (-(f["vt"] or {}).get("malicious", 0),
                                                             order.index(f["verdict"])))
        rows = []
        for f in flows:
            vt = f.get("vt")
            if vt:
                st = "critical" if vt["malicious"] >= 3 else "warning" if (vt["malicious"] or vt["suspicious"]) else "good"
                vt_cell = pill(st, f"{vt['malicious']}/{vt['total']}")
                vt_cell.set_tooltip_text(f"VirusTotal: {vt['malicious']} maliciosos, {vt['suspicious']} sospechosos de "
                                         f"{vt['total']} motores · reputación {vt.get('reputation')} · {vt.get('as_owner') or ''}")
            else:
                vt_cell = lbl("—", "td")
                vt_cell.set_tooltip_text("Sin puntuación todavía: " + str(live.get("status") or ""))
            geo = f"{cc_flag(f.get('country'))} {f.get('country') or '—'}" + (" 🧅" if f.get("tor") else "")
            geo_l = lbl(geo, "td")
            geo_l.set_tooltip_text(" · ".join(str(x) for x in (f.get("country_name"), f.get("city"), f.get("org"),
                                                               (f"Tor {f['tor']} ({f.get('tor_nick')})" if f.get("tor") else None),
                                                               f"AS{f['asn']}" if f.get("asn") else None) if x)
                                   or "sin datos GeoIP")
            copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copiar IP")
            copy_btn.add_css_class("flat")
            copy_btn.add_css_class("mini")
            copy_btn.connect("clicked", lambda _b, ip=f["remote"]: self.copy(ip, "IP copiada"))
            rows.append([pill(VERDICT[f["verdict"]][0], VERDICT[f["verdict"]][1] + (" DNS" if f["dns"] else "")),
                         f["process"], f"{f['remote']}:{f['rport']}", geo_l, vt_cell, f["iface"] or "?", copy_btn])
        tools = hbox(8)
        cp = Gtk.Button(label="Copiar tabla", tooltip_text="Copia todas las conexiones (TSV, para pegar en una hoja o informe)")
        cp.connect("clicked", lambda *_: self.copy(self._flows_tsv(flows), f"{len(flows)} conexiones copiadas"))
        tools.append(cp)
        ci = Gtk.Button(label="Copiar IPs", tooltip_text="Solo las IPs de destino, una por línea")
        ci.connect("clicked", lambda *_: self.copy("\n".join(dict.fromkeys(f["remote"] for f in flows)), "IPs copiadas"))
        tools.append(ci)
        tools.append(Gtk.Box(hexpand=True))
        tools.append(lbl(f"VirusTotal automático: {live.get('status', '—')} · en cola {live.get('queued', 0)} · "
                         f"hoy {live.get('today', 0)}/{live.get('limit', '—')}", "kpi-sub"))
        inner = vbox(8)
        inner.append(tools)
        inner.append(table([("Veredicto", 0.9), ("Proceso", 1.3), ("Destino", 1.8), ("País", 0.6), ("VirusTotal", 0.8),
                            ("Interfaz", 0.8), ("", 0.2)], rows, max_rows=150))
        box.append(card("Conexiones en tiempo real (cada 2 s) · geolocalización local, sin enviar datos", inner))

    @staticmethod
    def _flows_tsv(flows) -> str:
        head = "veredicto\tproceso\tproto\torigen\tdestino\tpuerto\tpais\tvt_maliciosos\tvt_total\tinterfaz"
        lines = [head]
        for f in flows:
            vt = f.get("vt") or {}
            lines.append("\t".join(str(x if x is not None else "") for x in (
                f["verdict"], f["process"], f["proto"], f"{f['local']}:{f['lport']}", f["remote"], f["rport"],
                f.get("country"), vt.get("malicious"), vt.get("total"), f["iface"])))
        return "\n".join(lines)

    def render_nets(self):
        box = self.pages["nets"]
        clear(box)
        n = self.data.get("networks")
        if not n:
            box.append(lbl(self.data.get("networks_error") or "cargando…"))
            return
        rates = n.get("rates") or {}
        ifs = [i for i in n["interfaces"] if i["category"] != "loopback" and not i["name"].startswith("veth")]
        ifs.sort(key=lambda x: CATEGORY_ORDER.index(x["category"]) if x["category"] in CATEGORY_ORDER else 9)
        rows = []
        for i in ifs:
            r = rates.get(i["name"], {})
            w = i.get("wifi") or {}
            rows.append([i["name"], pill("neutral", i["category"] + ("" if i["up"] else " · caída")), ", ".join(i["subnets"]) or "—",
                         (f"{w['ssid']} · {w['security']} · {w['signal']}%" if w else (i["gateway"] or "—")),
                         f"↓ {human_bps(r.get('rx_bps'))}  ↑ {human_bps(r.get('tx_bps'))}", str(len(i["neighbors"]))])
        box.append(card("Interfaces y redes", table([("Interfaz", 1.2), ("Tipo", 1.2), ("Subred", 1.4),
                                                     ("Red / gateway", 2.2), ("Tráfico", 1.6), ("Vecinos", 0.6)], rows)))
        row = hbox(12)
        neigh = [[x["ip"], x["mac"], x["vendor"] or "desconocido", i["name"],
                  pill("neutral", "gateway") if x["ip"] == i["gateway"] else ""] for i in ifs for x in i["neighbors"]]
        nc = card("Dispositivos vistos (tabla ARP, sin escanear)", table(
            [("IP", 1.1), ("MAC", 1.3), ("Fabricante", 1.8), ("Interfaz", 1), ("", 0.6)], neigh))
        nc.set_hexpand(True)
        row.append(nc)
        if n.get("libvirt") is not None:
            lv = card("Redes de máquinas virtuales", table([("Red", 1.6), ("Forward", 0.8), ("Aislamiento", 1.0)], [
                [v["name"], v["forward"], pill("critical", "NO aislada") if v["isolation_broken"] else
                 pill("good", "Aislada") if v["forward"] == "isolated" else pill("neutral", "Con salida")]
                for v in n["libvirt"]]))
            lv.set_size_request(440, -1)
            row.append(lv)
        box.append(row)
        row = hbox(12)
        if n.get("docker") is not None:
            dc = card("Redes Docker", table([("Red", 1.6), ("Driver", 0.8), ("Bridge", 1.2)],
                                           [[d["name"], d["driver"], d["bridge"] or "—"] for d in n["docker"]]))
            dc.set_hexpand(True)
            row.append(dc)
        kc = card("Redes conocidas (huella SSID + MAC del gateway)", table(
            [("Red", 1.2), ("Subred", 1.2), ("MAC gateway", 1.4), ("Dispositivos", 0.8), ("Última vez", 1.2)],
            [[k["label"], k["subnet"], k["gateway_mac"], str(k["devices"]), iso(k["last"])] for k in n.get("known") or []]))
        kc.set_hexpand(True)
        row.append(kc)
        box.append(row)

    # ── mapa (persistente: conserva zoom y selección entre actualizaciones) ──
    def build_map(self):
        box = self.pages["map"]
        self.mapv = MapView(600, on_select=self.on_map_select)
        self._map_sel = (None, None)
        tools = hbox(6)
        for icon, tip, fn in (("zoom-in-symbolic", "Acercar", lambda: self.mapv.zoom(1.5)),
                              ("zoom-out-symbolic", "Alejar", lambda: self.mapv.zoom(1 / 1.5)),
                              ("zoom-fit-best-symbolic", "Ver el mundo entero", lambda: self.mapv.reset())):
            b = Gtk.Button(icon_name=icon, tooltip_text=tip)
            b.connect("clicked", lambda _b, f=fn: f())
            tools.append(b)
        tools.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        for key, label in (("live", "Conexiones en vivo"), ("chain", "Cadena VPN"), ("tor", "Circuito Tor"),
                           ("history", "Historial"), ("heat", "Tiempo por país")):
            t = Gtk.ToggleButton(label=label, active=self.mapv.layers[key])
            t.connect("toggled", lambda b, k=key: (self.mapv.layers.__setitem__(k, b.get_active()), self.mapv.queue_draw()))
            tools.append(t)
        tools.append(Gtk.Box(hexpand=True))
        tools.append(lbl("Rueda: zoom · arrastrar: mover · doble clic: acercar · clic en un punto: detalle", "kpi-sub"))
        inner = vbox(8)
        inner.append(tools)
        frame = Gtk.Frame(child=self.mapv)
        inner.append(frame)
        inner.append(legend_row([("Fuga", P["critical"]), ("Directa (IP real)", P["serious"]), ("Protegida (túnel)", P["good"]),
                                 ("Cadena VPN", P["s1"]), ("Circuito Tor", "#9085e9"), ("Origen", P["ink"])]))
        box.append(card("Mapa de conexiones", inner))
        self.map_detail = vbox(0)
        box.append(self.map_detail)
        self.map_circuits = vbox(0)
        box.append(card("Circuitos Tor observables", self.map_circuits))
        self.map_note = lbl("", "kpi-sub", wrap=True)
        box.append(self.map_note)
        self._map_circ_sig = None

    def render_map(self):
        m = self.data.get("map") or {}
        flows = (self.data.get("leakwatch") or {}).get("flows") or []
        self.mapv.set_data(m, flows)
        self.map_note.set_text(m.get("note") or "")
        sig = json.dumps(m.get("tor_circuits"), sort_keys=True, default=str)
        if sig != self._map_circ_sig:
            self._map_circ_sig = sig
            clear(self.map_circuits)
            self.map_circuits.append(table(
                [("Circuito", 0.7), ("Streams", 0.5), ("Guard", 1.4), ("Middle", 1.4), ("Exit", 1.4)],
                [[c["id"], str(c["streams"])] + [f"{cc_flag(h['country'])} {h['nick']} ({h['country'] or '?'})"
                                                 for h in c["path"][:3]]
                 for c in (m.get("tor_circuits") or []) if len(c["path"]) >= 3], max_rows=20))
        kind, payload = self._map_sel
        if kind == "cluster":                          # refrescar el grupo seleccionado con los datos nuevos
            key = (round(payload["lat"], 2), round(payload["lon"], 2))
            fresh = next((g for g in self.mapv.clusters() if (round(g["lat"], 2), round(g["lon"], 2)) == key), None)
            if fresh:
                self.mapv.selected = fresh
                self._render_map_detail("cluster", fresh)

    def on_map_select(self, kind, payload):
        self._map_sel = (kind, payload)
        self._render_map_detail(kind, payload)

    def _render_map_detail(self, kind, p):
        clear(self.map_detail)
        if kind is None or kind == "heat" and not p:
            return
        if kind == "cluster":
            flows = sorted(p["flows"], key=lambda f: -MapView.RANK.get(f["verdict"], 0))
            rows = []
            for f in flows:
                vt = f.get("vt")
                vt_cell = (pill("critical" if vt["malicious"] >= 3 else "warning" if (vt["malicious"] or vt["suspicious"])
                                else "good", f"{vt['malicious']}/{vt['total']}") if vt else lbl("—", "td"))
                cb = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copiar IP")
                cb.add_css_class("flat")
                cb.add_css_class("mini")
                cb.connect("clicked", lambda _b, ip=f["remote"]: self.copy(ip, "IP copiada"))
                rows.append([pill(VERDICT[f["verdict"]][0], VERDICT[f["verdict"]][1]), f["process"],
                             f"{f['remote']}:{f['rport']}", f"🧅 {f['tor']}" if f.get("tor") else "—", vt_cell,
                             f.get("org") or "—", cb])
            tools = hbox(8)
            z = Gtk.Button(label="Acercar aquí")
            z.connect("clicked", lambda *_: self.mapv.focus(p["lon"], p["lat"]))
            tools.append(z)
            ci = Gtk.Button(label="Copiar IPs")
            ci.connect("clicked", lambda *_: self.copy("\n".join(dict.fromkeys(f["remote"] for f in flows)), "IPs copiadas"))
            tools.append(ci)
            ct = Gtk.Button(label="Copiar tabla")
            ct.connect("clicked", lambda *_: self.copy(self._flows_tsv(flows), f"{len(flows)} conexiones copiadas"))
            tools.append(ct)
            inner = vbox(8)
            inner.append(tools)
            inner.append(table([("Veredicto", 0.9), ("Proceso", 1.3), ("Destino", 1.7), ("Tor", 0.8), ("VirusTotal", 0.8),
                                ("Organización", 1.6), ("", 0.2)], rows))
            title = f"{cc_flag(p['country'])} {p['name'] or 'Ubicación desconocida'} · {len(flows)} conexiones"
            self.map_detail.append(card(title, inner))
            return
        if kind == "hop":
            pairs = [("Tipo", p.get("type")), ("Nodo", p.get("label")), ("IP", p.get("ip")),
                     ("País", f"{cc_flag(p.get('country'))} {p.get('country') or '?'}"), ("Huella", p.get("fp"))]
        elif kind == "history":
            pairs = [("Capa", p["layer"]), ("Elemento", p["label"]), ("País", f"{cc_flag(p.get('country'))} {p.get('country')}"),
                     ("Desde", iso(p["started"])), ("Hasta", iso(p["ended"]) if p["ended"] else "activo")]
        elif kind == "home":
            pairs = [("Origen", p.get("country")), ("Estimado por", p.get("geo_source"))]
        else:
            pairs = [("País", p.get("name")), ("Tiempo de salida (7 días)", fmt_duration(p.get("seconds")))]
        grid = table([("Campo", 1.0), ("Valor", 3.0)], [[k, v if v is not None else "—"] for k, v in pairs])
        ip = p.get("ip") or (p.get("label") if kind == "history" else None)
        suffix = None
        if ip:
            suffix = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text="Copiar")
            suffix.add_css_class("flat")
            suffix.connect("clicked", lambda *_: self.copy(str(ip), "Copiado"))
        self.map_detail.append(card("Detalle", grid, suffix))

    def render_hist(self):
        box = self.pages["hist"]
        clear(box)
        box.append(card("Sesiones", table(
            [("Inicio", 1.2), ("Duración", 1.0), ("Interfaz", 0.8), ("VPN", 1.4), ("IP pública", 1.2), ("Cierre", 1.4)],
            [[iso(s["started"]), fmt_duration(s["duration"]), s["egress_iface"], s["vpn"] or "—", s["public_ip"] or "—",
              s["end_reason"] or pill("good", "activa")] for s in self.data.get("sessions") or []], max_rows=40)))
        box.append(card("Contadores de tiempo", table(
            [("Elemento", 2.2), ("Capa", 1.0), ("País", 0.5), ("Usos", 0.4), ("Total", 1.0), ("En curso", 1.0)],
            [[c["label"], c["layer"], c["country"] or "—", str(c["uses"]), c["total_fmt"], c.get("current_fmt") or ""]
             for c in self.data.get("counters") or []], max_rows=60)))
        box.append(card("Timeline", table(
            [("Hora", 1.1), ("Severidad", 0.8), ("Evento", 1.4), ("Detalle", 3.2)],
            [[iso(e["ts"]), pill(SEV_STATUS.get(e["severity"], "neutral"), e["severity"]), e["kind"],
              json.dumps(e["data"], ensure_ascii=False)[:140]] for e in self.data.get("timeline") or []], max_rows=80)))

    def render_fix(self):
        box = self.pages["fix"]
        clear(box)
        box.append(lbl("Los comandos no se ejecutan solos: cópialos, revísalos y lánzalos tú.", "kpi-sub"))
        for fx in self.data.get("fixes") or []:
            inner = vbox(6)
            if fx.get("why") or fx.get("finding"):
                inner.append(lbl(fx.get("why") or fx.get("finding"), "kpi-sub", wrap=True))
            for s in fx["steps"]:
                line = hbox(8)
                desc = vbox(3)
                tags = (" · root" if s["root"] else "") + (" · corta la conexión" if s["disruptive"] else "")
                desc.append(lbl(s["desc"] + tags, "td", wrap=True))
                if s.get("cmd"):
                    desc.append(lbl(s["cmd"], "cmd", wrap=True, selectable=True))
                desc.set_hexpand(True)
                line.append(desc)
                if s.get("cmd"):
                    b = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copiar")
                    b.add_css_class("flat")
                    b.connect("clicked", lambda _b, c=s["cmd"]: self.copy(c))
                    line.append(b)
                inner.append(line)
            if fx.get("verify") and fx["verify"] != "—":
                inner.append(lbl(f"Comprobar: {fx['verify']}", "kpi-sub", wrap=True))
            sev = SEV_STATUS.get(fx.get("severity", "info"), "neutral")
            box.append(card(fx["title"], inner, pill(sev, (fx.get("severity") or "info").upper())))

    def render_intel(self):
        from .. import intel as intel_mod
        box = self.pages["intel"]
        clear(box)
        keys = self.data.get("intel_keys") or {}
        stored = intel_mod.load_keys()
        kg = Adw.PreferencesGroup(title="API keys",
                                  description="Escribe la clave y pulsa Intro o ✓ para guardarla. Se guardan solo en este "
                                              f"equipo ({tilde(intel_mod.secrets_path())}, permisos 0600) y nunca se muestran, "
                                              "ni se envían al daemon ni a los logs.")
        for name, title, provider in KEY_ROWS:
            row = Adw.PasswordEntryRow(title=title, show_apply_button=True)
            row.connect("apply", self.on_key_apply, name)
            if name in stored:
                saved = pill("good", "guardada")
                saved.set_valign(Gtk.Align.CENTER)
                row.add_suffix(saved)
                if provider:
                    t = Gtk.Button(label="Probar", valign=Gtk.Align.CENTER, tooltip_text="Consulta 8.8.8.8 con esta clave")
                    t.add_css_class("flat")
                    t.connect("clicked", lambda _b, p=provider: self.call_bg(
                        "intel_test", {"provider": p}, lambda r: self.toast(f"{r['provider']}: {r['detail']}")))
                    row.add_suffix(t)
                d = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Borrar clave")
                d.add_css_class("flat")
                d.connect("clicked", lambda _b, n=name: self.on_key_delete(n))
                row.add_suffix(d)
            kg.add(row)
        box.append(kg)
        row = hbox(12, homogeneous=True)
        for p, stx in (keys.get("providers") or {}).items():
            k = KPI(p)
            ok = not stx.startswith("falta")
            k.set("Configurado" if ok else "Sin clave", stx, "good" if ok else "warning", "Listo" if ok else "Pendiente")
            row.append(k.widget)
        box.append(row)
        bar = hbox(8)
        btn = Gtk.Button(label="Escanear historial")
        btn.add_css_class("suggested-action")
        btn.set_sensitive(bool(keys.get("consent")))
        btn.connect("clicked", lambda *_: self.call_bg("intel_scan", {"background": True},
                                                       lambda r: self.toast(f"Escaneando {r['count']} IPs…")))
        bar.append(btn)
        bar.append(lbl("Las consultas solo salen por VPN o Tor (o sin VPN si lo permites en Ajustes).", "kpi-sub"))
        box.append(bar)
        order = {"malicioso": 0, "expuesto": 1, "sospechoso": 2}
        results = sorted(self.data.get("intel") or [], key=lambda x: order.get(x["verdict"], 9))
        rows = []
        for r in results:
            stx = ("critical" if r["verdict"] in ("malicioso", "expuesto") else
                   "warning" if r["verdict"] == "sospechoso" else "good")
            g = r.get("geo") or {}
            geo = lbl(f"{cc_flag(g.get('country'))} {g.get('country') or '—'}", "td")
            geo.set_tooltip_text(" · ".join(str(x) for x in (g.get("country_name"), g.get("city"),
                                                              f"AS{r['asn']}" if r.get("asn") else None,
                                                              f"fuente: {g.get('source')}" if g.get("source") else None)
                                             if x) or "sin datos GeoIP")
            vt = r.get("vt")
            if vt:
                vst = "critical" if vt["malicious"] >= 3 else "warning" if (vt["malicious"] or vt["suspicious"]) else "good"
                vt_cell = pill(vst, f"{vt['malicious']}/{vt['total']}")
                vt_cell.set_tooltip_text(f"{vt['malicious']} maliciosos, {vt['suspicious']} sospechosos de {vt['total']} "
                                         f"motores · reputación {vt.get('reputation')}")
            else:
                vt_cell = lbl((r["results"].get("virustotal") or {}).get("status") or "—", "td")
            gn = r["results"].get("greynoise") or {}
            ports = r.get("shodan_ports") or []
            sh_txt = (f"{len(ports)} puertos" + (f" · {len(r['shodan_vulns'])} CVE" if r.get("shodan_vulns") else "")
                      if ports else ((r["results"].get("shodan") or {}).get("verdict") or
                                     (r["results"].get("shodan") or {}).get("status") or "—"))
            sh_cell = lbl(sh_txt, "td")
            if ports:
                sh_cell.set_tooltip_text("Puertos: " + ", ".join(map(str, ports[:30])) +
                                         ("\nCVE: " + ", ".join(r["shodan_vulns"][:10]) if r.get("shodan_vulns") else ""))
            copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text="Copiar IP")
            copy_btn.add_css_class("flat")
            copy_btn.add_css_class("mini")
            copy_btn.connect("clicked", lambda _b, ip=r["ip"]: self.copy(ip, "IP copiada"))
            rows.append([r["ip"], geo, tor_pill(r.get("tor")), r.get("org") or "—", pill(stx, r["verdict"]),
                         gn.get("verdict") or gn.get("status") or "—", vt_cell, sh_cell,
                         (r["results"].get("censys") or {}).get("verdict") or "—", copy_btn])
        tools = hbox(8)
        cp = Gtk.Button(label="Copiar tabla", tooltip_text="Todos los resultados en formato tabulado")
        cp.connect("clicked", lambda *_: self.copy(self._intel_tsv(results), f"{len(results)} resultados copiados"))
        tools.append(cp)
        ci = Gtk.Button(label="Copiar IPs")
        ci.connect("clicked", lambda *_: self.copy("\n".join(r["ip"] for r in results), "IPs copiadas"))
        tools.append(ci)
        ex = Gtk.Button(label="Comprobar en ExoneraTor",
                        tooltip_text="Confirma por Tor si cada IP fue relay de Tor (hasta anteayer). El consenso local "
                                     "y la lista oficial de salidas ya se usan siempre, sin consultas por IP")
        ex.connect("clicked", lambda *_: self.call_bg("intel_tor_check", {"background": True}, lambda r: self.toast(
            f"ExoneraTor: comprobando {r['count']} IPs por Tor…")))
        tools.append(ex)
        inner = vbox(8)
        inner.append(tools)
        inner.append(table([("IP", 1.2), ("País", 0.6), ("Tor", 0.7), ("Organización", 1.7), ("Veredicto", 0.9), ("GreyNoise", 0.8),
                            ("VirusTotal", 0.8), ("Shodan", 0.9), ("Censys", 0.6), ("", 0.2)], rows))
        box.append(card("Resultados · geolocalización local", inner))
        box.append(lbl("Los exits de Tor y servidores VPN suelen figurar como maliciosos por el abuso de otros usuarios: "
                       "indica listas de bloqueo, no algo sobre tu tráfico.", "kpi-sub", wrap=True))

    @staticmethod
    def _intel_tsv(results) -> str:
        lines = ["ip\tpais\ttor\torganizacion\tasn\tveredicto\tgreynoise\tvt_maliciosos\tvt_total\tshodan_puertos"]
        for r in results:
            vt = r.get("vt") or {}
            lines.append("\t".join(str(x if x is not None else "") for x in (
                r["ip"], (r.get("geo") or {}).get("country"), (r.get("tor") or {}).get("verdict"), r.get("org"),
                r.get("asn"), r["verdict"],
                (r["results"].get("greynoise") or {}).get("verdict"), vt.get("malicious"), vt.get("total"),
                ",".join(map(str, r.get("shodan_ports") or [])))))
        return "\n".join(lines)

    def on_key_apply(self, row, name):
        from .. import intel as intel_mod
        value = row.get_text().strip()
        row.set_text("")
        if not value:
            return
        try:
            intel_mod.save_key(name, value)
            self.toast(f"Clave de {name} guardada")
        except Exception as e:  # noqa: BLE001
            self.toast(f"No se pudo guardar: {e}")
        self.sig.pop("intel", None)
        self.call_bg("intel_keys", {}, lambda r: (self.data.__setitem__("intel_keys", r), self.render()))

    def on_key_delete(self, name):
        from .. import intel as intel_mod
        intel_mod.delete_key(name)
        self.toast(f"Clave de {name} borrada")
        self.sig.pop("intel", None)
        self.call_bg("intel_keys", {}, lambda r: (self.data.__setitem__("intel_keys", r), self.render()))

    # ── ajustes ──
    def render_settings(self):
        box = self.pages["settings"]
        clear(box)
        s = self.data.get("settings")
        if not s:
            box.append(lbl(self.data.get("settings_error") or "cargando…"))
            return
        v = s["values"]
        auto = s.get("autostart") or {}

        def switch(group, key, title, subtitle, invert=False):
            r = Adw.SwitchRow(title=GLib.markup_escape_text(title), subtitle=GLib.markup_escape_text(subtitle))
            r.set_active(bool(v.get(key)) != invert)
            r.connect("notify::active", lambda row, _p: self.set_setting(key, row.get_active() != invert))
            group.add(r)

        g = Adw.PreferencesGroup(title="Monitorización y persistencia",
                                 description="El historial solo se guarda mientras el daemon está en marcha.")
        ar = Adw.SwitchRow(title="Iniciar con la sesión", subtitle="Servicio de usuario de systemd: monitoriza y guarda el "
                           "historial aunque la app esté cerrada" + ("" if auto.get("available") else " (systemd no disponible)"))
        ar.set_active(bool(auto.get("enabled")))
        ar.set_sensitive(bool(auto.get("available")))
        ar.connect("notify::active", self.on_autostart)
        g.add(ar)
        tr = Adw.SwitchRow(title="Icono en la bandeja del sistema",
                           subtitle="Estado y controles desde la barra superior, también al iniciar sesión")
        tr.set_active(bool(auto.get("tray_autostart")))
        tr.connect("notify::active", self.on_tray)
        g.add(tr)
        switch(g, "public_ip.require_tunnel", "Comprobar la IP pública siempre",
               "Desactivado: solo por la VPN. Activado: también sin VPN (el servicio de eco ve tu IP real)", invert=True)
        switch(g, "leakwatch.enabled", "Vigilante de fugas en tiempo real", "Revisa las conexiones cada 2 s")
        ret = Adw.SpinRow.new_with_range(0, 3650, 1)
        ret.set_title("Retención del historial (días)")
        ret.set_subtitle("0 = sin límite")
        ret.set_value(v.get("storage.retention_days") or 0)
        ret.connect("notify::value", lambda r, _p: self.set_setting("storage.retention_days", int(r.get_value()), quiet=True))
        g.add(ret)
        box.append(g)

        g = Adw.PreferencesGroup(title="Consentimientos",
                                 description="Todo lo que genera tráfico hacia terceros o modifica el sistema.")
        for key, title, sub_ in (
                ("consent.direct_ip_checks", "Consultar la IP pública por la ruta por defecto", "El servicio de eco verá tu IP de salida"),
                ("consent.tor_ip_checks", "Comprobar la IP de salida de Tor", "Vía check.torproject.org a través de Tor"),
                ("consent.threat_intel_lookups", "Threat intel (GreyNoise, VirusTotal, Shodan, Censys)", "Los servicios sabrán qué IPs consultas"),
                ("consent.active_dns_leak_test", "Test activo de fugas DNS", "Un servicio externo verá tus resolvers"),
                ("consent.allow_rotation_changes", "Permitir rotaciones reales", "Cambia conexiones VPN/proxy/Tor de verdad"),
                ("consent.allow_killswitch", "Permitir el kill-switch propio (nftables)", "Necesita sudo sin contraseña o pkexec")):
            switch(g, key, title, sub_)
        box.append(g)

        g = Adw.PreferencesGroup(title="Fugas y threat intel")
        cr = Adw.ComboRow(title="Si se detecta una fuga", subtitle="Aplicar el kill-switch exige el consentimiento de arriba")
        cr.set_model(Gtk.StringList.new(["Solo avisar", "Aplicar el kill-switch"]))
        cr.set_selected(1 if v.get("leakwatch.on_leak") == "killswitch" else 0)
        cr.connect("notify::selected", lambda r, _p: self.set_setting("leakwatch.on_leak",
                                                                       "killswitch" if r.get_selected() == 1 else "alert"))
        g.add(cr)
        switch(g, "intel.auto_live", "Consultar automáticamente en VirusTotal las IPs a las que te conectas",
               "Puntuación en Tiempo real + aviso si es sospechosa. VirusTotal (Google) verá esos destinos")
        nt = Adw.ComboRow(title="Notificar puntuaciones de VirusTotal")
        nt.set_model(Gtk.StringList.new(["Solo sospechosas o maliciosas", "Todas las IPs puntuadas"]))
        nt.set_selected(1 if v.get("intel.live_notify") == "all" else 0)
        nt.connect("notify::selected", lambda r, _p: self.set_setting("intel.live_notify",
                                                                       "all" if r.get_selected() == 1 else "flagged"))
        g.add(nt)
        lim = Adw.SpinRow.new_with_range(0, 5000, 10)
        lim.set_title("Tope diario de consultas automáticas")
        lim.set_subtitle("La API gratuita de VirusTotal permite 500 al día y 4 por minuto")
        lim.set_value(v.get("intel.live_daily_limit") or 400)
        lim.connect("notify::value", lambda r, _p: self.set_setting("intel.live_daily_limit", int(r.get_value()), quiet=True))
        g.add(lim)
        switch(g, "intel.via_tor", "Consultas de threat intel por Tor", "Algunos servicios limitan o bloquean Tor")
        switch(g, "intel.allow_direct", "Permitir consultas sin VPN", "Saldrían desde tu IP real")
        box.append(g)
        box.append(self.map_group())
        box.append(lbl(f"Guardado en {tilde(s['path'])} (no se modifica tu config.toml)", "kpi-sub"))

    # ── mapa OpenStreetMap ──
    MAP_VIA = [("auto", "Automático: Tor y, si no hay, la VPN"), ("tor", "Solo por Tor"), ("vpn", "Solo por la VPN"),
               ("direct", "Directo (tu IP real; solo descarga ficheros públicos del mundo entero)")]

    def map_group(self):
        """Grupo persistente (sobrevive a los redibujados de Ajustes mientras se genera el mapa)."""
        if getattr(self, "_map_grp", None) is not None:
            self._map_status_update()
            return self._map_grp
        g = Adw.PreferencesGroup(
            title="Mapa (OpenStreetMap)",
            description="Mapa propio hecho con datos de OpenStreetMap e incorporado en la app: costas, países, "
                        "capitales y ciudades, con estilo oscuro y más detalle al acercar. Funciona sin conexión: "
                        "mirar el mapa no pide nada a ningún servidor. Actualizarlo es opcional (descarga ≈25 MB).")
        self._map_row = Adw.ActionRow(title="Estado")
        g.add(self._map_row)
        self._map_via = Adw.ComboRow(title="Descargar por")
        self._map_via.set_model(Gtk.StringList.new([t for _, t in self.MAP_VIA]))
        g.add(self._map_via)
        self._map_bar = Gtk.ProgressBar(show_text=True, visible=False, valign=Gtk.Align.CENTER, hexpand=True)
        self._map_btn = Gtk.Button(label="Generar mapa", valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self._map_btn.connect("clicked", lambda _b: self.map_build())
        act = Adw.ActionRow(title="Actualizar con datos recientes de OpenStreetMap",
                            subtitle="Fuentes: osmdata.openstreetmap.de (tierra) y Overpass API (nombres de lugares)")
        act.add_suffix(self._map_bar)
        act.add_suffix(self._map_btn)
        g.add(act)
        self._map_grp = g
        self._map_status_update()
        return g

    def _map_status_update(self):
        st = osmmap.status()
        if st["installed"]:
            self._map_row.set_subtitle(f"En uso: {st['source']} · {st['bytes'] / 1e6:.1f} MB · {st['places']} lugares · "
                                       f"datos de {iso(st['created'])[:10]} · {st['attribution']} (ODbL)")
            self._map_btn.set_label("Actualizar")
        else:
            self._map_row.set_subtitle("No instalado: el mapa usa un contorno básico dibujado a mano")

    def map_build(self):
        import subprocess
        via = self.MAP_VIA[self._map_via.get_selected()][0]
        self._map_btn.set_sensitive(False)
        self._map_bar.set_visible(True)
        self._map_bar.set_fraction(0)
        self._map_bar.set_text("empezando…")
        cmd = [sys.executable, "-m", "vela", "map", "build", "--via", via, "--progress", "--refresh"]

        def work():
            err, res = None, None
            try:
                pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                      cwd=str(Path(__file__).resolve().parents[2]))
                for line in pr.stdout:
                    line = line.rstrip()
                    if line.startswith("progress "):
                        _, f, msg = line.split(" ", 2)
                        GLib.idle_add(lambda f=float(f), m=msg: (self._map_bar.set_fraction(f), self._map_bar.set_text(m),
                                                                False)[-1])
                    elif line.startswith("error "):
                        err = line[6:]
                    elif line.startswith("result "):
                        res = json.loads(line[7:])
                pr.wait()
                if pr.returncode and not err:
                    err = f"código {pr.returncode}"
            except Exception as e:  # noqa: BLE001
                err = str(e)
            GLib.idle_add(self._map_done, err, res)
        threading.Thread(target=work, daemon=True).start()

    def _map_done(self, err, res):
        self._map_btn.set_sensitive(True)
        self._map_bar.set_visible(False)
        if err:
            self.toast(f"No se pudo generar el mapa: {err}")
        else:
            extra = f" (sin nombres: {res['places_error']})" if res and res.get("places_error") else ""
            self.toast(f"Mapa OpenStreetMap listo{extra}")
            self.mapv._base = None
            self.mapv.queue_draw()
        self._map_status_update()
        return False

    def set_setting(self, key, value, quiet=False):
        self.call_bg("settings_set", {"changes": {key: value}},
                     lambda r: (None if quiet else self.toast("Ajuste guardado"),
                                self.call_bg("settings_get", {}, lambda s: self.data.__setitem__("settings", s))))

    def on_tray(self, row, _p):
        from .. import autostart
        if row.get_active():
            autostart.tray_enable()
            self.toast("Icono de bandeja activado")
        else:
            autostart.tray_disable()
            self.toast("Icono de bandeja desactivado")

    def on_autostart(self, row, _p):
        from .. import autostart
        want = row.get_active()

        def work():
            res = autostart.enable() if want else autostart.disable()
            GLib.idle_add(self.toast, ("Arranque con la sesión activado" if want else "Arranque con la sesión desactivado")
                          if res.get("ok") else f"systemd: {res.get('error')}")
            if want:
                ensure_daemon()
        threading.Thread(target=work, daemon=True).start()

    def render_prof(self):
        box = self.pages["prof"]
        clear(box)
        prof = self.data.get("profiles") or {}
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=3, min_children_per_line=1,
                           column_spacing=12, row_spacing=12, homogeneous=True)
        for name, p in (prof.get("profiles") or {}).items():
            inner = vbox(6)
            inner.append(lbl(p.get("description") or "", "kpi-sub", wrap=True))
            tags = hbox(6)
            tags.append(pill("good" if p.get("use_tor") else "neutral", "Tor" if p.get("use_tor") else "sin Tor"))
            tags.append(pill("good" if p.get("require_vpn") else "neutral",
                             "VPN obligatoria" if p.get("require_vpn") else "VPN opcional"))
            tags.append(pill("good" if p.get("require_killswitch") else "neutral", "kill-switch"))
            inner.append(tags)
            inner.append(lbl(f"DNS {p.get('dns_policy')} · retención {p.get('retention_days')} d · prohibidos "
                             f"{', '.join(p.get('forbidden_countries') or []) or '—'}", "td", wrap=True))
            if name == prof.get("active"):
                suffix = pill("good", "Activo")
            else:
                suffix = Gtk.Button(label="Activar")
                suffix.connect("clicked", lambda _b, n=name: self.call_bg("profile_activate", {"name": n}, lambda r: (
                    self.toast(f"Perfil activo: {n}"), self.refresh(full=True))))
            flow.append(card(name, inner, suffix))
        box.append(flow)


class App(Adw.Application):
    def __init__(self, backend=None):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.backend = backend
        self.win = None

    def do_activate(self):
        if self.win is None:
            Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.FORCE_DARK)
            prov = Gtk.CssProvider()
            prov.load_from_string(CSS)
            Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), prov,
                                                      Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)
            # icono de la ventana: el SVG del paquete, visible como «<APP_ID>» para el tema de iconos
            theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
            theme.add_search_path(str(_icon_dir()))
            Gtk.Window.set_default_icon_name(APP_ID)
            if self.backend is None:
                ensure_daemon()
            self.win = Window(self, self.backend or connect())
        self.win.present()


def _icon_dir() -> Path:
    """Carpeta con el icono nombrado como el APP_ID (lo que buscan el tema de iconos y el lanzador)."""
    import shutil
    from ..util import xdg_dir
    d = xdg_dir("data") / "icons"
    d.mkdir(parents=True, exist_ok=True)
    dst = d / f"{APP_ID}.svg"
    if not dst.exists() or dst.stat().st_mtime < ICON.stat().st_mtime:
        shutil.copyfile(ICON, dst)
    return d


DESKTOP = """[Desktop Entry]
Type=Application
Name=VELA
GenericName=Vigilant Egress & Leak Analyst
Comment=Tu identidad de red, siempre en vela: VPN, proxies, Tor, DNS, redes y fugas
Keywords=opsec;vpn;tor;proxy;dns;privacidad;fugas;
Exec={exe} -m vela app
Icon={icon}
Terminal=false
Categories=Network;Security;System;
StartupWMClass=io.github.j0rd1s3rr4n0.Vela
"""


def install_desktop() -> str:
    import os
    p = Path.home() / f".local/share/applications/{APP_ID}.desktop"
    p.parent.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    # icono en el tema de iconos del usuario (hicolor) para el menú de aplicaciones
    import shutil
    icon_dst = Path.home() / f".local/share/icons/hicolor/scalable/apps/{APP_ID}.svg"
    icon_dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ICON, icon_dst)
    p.write_text(DESKTOP.format(exe=f"env PYTHONPATH={root} {sys.executable}", icon=APP_ID))
    os.chmod(p, 0o644)
    return str(p)


def run(backend=None) -> int:
    return App(backend).run([sys.argv[0]])
