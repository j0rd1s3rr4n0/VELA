"""VELA — aplicación nativa GTK 4 + libadwaita (diseño corporativo).

Ventana de escritorio propia (sin navegador ni servidor web): habla con `velad` por el socket UNIX
(o con el motor local si el daemon no está en marcha). Las consultas se hacen en hilos de fondo y la
interfaz se actualiza con GLib.idle_add. El panel de mando usa widgets persistentes que solo cambian
sus datos (sin parpadeo); las demás páginas se reconstruyen solo cuando cambian sus datos.
"""

from __future__ import annotations

from ..i18n import _
from ..i18n import language as i18n_language

import hashlib
import json
import math
import re
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
from .. import (about as about_mod, applaunch, backup as backup_mod, deps, dnsfix, logs, mac as mac_mod, ocr,
                translate)  # noqa: E402
from ..geo import country_label  # noqa: E402
from .. import APP_ID as VELA_APP_ID  # noqa: E402
from ..ipc import connect  # noqa: E402
from ..util import fmt_duration, fmt_duration_short, iso, tilde  # noqa: E402
from .charts import P, STATUS, Columns, Donut, Gauge, HBars, LineChart, Sankey, measure, set_rgb, text  # noqa: E402
from . import theme as theme_mod  # noqa: E402
from .. import themes  # noqa: E402

APP_ID = VELA_APP_ID
DATA = Path(__file__).resolve().parents[1] / "data"
BRAND_DIR = DATA / "brand"
ICON = BRAND_DIR / "vela-app-256.png"          # icono de la app (tesela oscura del Brand Kit)
ICON_SIZES = (16, 24, 32, 48, 64, 128, 256, 512)
SEV_STATUS = {"critical": "critical", "high": "critical", "medium": "serious", "warning": "warning",
              "low": "warning", "info": "info"}
SEV_LABEL = {"critical": _("Crítica"), "high": _("Alta"), "medium": _("Media"), "warning": _("Aviso"), "low": _("Baja"),
             "info": _("Info")}
SEV_ORDER = ["critical", "high", "medium", "warning", "low", "info"]
# Eventos que invalidan el estado visible: la UI vuelve a pedir status/fixes con debounce.
REFRESH_EVENTS = {"finding", "dns_change", "dns_encryption_change", "dns_route_change",
                  "killswitch_change", "network_new", "gateway_mac_change", "rotation",
                  "profile_change", "config_change", "settings_change", "anomaly_detected",
                  "emergency", "emergency_end", "public_ip_change", "wan_ip_change",
                  "tor_available", "tor_unavailable", "direct_exposure", "ip_leak"}


def sev_pill(sev):
    return pill(SEV_STATUS.get(sev, "neutral"), SEV_LABEL.get(sev, str(sev)).upper())
VERDICT = {"fuga": ("critical", _("Fuga")), "directa": ("serious", _("Directa")), "protegida": ("good", _("Protegida")),
           "permitida": ("neutral", _("Permitida")), "otra": ("neutral", _("Otra"))}
# Veredicto → token de red (el color se resuelve al pintar, con el tema activo)
VERDICT_COLOR = {"fuga": "net_leak", "directa": "net_direct", "protegida": "net_protected", "permitida": "info",
                 "otra": "net_unknown"}
# Veredictos de threat intel (identificadores del motor) → (estado, etiqueta). Nada desconocido se muestra como limpio.
INTEL_VERDICT = {"malicioso": ("critical", _("Malicioso")), "expuesto": ("serious", _("Expuesto")),
                 "sospechoso": ("warning", _("Sospechoso")), "limpio": ("good", _("Limpio")),
                 "benigno": ("good", _("Benigno")), "info": ("info", _("Información")),
                 "sin_datos": ("neutral", _("Sin datos")), None: ("neutral", _("No analizado"))}
CATEGORY_ORDER = ["wifi", "lan", "vpn", "bloqueo", "máquinas virtuales", "contenedores", "virtual"]



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


def pill(status: str, label_: str, icon=True):
    """Píldora de estado: icono + texto (el estado nunca depende solo del color). icon=False para etiquetas
    que no son un estado (p. ej. lo que exige un perfil)."""
    glyph = STATUS.get(status, STATUS["neutral"])[0]
    w = lbl(f"{glyph} {label_}" if icon else label_, f"pill pill-{status}")
    w.set_halign(Gtk.Align.START)
    w.set_valign(Gtk.Align.CENTER)
    return w


def card(title: str | None = None, child=None, suffix=None):
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.add_css_class("card")
    if title:
        head = Gtk.Box(spacing=8)
        t = lbl(title.upper(), "card-title", wrap=True)
        t.set_hexpand(True)
        head.append(t)
        if suffix is not None:
            suffix.set_valign(Gtk.Align.START)
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


def _log_detail(entry: dict) -> str:
    """Resumen de una entrada de log para la tabla; el texto completo va en el tooltip."""
    if entry.get("detail") is not None:
        try:
            return json.dumps(entry["detail"], ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return str(entry["detail"])
    parts = []
    if entry.get("type"):
        parts.append(str(entry["type"]))
    if entry.get("exception"):
        parts.append(str(entry["exception"]))
    if entry.get("context"):
        try:
            parts.append(json.dumps(entry["context"], ensure_ascii=False, default=str))
        except (TypeError, ValueError):
            parts.append(str(entry["context"]))
    if entry.get("traceback"):
        parts.append(entry["traceback"].strip().splitlines()[-1])
    return " · ".join(parts)[:500]


def _log_buttons(app, kind: str, entries: list[dict]):
    box = hbox(8)
    copy = Gtk.Button(label=_("Copiar registro"))
    copy.add_css_class("flat")
    copy.connect("clicked", lambda *_ign: app.copy(json.dumps(entries, ensure_ascii=False, indent=2, default=str),
                                                   _("Registro copiado")))
    box.append(copy)
    clear = Gtk.Button(label=_("Vaciar registro"))
    clear.add_css_class("flat")
    clear.add_css_class("destructive-action")
    clear.connect("clicked", lambda *_ign: app._confirm(
        _("¿Vaciar el registro de {kind}?", kind=_("errores") if kind == "errors" else _("auditoría")),
        _("El fichero se borra del disco. No se puede deshacer."),
        lambda: app._log_clear(kind), _("Vaciar"), destructive=True))
    box.append(clear)
    return box


# Identificadores técnicos que se leen mejor en monoespaciada: IPs (con o sin puerto/prefijo), MAC, hashes
TECH_RE = re.compile(r"^(\d{1,3}(\.\d{1,3}){3}(:\d+|/\d+)?|\[?[0-9a-f]*:[0-9a-f]*:[0-9a-f:]*\]?(:\d+|/\d+)?|"
                     r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}|[0-9a-f]{16,64})$", re.I)


def table(columns: list[tuple[str, float]], rows: list[list], max_rows=200, empty=None):
    """Tabla compacta: columns = [(título, peso)], celdas = texto | widget. Las IPs, puertos y MAC
    van en monoespaciada con cifras tabulares; los espaciados salen de la densidad del tema (.cell)."""
    grid = Gtk.Grid(column_spacing=14, row_spacing=0)
    grid.add_css_class("vtable")
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
            css = "td" if j else "td-strong"
            if not isinstance(cell, Gtk.Widget) and cell is not None and TECH_RE.match(str(cell).strip()):
                css += " mono"
            w = cell if isinstance(cell, Gtk.Widget) else lbl(cell, css, ellipsize=True,
                                                               width=int(columns[j][1] * 14))
            w.add_css_class("cell")
            w.set_halign(Gtk.Align.START)
            w.set_valign(Gtk.Align.CENTER)
            if not isinstance(cell, Gtk.Widget):
                w.set_tooltip_text(str(cell))
            grid.attach(w, j, r, 1, 1)
        r += 1
    if not rows:
        grid.attach(lbl(empty or _("sin datos"), "empty", wrap=True), 0, 1, len(columns), 1)
    elif len(rows) > max_rows:
        grid.attach(lbl(_("… y {n} filas más (usa «Copiar tabla» para verlas todas)", n=len(rows) - max_rows), "kpi-hint"),
                    0, r, len(columns), 1)
    return grid


PROXY_GUIDE = [
    _("Las capas se apilan: el proxy decide a QUIÉN envía tu programa el tráfico; la VPN decide POR DÓNDE sale del "
    "equipo. Todo lo que no es loopback (incluido lo que envía un proxy) sigue la ruta del sistema: por el túnel si la "
    "VPN está conectada."),
    _("Proxy LOCAL (en tu equipo: mitmproxy, Burp, privoxy…): solo reenvía. El destino sigue viendo la IP de la VPN (o "
    "tu IP real sin VPN). No añade anonimato, pero ve y puede modificar todo lo que pasa por él."),
    _("Proxy REMOTO por encima de la VPN (tú → VPN → proxy → destino): el destino ve la IP del proxy; el proxy ve la IP "
    "de la VPN, no la tuya; la VPN ve que te conectas al proxy (y su contenido si no va cifrado)."),
    _("Proxy + Tor: «Tor → proxy» (salir de Tor a un proxy) evita bloqueos a exits de Tor, pero ese proxy ve todo y "
    "puede correlacionarte. «Proxy → Tor» (Socks5Proxy/HTTPSProxy en torrc) oculta el uso de Tor a tu red."),
    _("DNS: usa socks5h:// (o torsocks / proxy_dns en proxychains) para que los nombres los resuelva el proxy; con "
    "socks5:// o http sin CONNECT, el DNS sale por tu resolver y revela los dominios."),
    _("Los programas que ignoran el proxy salen «Directo»: el diagrama lo muestra. Con el kill-switch de la VPN, si el "
    "túnel cae, el proxy local también se queda sin salida (no expone tu IP)."),
]


def tor_pill(t):
    """Celda Tor: exit / relay / no, con el detalle de las fuentes en el tooltip."""
    t = t or {}
    v = t.get("verdict")
    w = pill({"exit": "serious", "relay": "warning", "no": "good"}.get(v, "neutral"),
             {"exit": _("Tor exit"), "relay": _("Tor relay"), "no": "No"}.get(v, "?"))
    tip = []
    if t.get("relays"):
        tip.append(_("Relays: ") + ", ".join(f"{r['nick']} ({' '.join(r['flags'][:4])})" for r in t["relays"]))
    tip.append(_("Consenso local: ") + (_("sí") if t.get("consensus") else _("no")))
    tip.append(_("Lista oficial de salidas: ") + (_("sí") if t.get("in_exit_list") else _("no")))
    exo = t.get("exonerator")
    if exo:
        tip.append(_("ExoneraTor ({v1}): ", v1=exo.get('date')) + (exo.get("result") or exo.get("detail") or "—"))
    else:
        tip.append(_("ExoneraTor: no consultado"))
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
    """Leyenda en fila que se reparte en varias líneas si la ventana es estrecha."""
    b = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=len(items), min_children_per_line=1,
                    column_spacing=16, row_spacing=4, halign=Gtk.Align.START)
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

    def set(self, value, sub, status, status_label, tip=None):
        self.value.set_text(str(value))
        self.value.set_tooltip_text(tip or str(value))
        self.sub.set_text(str(sub or ""))
        self.sub.set_tooltip_text(tip or str(sub or ""))
        clear(self.pill_box)
        p = pill(status, status_label)
        if tip:
            p.set_tooltip_text(tip)
            self.widget.set_tooltip_text(tip)
        self.pill_box.append(p)


# Estilo propio del mapa base (oscuro, discreto: los datos van encima)
# Estilo del mapa base: tokens map_* del tema activo (claro u oscuro; los datos van encima)
MAP_STYLE = {"ocean": "map_ocean", "land": "map_land", "coast": "map_coast", "grid": "map_grid",
             "country": "map_label", "city": "map_label_strong", "dot": "map_dot"}
MAP_YTOP = osmmap.lonlat_to_norm(0, 82)[1]
MAP_YBOT = osmmap.lonlat_to_norm(0, -60)[1]
MAP_YSPAN = MAP_YBOT - MAP_YTOP


def reason_label(reason: str) -> str:
    """Motivo de cierre de sesión (identificador guardado en español) en el idioma de la interfaz."""
    if reason.startswith("cambio de "):
        return _("cambio de {what}", what=reason[len("cambio de "):])
    return _(reason)


class MapView(Gtk.DrawingArea):
    """Mapa mundial interactivo (cairo).

    Rueda: zoom centrado en el cursor · arrastrar: desplazar · doble clic: acercar · clic: seleccionar.
    Capas: conexiones en vivo (agrupadas por ubicación), cadena actual, Tor, historial y mapa de calor.
    Los marcadores tienen tamaño fijo en pantalla: al acercar se separan los grupos.

    Mapa base: Web Mercator dibujado con datos de OpenStreetMap preprocesados en local (osmmap), con
    varios niveles de detalle y estilo propio. No pide teselas a ningún servidor mientras lo usas.
    El fondo se dibuja en una imagen en caché; al arrastrar se desplaza la imagen y se redibuja al parar."""

    VCOL = VERDICT_COLOR
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
        key = (w, h, round(self.s, 6), id(bm), self.get_scale_factor(), self._marker_geo(), P.get("_key"))
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
            x, _ign = self.proj(lon, 0, w, h)
            if 0 <= x <= w:
                cr.move_to(round(x) + 0.5, 0)
                cr.line_to(round(x) + 0.5, h)
        for lat in range(-60, 85, step):
            _ign, y = self.proj(0, lat, w, h)
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

        lang = i18n_language()
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
            label = (p.get("names") or {}).get(lang) or p["name"]
            if kind == "country":
                name = label.upper()
                size = 7.5 if z < 3 else 8.5
                tw, th = measure(cr, name, size, True)
                r = (x - tw / 2 - 2, y - th / 2 - 1, x + tw / 2 + 2, y + th / 2 + 1)
                if free(r):
                    taken.append(r)
                    text(cr, x, y, name, size, MAP_STYLE["country"], bold=True, align="center", valign="middle")
                    shown += 1
            else:
                size = 8.0 if kind == "capital" else 7.5
                tw, th = measure(cr, label, size, kind == "capital")
                r = (x - 3, y - th / 2 - 1, x + 6 + tw + 2, y + th / 2 + 1)
                if free(r):
                    taken.append(r)
                    set_rgb(cr, MAP_STYLE["dot"] if kind == "city" else MAP_STYLE["city"])
                    cr.arc(x, y, 2.2 if kind == "capital" else 1.7, 0, 2 * math.pi)
                    cr.fill()
                    text(cr, x + 5, y, label, size, MAP_STYLE["city"] if kind == "capital" else MAP_STYLE["country"],
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
                set_rgb(cr, "series1", 0.13)
                cr.arc(px, py, r, 0, 2 * math.pi)
                cr.fill()
                self.points.append((px, py, r, "heat", x))
        if self.layers["history"]:
            for it in d.get("history") or []:
                px, py = self.proj(it["lon"], it["lat"], w, h)
                set_rgb(cr, "net_tor" if it["layer"].startswith("tor") else "series1", 0.65)
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
                    set_rgb(cr, self.VCOL.get(g["worst"], "muted"), 0.35 if self.selected is not g else 0.9)
                    cr.set_line_width(1.5 if self.selected is not g else 2.5)
                    mx_, my_ = (start[0] + p[0]) / 2, (start[1] + p[1]) / 2 - min(90, math.dist(start, p) * 0.25)
                    cr.move_to(*start)
                    cr.curve_to(mx_, my_, mx_, my_, *p)
                    cr.stroke()
            for g in cl:
                px, py = self.proj(g["lon"], g["lat"], w, h)
                n = len(g["flows"])
                r = 5 + 2.2 * math.sqrt(n)
                set_rgb(cr, "surface")
                cr.arc(px, py, r + 2, 0, 2 * math.pi)
                cr.fill()
                set_rgb(cr, self.VCOL.get(g["worst"], "muted"))
                cr.arc(px, py, r, 0, 2 * math.pi)
                cr.fill()
                if g["vt_bad"]:
                    set_rgb(cr, "net_leak")
                    cr.set_line_width(2)
                    cr.arc(px, py, r + 4, 0, 2 * math.pi)
                    cr.stroke()
                if n > 1:
                    text(cr, px, py, str(n), 7.5, "surface", bold=True, align="center", valign="middle")
                if g["tor"]:
                    text(cr, px + r + 1, py - r - 2, "🧅", 8, "ink", valign="middle")
                if self.s >= 3:
                    text(cr, px, py + r + 3, f"{g['country'] or '?'}", 8, "ink2", align="center")
                self.points.append((px, py, r + 3, "cluster", g))
        for layer, chain, color in (("chain", d.get("chain") or [], "highlight"), ("tor", d.get("tor_chain") or [], "net_tor")):
            if not self.layers[layer]:
                continue
            prev = start
            for hop in chain:
                if hop.get("lat") is None:
                    continue
                p = self.proj(hop["lon"], hop["lat"], w, h)
                c = "net_protected" if hop["type"] == "vpn" else color
                if prev and math.dist(prev, p) > 2:
                    set_rgb(cr, c, 0.95)
                    cr.set_line_width(2.5)
                    cr.set_dash([6, 4])
                    mx_, my_ = (prev[0] + p[0]) / 2, (prev[1] + p[1]) / 2 - min(70, math.dist(prev, p) * 0.3)
                    cr.move_to(*prev)
                    cr.curve_to(mx_, my_, mx_, my_, *p)
                    cr.stroke()
                    cr.set_dash([])
                set_rgb(cr, "surface")
                cr.rectangle(p[0] - 6, p[1] - 6, 12, 12)
                cr.fill()
                set_rgb(cr, c)
                cr.rectangle(p[0] - 4.5, p[1] - 4.5, 9, 9)
                cr.fill()
                self.points.append((p[0], p[1], 9, "hop", hop))
                prev = p
        if start:
            set_rgb(cr, "ink")
            cr.arc(start[0], start[1], 5, 0, 2 * math.pi)
            cr.fill()
            set_rgb(cr, "surface")
            cr.arc(start[0], start[1], 2, 0, 2 * math.pi)
            cr.fill()
            self.points.append((start[0], start[1], 9, "home", home))
        z = self.zoom_level(w, h)
        text(cr, w - 8, h - 6, f"zoom {z:.1f} · ×{self.s:.1f}", 8, "muted", align="right", valign="bottom")
        note = (osmmap.ATTRIBUTION if osmmap.load() else
                _("Mapa básico · genera el mapa OpenStreetMap en Ajustes → Mapa"))
        tw, th = measure(cr, note, 7.5)
        set_rgb(cr, MAP_STYLE["ocean"], 0.8)
        cr.rectangle(0, h - th - 6, tw + 14, th + 6)
        cr.fill()
        text(cr, 7, h - 3, note, 7.5, "muted", valign="bottom")

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
            return (f"{cc_flag(p['country'])} {p['name'] or '?'} · {len(p['flows'])} conexiones\n"
                    + " · ".join(f"{k}: {v}" for k, v in verd.items()) + "\n"
                    + _("Programas: {names}", names=", ".join(f"{k} ({v})" for k, v in sorted(procs.items(), key=lambda kv: -kv[1])[:5]))
                    + "\nIPs: " + ", ".join(ips[:5]) + (" …" if len(ips) > 5 else "")
                    + (_("\n🧅 {tor} conexiones a nodos Tor", tor=p['tor']) if p["tor"] else "")
                    + (_("\n⚠ {vt_bad} marcadas en VirusTotal", vt_bad=p['vt_bad']) if p["vt_bad"] else "")
                    + _("\nClic para ver el detalle"))
        if kind == "hop":
            return _("{type}: {v2}\n{v4} · {v6} (ubicación estimada)", type=p['type'], v2=p.get('label'), v4=p.get('ip') or '', v6=p.get('country') or '?')
        if kind == "history":
            return f"{p['layer']}: {p['label']} ({p.get('country') or '?'})\n{iso(p['started'])} → " \
                   f"{iso(p['ended']) if p['ended'] else _('activo')}"
        if kind == "heat":
            return _("{name}: {duration} de salida (7 días)", name=p['name'], duration=fmt_duration(p['seconds']))
        if kind == "home":
            return _("Tu origen (estimado por {v1})", v1=p.get('geo_source'))
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


class ThemePreview(Gtk.DrawingArea):
    """Miniatura de un tema dibujada con SUS tokens reales (en el modo claro/oscuro en uso): fondo, barra
    lateral con un elemento seleccionado, tarjeta, texto, botón principal y estados ✔ ▲ ✖."""

    def __init__(self, theme_id):
        super().__init__()
        self.theme_id = theme_id
        self.set_content_width(170)
        self.set_content_height(96)
        self.set_draw_func(self._draw)

    def _draw(self, _a, cr, w, h):
        t = themes.tokens(self.theme_id, P.get("_dark", True))

        def rect(x, y, ww, hh, c, r=4):
            set_rgb(cr, c)
            cr.new_sub_path()
            cr.arc(x + ww - r, y + r, r, -math.pi / 2, 0)
            cr.arc(x + ww - r, y + hh - r, r, 0, math.pi / 2)
            cr.arc(x + r, y + hh - r, r, math.pi / 2, math.pi)
            cr.arc(x + r, y + r, r, math.pi, 1.5 * math.pi)
            cr.close_path()
            cr.fill()
        rect(0, 0, w, h, t["border"], 8)
        rect(1, 1, w - 2, h - 2, t["bg"], 7)
        set_rgb(cr, t["sidebar"])
        cr.rectangle(1, 1, 42, h - 2)
        cr.fill()
        rect(6, 14, 32, 9, t["selected"], 3)
        set_rgb(cr, t["accent_text"])
        cr.rectangle(6, 14, 2, 9)
        cr.fill()
        for i in range(3):
            rect(10, 30 + i * 11, 22, 4, t["muted"], 2)
        rect(52, 10, w - 60, h - 20, t["border"], 6)
        rect(53, 11, w - 62, h - 22, t["surface"], 5)
        text(cr, 61, 16, "VELA", 8.5, t["ink"], bold=True)
        rect(61, 33, 58, 4, t["ink2"], 2)
        rect(61, 41, 40, 4, t["muted"], 2)
        rect(w - 56, 15, 40, 14, t["accent"], 4)
        text(cr, w - 36, 22, "OK", 7, t["accent_fg"], bold=True, align="center", valign="middle")
        for i, (icon, tok) in enumerate((("✔", "success"), ("▲", "warning"), ("✖", "danger"))):
            x = 61 + i * 30
            set_rgb(cr, over_tint(t[tok], t["surface"]))
            rect(x, 56, 26, 14, over_tint(t[tok], t["surface"]), 7)
            text(cr, x + 13, 63, icon, 7, t[tok], bold=True, align="center", valign="middle")


def over_tint(c, bg):
    return themes.over(c, themes.PILL_ALPHA, bg)


class Wordmark(Gtk.DrawingArea):
    """Logotipo «VELA» del Brand Kit a un ancho fijo (nítido en HiDPI): versión clara u oscura según el tema."""

    _cache: dict = {}

    def __init__(self, width):
        super().__init__(halign=Gtk.Align.START)
        self.set_content_width(width)
        self.set_content_height(round(width * 101 / 600))
        self.set_draw_func(self._draw)
        self.update_property([Gtk.AccessibleProperty.LABEL], ["VELA"])

    def _draw(self, _a, cr, w, h):
        name = "vela-wordmark-on-dark.png" if P.get("_dark", True) else "vela-wordmark-on-light.png"
        img = self._cache.get(name)
        if img is None:
            img = self._cache[name] = cairo.ImageSurface.create_from_png(str(BRAND_DIR / name))
        k = min(w / img.get_width(), h / img.get_height())
        cr.scale(k, k)
        cr.set_source_surface(img, 0, (h / k - img.get_height()) / 2)
        cr.get_source().set_filter(cairo.FILTER_GOOD)
        cr.paint()


# ── ventana ─────────────────────────────────────────────────────────────────

PAGES = [("dash", _("Panel de mando"), "utilities-system-monitor-symbolic"),
         ("live", _("Tiempo real"), "network-transmit-receive-symbolic"),
         ("nets", _("Redes"), "network-wired-symbolic"),
         ("map", _("Mapa"), "mark-location-symbolic"),
         ("hist", _("Historial"), "document-open-recent-symbolic"),
         ("fix", _("Alertas y acciones"), "dialog-warning-symbolic"),
         ("intel", _("Threat intel"), "security-high-symbolic"),
         ("prof", _("Perfiles"), "system-users-symbolic"),
         ("tools", _("Utilidades"), "applications-utilities-symbolic"),
         ("errors", _("Errores"), "dialog-error-symbolic"),
         ("settings", _("Ajustes"), "emblem-system-symbolic"),
         ("about", _("Acerca de"), "help-about-symbolic")]
KEY_ROWS = [("virustotal", "VirusTotal", "virustotal"), ("shodan", _("Shodan"), "shodan"),
            ("greynoise", _("GreyNoise (opcional: sin clave usa la API comunitaria)"), "greynoise"),
            ("censys_token", _("Censys · token de la Platform"), "censys"),
            ("censys_org", _("Censys · ID de organización (opcional)"), None)]


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
        self._refresh_timer = None

        # barra lateral
        side = vbox(0)
        brand = hbox(10)
        brand.set_margin_top(4)
        brand.set_margin_start(16)
        brand.set_margin_bottom(14)
        brand.set_tooltip_text(f"VELA · {ACRONYM}\n{_(TAGLINE)}")
        logo = Gtk.Image.new_from_file(str(BRAND_DIR / "vela-symbol-128.png"))
        logo.set_pixel_size(36)
        logo.set_accessible_role(Gtk.AccessibleRole.PRESENTATION)
        brand.append(logo)
        names = vbox(3)
        names.set_valign(Gtk.Align.CENTER)
        self.wordmark = Wordmark(76)
        names.append(self.wordmark)
        sub = lbl(ACRONYM, "brand-sub", wrap=True)
        sub.set_max_width_chars(22)
        names.append(sub)
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
        self.side_status = lbl("", "side-status", wrap=True)
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
        for key, _title, _ign in PAGES:
            box = vbox(12)
            self.pages[key] = box
            self.stack.add_named(scroller(box), key)
        header = Adw.HeaderBar()
        self.title = lbl(_("Panel de mando"), "page-title")
        header.set_title_widget(self.title)
        self.profile_dd = Gtk.DropDown(tooltip_text=_("Perfil OPSEC activo"))
        self._profiles = []
        self._profile_handler = self.profile_dd.connect("notify::selected", self.on_profile)
        header.pack_start(self.profile_dd)
        self.head_pill = hbox(0)
        header.pack_start(self.head_pill)
        panic = Gtk.Button(tooltip_text=_("Modo de emergencia: detiene las rotaciones y, si lo permites, bloquea "
                                          "las conexiones no verificadas. Pide confirmación."))
        pc = hbox(6)
        pc.append(Gtk.Image.new_from_icon_name("dialog-warning-symbolic"))
        pc.append(Gtk.Label(label=_("Emergencia")))
        panic.set_child(pc)
        panic.add_css_class("destructive-action")
        panic.add_css_class("emergency")
        panic.connect("clicked", self.on_panic)
        header.pack_end(panic)
        ref = Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text=_("Actualizar"))
        ref.connect("clicked", lambda *_ign: self.refresh(full=True))
        header.pack_end(ref)
        self.toasts = Adw.ToastOverlay(child=self.stack)
        content_tv = Adw.ToolbarView()
        content_tv.add_top_bar(header)
        self.banner = Adw.Banner(title=_("MODO EMERGENCIA ACTIVO · rotaciones detenidas"), button_label="Reanudar")
        self.banner.connect("button-clicked", lambda *_ign: self.call_bg("resume", {}, lambda r: self.toast(_("Emergencia desactivada"))))
        content_tv.add_top_bar(self.banner)
        content_tv.set_content(self.toasts)
        content_tv.add_css_class("content-bg")

        split = Adw.NavigationSplitView(min_sidebar_width=210, max_sidebar_width=240)
        split.set_sidebar(Adw.NavigationPage(child=side_tv, title="VELA"))
        split.set_content(Adw.NavigationPage(child=content_tv, title=_("Panel")))
        self.set_content(split)

        self.build_dash()
        self.build_map()
        self.build_tools()
        self.build_about()
        self.themes = app.themes
        self.themes.listeners.append(self.on_theme)
        self.on_theme(self.themes.tokens, self.themes.dark)
        keys = [k for k, _ign, _ign in PAGES]
        start = keys.index(self.state["page"]) if self.state.get("page") in keys else 0
        self.nav.select_row(self.nav.get_row_at_index(start))
        GLib.timeout_add_seconds(4, lambda: (self.refresh(), True)[1])
        GLib.timeout_add_seconds(2, self._fast)
        GLib.timeout_add_seconds(1, self._clock)
        self.refresh(full=True)
        threading.Thread(target=self._events, daemon=True).start()

    def on_theme(self, _tokens, dark):
        """Tema aplicado (al arrancar, al elegirlo en Ajustes o al cambiar el escritorio de claro a oscuro)."""
        theme_mod.redraw_tree(self)           # los widgets ya cambian con la CSS; cairo necesita redibujar

    def _save_state(self, *_ign):
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
        self.title.set_text(dict((k, t) for k, t, _ign in PAGES)[row.key])
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
                logs.error(_("error en la interfaz"), e, {"method": method})
                GLib.idle_add(self.toast, f"Error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def refresh(self, full=False, force_slow=False):
        if self.busy:
            return
        if force_slow:
            self.data["_slow"] = 0
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
                        logs.error(_("error al cargar rutas"), e)
                        d["routes_error"] = str(e)
                d["leakwatch"] = self.b.call("leakwatch")
                if full or force_slow or time.monotonic() - self.data.get("_slow", 0) > 20:
                    for k, m, p in (("networks", "networks", {}), ("map", "map", {}), ("sessions", "sessions", {"limit": 80}),
                                    ("counters", "counters", {}), ("timeline", "timeline", {"limit": 600}),
                                    ("fixes", "fixes", {}), ("profiles", "profiles", {}), ("intel", "intel_results", {}),
                                    ("intel_keys", "intel_keys", {}), ("stats", "stats", {"period": "week"}),
                                    ("anomalies", "anomalies", {}), ("data_info", "data_info", {}),
                                    ("logs", "logs", {"limit": 300}), ("settings", "settings_get", {})):
                        try:
                            d[k] = self.b.call(m, **p)
                        except Exception as e:  # noqa: BLE001
                            d[k + "_error"] = str(e)
                    d["_slow"] = time.monotonic()
            except Exception as e:  # noqa: BLE001
                logs.error(_("error al actualizar la interfaz"), e)
                d["error"] = str(e)
            GLib.idle_add(self._apply, d)
        threading.Thread(target=work, daemon=True).start()

    def _apply(self, d):
        self.busy = False
        self.data.update(d)
        self.render()
        return False

    def refresh_after(self, domains=None, message=None):
        """Invalida el motor y recarga la UI tras una acción que cambia el sistema."""
        def work():
            try:
                self.b.call("refresh", domains=list(domains or ["all"]))
            except Exception as e:  # noqa: BLE001
                logs.error(_("error al refrescar el estado"), e, {"domains": list(domains or ["all"])})
                GLib.idle_add(self.toast, _("No se pudo refrescar: {e}", e=e))

            def finish():
                self.data["_slow"] = 0
                self.sig.clear()
                self._tools_checked = 0
                self.busy = False
                if message:
                    self.toast(message)
                self.refresh(full=True, force_slow=True)
                return False
            GLib.idle_add(finish)
        threading.Thread(target=work, daemon=True).start()

    def refresh_ui(self, message=None):
        """Recarga la UI cuando el motor ya invalidó su estado (acciones del daemon)."""
        self.data["_slow"] = 0
        self.sig.clear()
        self._tools_checked = 0
        self.busy = False
        if message:
            self.toast(message)
        self.refresh(full=True, force_slow=True)

    def _queue_refresh(self):
        """Un solo refresco diferido para ráfagas de eventos (netlink, DNS, fugas…)."""
        if self._refresh_timer is not None:
            return False
        self._refresh_timer = GLib.timeout_add(1200, self._do_queued_refresh)
        return False

    def _do_queued_refresh(self):
        self._refresh_timer = None
        self.refresh(full=True, force_slow=True)
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
                    _ign, t0, rx0, tx0 = self._last_counters
                    dt = max(0.1, t - t0)
                    self.traffic["rx"].append(max(0, (rx - rx0) / dt))
                    self.traffic["tx"].append(max(0, (tx - tx0) / dt))
                self._last_counters = (dev, t, rx, tx)
                span = len(self.traffic["rx"]) * 2
                self.traffic_chart.set([(_("Descarga"), "series1", list(self.traffic["rx"])),
                                        (_("Subida"), "series2", list(self.traffic["tx"]))],
                                       (_("hace {m} min {s} s", m=span // 60, s=span % 60) if span >= 60 else _("hace {s} s", s=span), _("ahora")))
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
                if ev.get("kind") in REFRESH_EVENTS:
                    GLib.idle_add(self._queue_refresh)
        except Exception as e:  # noqa: BLE001
            logs.error(_("error en el flujo de eventos"), e)

    def _notify(self, ev):
        from .. import notifications
        if not notifications.allowed():
            return False
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

            def done(_r):
                self.refresh_ui(_("Perfil activo: {name}", name=name))
                return False
            self.call_bg("profile_activate", {"name": name}, done)

    def on_panic(self, *_ign):
        dlg = Adw.AlertDialog(heading=_("¿Activar el modo de emergencia?"),
                              body=_("Detiene las rotaciones y, si está permitido, bloquea las conexiones no verificadas. "
                                   "No borra datos ni cambia la configuración."))
        dlg.add_response("cancel", _("Cancelar"))
        dlg.add_response("panic", _("Activar"))
        dlg.set_response_appearance("panic", Adw.ResponseAppearance.DESTRUCTIVE)
        def go(_d, r):
            if r != "panic":
                return

            def done(res):
                self.refresh_ui(_("Emergencia activa · kill-switch ") +
                                (_("aplicado") if res["killswitch"].get("ok") else _("no aplicado")))
                return False
            self.call_bg("panic", {}, done)
        dlg.connect("response", go)
        dlg.present(self)

    # ── render común ──
    def render(self):
        st = self.data.get("status")
        if not st:
            return
        ex = st["exposure"]
        stx = {"baja": "good", "media": "warning", "alta": "critical"}[ex["level"]]
        clear(self.head_pill)
        self.head_pill.append(pill(stx, _("Exposición {score}/100", score=ex['score'])))
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
        self.side_status.set_text(f"{_('daemon conectado') if getattr(self.b, 'remote', False) else _('motor local')}\n"
                                  + _("actualizado {t}", t=time.strftime('%H:%M:%S')))
        page = self.current()
        if page == "dash":
            self.update_dash()
            return
        if page == "map":
            self.render_map()
            return
        if page == "tools":
            self.render_tools()
            return
        if page == "errors":
            self.render_errors()
            return
        if page == "about":
            self.render_about()
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
        # franja de estado general: lo primero que se lee (icono + titular + motivos; nunca solo color)
        self.strip = hbox(12)
        self.strip.add_css_class("card")
        self.strip.add_css_class("callout")
        self.strip_icon = Gtk.Image(pixel_size=22, valign=Gtk.Align.CENTER)
        self.strip.append(self.strip_icon)
        st_txt = vbox(2)
        self.strip_title = lbl("", "kpi-value", wrap=True)
        self.strip_detail = lbl("", "kpi-sub", wrap=True)
        st_txt.append(self.strip_title)
        st_txt.append(self.strip_detail)
        st_txt.set_hexpand(True)
        self.strip.append(st_txt)
        self.strip_pill = hbox(0)
        self.strip_pill.set_valign(Gtk.Align.CENTER)
        self.strip.append(self.strip_pill)
        box.append(self.strip)
        row1 = hbox(12, homogeneous=True)
        self.kpi_tunnel, self.kpi_ip, self.kpi_ks, self.kpi_dns, self.kpi_session = (
            KPI(_("Túnel VPN")), KPI(_("IP pública")), KPI(_("Kill-switch")), KPI(_("DNS")), KPI(_("Sesión actual")))
        for k in (self.kpi_tunnel, self.kpi_ip, self.kpi_ks, self.kpi_dns, self.kpi_session):
            row1.append(k.widget)
        box.append(row1)

        row2 = hbox(12)
        self.gauge = Gauge()
        g = card(_("Exposición observable"), self.gauge)
        g.set_size_request(250, -1)
        row2.append(g)
        dn = hbox(14)
        self.donut = Donut(_("conexiones"))
        self.donut.set_size_request(150, 150)
        self.donut.set_hexpand(False)
        dn.append(self.donut)
        self.donut_legend = vbox(4)
        self.donut_legend.set_valign(Gtk.Align.CENTER)
        self.donut_legend.set_hexpand(True)
        dn.append(self.donut_legend)
        c = card(_("Conexiones a Internet ahora"), dn)
        c.set_size_request(330, -1)
        row2.append(c)
        tv = vbox(6)
        self.traffic_chart = LineChart(height=140, fmt=human_bps)
        self.traffic_dev = lbl("", "kpi-sub")
        tv.append(self.traffic_chart)
        leg = hbox(16)
        leg.append(legend_row([(_("Descarga"), "series1"), (_("Subida"), "series2")]))
        leg.append(Gtk.Box(hexpand=True))
        leg.append(self.traffic_dev)
        tv.append(leg)
        tc = card(_("Tráfico de la interfaz de salida"), tv)
        tc.set_hexpand(True)
        row2.append(tc)
        box.append(row2)

        self.chain_box = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=10,
                                     column_spacing=8, row_spacing=8, homogeneous=False)
        box.append(card(_("Topología de salida"), self.chain_box))

        row3 = hbox(12)
        self.alerts_box = vbox(0)
        a = card(_("Alertas activas"), self.alerts_box)
        a.set_hexpand(True)
        row3.append(a)
        self.proc_bars = HBars(color="series1", label_w=130)
        pc = card(_("Procesos con más conexiones"), self.proc_bars)
        pc.set_size_request(420, -1)
        row3.append(pc)
        box.append(row3)
        self.anom_box = vbox(0)
        box.append(card(_("Anomalías de red · línea base"), self.anom_box))

        row4 = hbox(12)
        self.events_chart = Columns(height=120)
        ev = vbox(6)
        ev.append(self.events_chart)
        ev.append(legend_row([(_("Crítico / alto"), "danger"), (_("Aviso"), "warning"), (_("Info"), "muted")]))
        e = card(_("Eventos · últimas 24 h"), ev)
        e.set_hexpand(True)
        row4.append(e)
        self.country_bars = HBars(color="series1", label_w=110)
        cc = card(_("Tiempo por país de salida · 7 días"), self.country_bars)
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
            self.kpi_tunnel.set(vpn.get("label") or ", ".join(net["tunnels"]), _("salida por {dev}", dev=net['egress']['ipv4']['dev']),
                                "good", _("Conectado"))
        else:
            self.kpi_tunnel.set(_("Desconectado"), _("salida directa por {v1}", v1=(net['egress'].get('ipv4') or {}).get('dev')),
                                "critical", _("Sin túnel"))
        pub = (st.get("public") or {}).get("default") or {}
        if pub.get("ok"):
            g = pub.get("geo") or {}
            real = pub.get("is_real_ip")
            stx, lab = (("critical", _("IP real")) if real and pub.get("via_tunnel") else
                        ("good", _("IP de la VPN")) if pub.get("via_tunnel") else ("serious", _("IP real")))
            self.kpi_ip.set(pub["ip"], _("{country} · {endpoint} · hace {s} s", country=g.get('country_name') or '?',
                                         endpoint=pub.get('endpoint'), s=int(time.time() - pub['ts'])), stx, lab)
        else:
            self.kpi_ip.set("—", pub.get("error") or _("pendiente"), "neutral", _("Sin dato"))
        kx = (st.get("killswitch") or {}).get("external") or {}
        rp = kx.get("route_protection") or {}
        if rp:
            ok4 = rp["ipv4"]["state"] == "bloqueado"
            active = ok4 and net["tunnels"]
            self.kpi_ks.set(", ".join(kx.get("declared_by") or []) or _("Ninguno"),
                            _("si cae el túnel: IPv4 {state} · IPv6 {state2}", state=_(rp['ipv4']['state']), state2=_(rp['ipv6']['state'])),
                            "good" if active else ("serious" if not net["tunnels"] else "critical"),
                            _("Activo") if active else _("Inactivo"))
        d = st.get("dns") or {}
        res = (d.get("encryption") or {}).get("resolvers") or []
        main = res[0] if res else {}
        enc = d.get("encrypted")
        self.kpi_dns.set(main.get("provider") or (main.get("addr") or "—"),
                         ", ".join(f"{r['addr']} {r['transport']}" for r in res)[:60],
                         "good" if enc else ("critical" if enc is False else "neutral"),
                         _("Cifrado") if enc else (_("En claro") if enc is False else "?"))
        s = st.get("session")
        self.kpi_session.set(fmt_duration(s["duration"]) if s else "—",
                             _("perfil {profile}", profile=st['profile']) + (_(" · desde {t}", t=iso(s['started'])[11:16]) if s else ""),
                             "neutral", st["profile"])
        self._update_strip(st, lw)
        # medidor + donut
        ex = st["exposure"]
        self.gauge.set(ex["score"], ex["level"], {"baja": "good", "media": "warning", "alta": "critical"}[ex["level"]])
        sm = lw.get("summary") or {}
        segs = [(VERDICT[k][1], sm.get(n, 0), VERDICT_COLOR[k]) for k, n in
                (("protegida", "protegidas"), ("fuga", "fugas"), ("directa", "directas"), ("permitida", "permitidas"))]
        self.donut.set(segs)
        clear(self.donut_legend)
        self.donut_legend.append(legend([(n, c, str(int(v))) for n, v, c in segs]))
        hint = (_("Sin VPN: todas muestran tu IP real") if not lw.get("tunnel_up") and sm.get("directas") else
                _("Hay conexiones fuera del túnel") if sm.get("fugas") else _("Todo el tráfico va por el túnel"))
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
        self.alerts_box.append(table([(_("Severidad"), 0.8), (_("Alerta"), 2.6), (_("Observado"), 2.4)],
                                     [[sev_pill(f["severity"]), f["title"], f["observed"]]
                                      for f in fs], max_rows=8))
        clear(self.anom_box)
        anoms = self.data.get("anomalies") or []
        if anoms:
            self.anom_box.append(table([(_("Tipo"), 1.4), (_("Severidad"), 0.8), (_("Detalle"), 4.2)],
                                       [[a.get("type", ""), sev_pill(a.get("severity", "info")), a.get("detail", "")]
                                        for a in anoms], max_rows=8))
        else:
            self.anom_box.append(lbl(_("Sin anomalías en la ventana analizada. La línea base se construye con las "
                                       "muestras del daemon."), "kpi-sub", wrap=True))
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
        self.events_chart.set(buckets, [("info", "Info", "muted"), ("warn", "Aviso", "warning"),
                                        ("crit", _("Crítico / alto"), "danger")], (_("hace 24 h"), _("ahora")))
        stats = self.data.get("stats") or {}
        merged = {}
        for x in (stats.get("time_by_country") or []) + (stats.get("time_by_tor_country") or []):
            name = country_label(x.get("key"), x["label"]) if len(str(x.get("key") or "")) == 2 else x["label"]
            merged[name] = merged.get(name, 0) + x["seconds"]
        self.country_bars.set([(k, v, fmt_duration_short(v)) for k, v in sorted(merged.items(), key=lambda kv: -kv[1])[:6]])

    def _update_strip(self, st, lw):
        """Resumen del estado con los datos del motor (no reclasifica nada): fugas > directas > túnel."""
        net = st["net"]
        sm = lw.get("summary") or {}
        nf, nd = sm.get("fugas", 0), sm.get("directas", 0)
        up = bool(net["via_tunnel"].get("ipv4"))
        ex = st["exposure"]
        enc = (st.get("dns") or {}).get("encrypted")
        dns_txt = _("DNS cifrado") if enc else (_("DNS en claro") if enc is False else _("DNS sin verificar"))
        if nf:
            stx, icon = "critical", "dialog-error-symbolic"
            title = _("Fugas: {n} conexiones esquivan la VPN", n=nf)
        elif not up and nd:
            stx, icon = "serious", "dialog-warning-symbolic"
            title = _("Sin VPN: {n} conexiones muestran tu IP real", n=nd)
        elif not up:
            stx, icon = "warning", "dialog-warning-symbolic"
            title = _("Sin VPN: tu tráfico sale con tu IP real")
        else:
            stx, icon = "good", "security-high-symbolic"
            title = _("El tráfico observado sale por el túnel")
        detail = " · ".join([_("Exposición {score}/100 ({level})", score=ex["score"], level=_(ex["level"])), dns_txt,
                             _("{n} alertas activas", n=sum(1 for f in st.get("findings") or [] if f["status"] == "fail"))])
        if stx == "good":
            detail += " · " + _("indicador de lo observable: no mide anonimato")
        for c in ("callout-good", "callout-warning", "callout-serious", "callout-critical"):
            self.strip.remove_css_class(c)
        self.strip.add_css_class(f"callout-{stx}")
        self.strip_icon.set_from_icon_name(icon)
        self.strip_title.set_text(title)
        self.strip_detail.set_text(detail)
        clear(self.strip_pill)
        self.strip_pill.append(pill(stx, {"critical": _("Fuga"), "serious": _("IP real expuesta"),
                                          "warning": _("Sin túnel"), "good": _("Túnel activo")}[stx]))

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
        nf, nd, up = s.get("fugas", 0), s.get("directas", 0), r.get("tunnel_up")
        # «Fuga» (motor) = tráfico que esquiva una VPN ACTIVA. Sin VPN no hay fugas: todo sale «directo» con tu IP
        # real. Se explica en la propia tarjeta para que un 0 en verde no parezca «estás protegido».
        if nf:
            fug = (nf, _("{n} conexiones esquivan el túnel: el destino ve tu IP real", n=nf), "critical", _("Fuera del túnel"))
        elif not up:
            fug = (0, _("Sin VPN no se cuentan fugas: mira «Directas»"), "neutral", _("No aplica sin túnel"))
        else:
            fug = (0, _("Nada esquiva el túnel ahora mismo"), "good", _("Sin fugas"))
        cards = (
            (_("Túnel"), (", ".join(r.get("tunnels") or []) or _("ninguno"),
                          _("Las conexiones a Internet salen por él") if up else _("Todo sale por tu conexión normal"),
                          "good" if up else "critical", _("Activo") if up else _("Caído")),
             _("Túnel VPN detectado en las interfaces del sistema. Que exista no garantiza que todo el tráfico lo use: "
               "eso lo dicen «Fugas» y «Directas».")),
            (_("Fugas"), fug,
             _("Fuga: conexión que sale por una interfaz física mientras hay una VPN activa (esquiva el túnel). "
               "Sin VPN no hay nada que esquivar, así que este contador queda en 0 aunque tu IP real esté expuesta.")),
            (_("Directas"), (nd, _("Salen sin túnel: el destino ve tu IP real") if nd else _("Ninguna conexión sale sin túnel"),
                             "serious" if nd else "good", _("Exponen tu IP real") if nd else _("Ninguna")),
             _("Directa: conexión a Internet sin VPN activa. No es una «fuga» del túnel, pero el destino ve tu IP real.")),
            (_("Marcadas en VirusTotal"), (r.get("vt_flagged", 0),
                                          _("Destinos con detecciones: revisa la tabla") if r.get("vt_flagged") else
                                          _("Ningún destino puntuado tiene detecciones"),
                                          "critical" if r.get("vt_flagged") else "neutral",
                                          _("Revisar") if r.get("vt_flagged") else _("Ninguna")),
             _("Solo cuenta los destinos que ya tienen puntuación de VirusTotal; los no analizados no se dan por limpios.")))
        for title, (val, sub, status, lab), tip in cards:
            k = KPI(title)
            k.set(val, sub, status, lab, tip=tip)
            row.append(k.widget)
        box.append(row)
        rt = self.data.get("routes")
        if rt:
            sk = Sankey()
            sk.set(rt["nodes"], rt["links"])
            self._sankey = sk
            inner = vbox(10)
            inner.append(sk)
            inner.append(legend_row([(_("Por el túnel VPN"), "net_protected"), (_("Directo · IP real"), "net_direct"),
                                     (_("Proxy"), "net_proxy"), (_("Tor"), "net_tor"), (_("Sin proxy (decide la ruta)"), "net_unknown")]))
            for line in rt.get("explain") or []:
                inner.append(lbl("• " + line, "td", wrap=True))
            guide = Gtk.Expander(label=_("Cómo encaja un proxy con la VPN y Tor"))
            g = vbox(4)
            for t in PROXY_GUIDE:
                g.append(lbl("• " + t, "kpi-sub", wrap=True))
            guide.set_child(g)
            inner.append(guide)
            box.append(card(_("Cómo viaja tu tráfico ahora (pasa el ratón por las bandas)"), inner))
        order = ["fuga", "directa", "otra", "permitida", "protegida"]
        flows = sorted(r.get("flows") or [], key=lambda f: (-(f["vt"] or {}).get("malicious", 0),
                                                             order.index(f["verdict"])))
        rows = []
        for f in flows:
            vt = f.get("vt")
            if vt:
                st = "critical" if vt["malicious"] >= 3 else "warning" if (vt["malicious"] or vt["suspicious"]) else "good"
                vt_cell = pill(st, f"{vt['malicious']}/{vt['total']}")
                vt_cell.set_tooltip_text(_("VirusTotal: {malicious} maliciosos, {suspicious} sospechosos de {total} motores · reputación {v7} · {v9}", malicious=vt['malicious'], suspicious=vt['suspicious'], total=vt['total'], v7=vt.get('reputation'), v9=vt.get('as_owner') or ''))
            else:
                vt_cell = lbl("—", "td")
                vt_cell.set_tooltip_text(_("Sin puntuación todavía: ") + str(live.get("status") or ""))
            geo = f"{cc_flag(f.get('country'))} {f.get('country') or '—'}" + (" 🧅" if f.get("tor") else "")
            geo_l = lbl(geo, "td")
            geo_l.set_tooltip_text(" · ".join(str(x) for x in (f.get("country_name"), f.get("city"), f.get("org"),
                                                               (f"Tor {f['tor']} ({f.get('tor_nick')})" if f.get("tor") else None),
                                                               f"AS{f['asn']}" if f.get("asn") else None) if x)
                                   or _("sin datos GeoIP"))
            copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Copiar IP"))
            copy_btn.add_css_class("flat")
            copy_btn.add_css_class("mini")
            copy_btn.connect("clicked", lambda _b, ip=f["remote"]: self.copy(ip, "IP copiada"))
            rows.append([pill(VERDICT[f["verdict"]][0], VERDICT[f["verdict"]][1] + (" DNS" if f["dns"] else "")),
                         f["process"], f"{f['remote']}:{f['rport']}", geo_l, vt_cell, f["iface"] or "?", copy_btn])
        tools = hbox(8)
        cp = Gtk.Button(label=_("Copiar tabla"), tooltip_text=_("Copia todas las conexiones (TSV, para pegar en una hoja o informe)"))
        cp.connect("clicked", lambda *_ign: self.copy(self._flows_tsv(flows), _("{n} conexiones copiadas", n=len(flows))))
        tools.append(cp)
        ci = Gtk.Button(label=_("Copiar IPs"), tooltip_text=_("Solo las IPs de destino, una por línea"))
        ci.connect("clicked", lambda *_ign: self.copy("\n".join(dict.fromkeys(f["remote"] for f in flows)), _("IPs copiadas")))
        tools.append(ci)
        tools.append(Gtk.Box(hexpand=True))
        tools.append(lbl(_("VirusTotal automático: {v1} · en cola {v3} · hoy {v5}/{v7}", v1=live.get('status', '—'), v3=live.get('queued', 0), v5=live.get('today', 0), v7=live.get('limit', '—')), "kpi-sub"))
        inner = vbox(8)
        inner.append(tools)
        inner.append(table([(_("Veredicto"), 0.9), (_("Proceso"), 1.3), (_("Destino"), 1.8), (_("País"), 0.6), ("VirusTotal", 0.8),
                            (_("Interfaz"), 0.8), ("", 0.2)], rows, max_rows=150))
        box.append(card(_("Conexiones en tiempo real (cada 2 s) · geolocalización local, sin enviar datos"), inner))

    @staticmethod
    def _flows_tsv(flows) -> str:
        head = _("veredicto\tproceso\tproto\torigen\tdestino\tpuerto\tpais\tvt_maliciosos\tvt_total\tinterfaz")
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
            rows.append([i["name"], pill("neutral", _(i["category"])),
                         pill("info", _("Activa"), icon=False) if i["up"] else lbl(_("Inactiva"), "kpi-hint"), ", ".join(i["subnets"]) or "—",
                         (f"{w['ssid']} · {w['security']} · {w['signal']}%" if w else (i["gateway"] or "—")),
                         f"↓ {human_bps(r.get('rx_bps'))}  ↑ {human_bps(r.get('tx_bps'))}", str(len(i["neighbors"]))])
        box.append(card(_("Interfaces y redes"), table([(_("Interfaz"), 1.2), (_("Tipo"), 1.0), (_("Estado"), 0.8), (_("Subred"), 1.4),
                                                     ("Red / gateway", 2.2), (_("Tráfico"), 1.6), (_("Vecinos"), 0.6)], rows)))
        row = hbox(12)
        neigh = [[x["ip"], x["mac"], x["vendor"] or _("desconocido"), i["name"],
                  pill("neutral", "gateway") if x["ip"] == i["gateway"] else ""] for i in ifs for x in i["neighbors"]]
        nc = card(_("Dispositivos vistos (tabla ARP, sin escanear)"), table(
            [("IP", 1.1), ("MAC", 1.3), (_("Fabricante"), 1.8), (_("Interfaz"), 1), ("", 0.6)], neigh))
        nc.set_hexpand(True)
        row.append(nc)
        if n.get("libvirt") is not None:
            lv = card(_("Redes de máquinas virtuales"), table([(_("Red"), 1.6), (_("Forward"), 0.8), (_("Aislamiento"), 1.0)], [
                [v["name"], v["forward"], pill("critical", _("NO aislada")) if v["isolation_broken"] else
                 pill("good", _("Aislada")) if v["forward"] == "isolated" else pill("neutral", _("Con salida"))]
                for v in n["libvirt"]]))
            lv.set_size_request(440, -1)
            row.append(lv)
        box.append(row)
        row = hbox(12)
        if n.get("docker") is not None:
            dc = card(_("Redes Docker"), table([(_("Red"), 1.6), (_("Driver"), 0.8), (_("Bridge"), 1.2)],
                                           [[d["name"], d["driver"], d["bridge"] or "—"] for d in n["docker"]]))
            dc.set_hexpand(True)
            row.append(dc)
        kc = card(_("Redes conocidas (huella SSID + MAC del gateway)"), table(
            [(_("Red"), 1.2), (_("Subred"), 1.2), (_("MAC gateway"), 1.4), (_("Dispositivos"), 0.8), (_("Última vez"), 1.2)],
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
        for icon, tip, fn in (("zoom-in-symbolic", _("Acercar"), lambda: self.mapv.zoom(1.5)),
                              ("zoom-out-symbolic", _("Alejar"), lambda: self.mapv.zoom(1 / 1.5)),
                              ("zoom-fit-best-symbolic", _("Ver el mundo entero"), lambda: self.mapv.reset())):
            b = Gtk.Button(icon_name=icon, tooltip_text=tip)
            b.connect("clicked", lambda _b, f=fn: f())
            tools.append(b)
        tools.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))
        for key, label in (("live", _("Conexiones en vivo")), ("chain", _("Cadena VPN")), ("tor", _("Circuito Tor")),
                           ("history", _("Historial")), ("heat", _("Tiempo por país"))):
            t = Gtk.ToggleButton(label=label, active=self.mapv.layers[key])
            t.connect("toggled", lambda b, k=key: (self.mapv.layers.__setitem__(k, b.get_active()), self.mapv.queue_draw()))
            tools.append(t)
        inner = vbox(8)
        tools_sc = Gtk.ScrolledWindow(vscrollbar_policy=Gtk.PolicyType.NEVER, hscrollbar_policy=Gtk.PolicyType.AUTOMATIC,
                                      propagate_natural_height=True)
        tools_sc.set_child(tools)
        inner.append(tools_sc)
        inner.append(lbl(_("Rueda: zoom · arrastrar: mover · doble clic: acercar · clic en un punto: detalle"), "kpi-hint", wrap=True))
        frame = Gtk.Frame(child=self.mapv)
        inner.append(frame)
        inner.append(legend_row([(_("Fuga"), "net_leak"), (_("Directa (IP real)"), "net_direct"), (_("Protegida (túnel)"), "net_protected"),
                                 (_("Permitida (tu excepción)"), "info"), (_("Cadena VPN"), "highlight"), (_("Circuito Tor"), "net_tor"), (_("Origen"), "ink")]))
        box.append(card(_("Mapa de conexiones"), inner))
        self.map_detail = vbox(0)
        box.append(self.map_detail)
        self.map_circuits = vbox(0)
        box.append(card(_("Circuitos Tor observables"), self.map_circuits))
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
                [(_("Circuito"), 0.7), (_("Streams"), 0.5), (_("Guard"), 1.4), (_("Middle"), 1.4), (_("Exit"), 1.4)],
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
                cb = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Copiar IP"))
                cb.add_css_class("flat")
                cb.add_css_class("mini")
                cb.connect("clicked", lambda _b, ip=f["remote"]: self.copy(ip, "IP copiada"))
                rows.append([pill(VERDICT[f["verdict"]][0], VERDICT[f["verdict"]][1]), f["process"],
                             f"{f['remote']}:{f['rport']}", f"🧅 {f['tor']}" if f.get("tor") else "—", vt_cell,
                             f.get("org") or "—", cb])
            tools = hbox(8)
            z = Gtk.Button(label=_("Acercar aquí"))
            z.connect("clicked", lambda *_ign: self.mapv.focus(p["lon"], p["lat"]))
            tools.append(z)
            ci = Gtk.Button(label=_("Copiar IPs"))
            ci.connect("clicked", lambda *_ign: self.copy("\n".join(dict.fromkeys(f["remote"] for f in flows)), _("IPs copiadas")))
            tools.append(ci)
            ct = Gtk.Button(label=_("Copiar tabla"))
            ct.connect("clicked", lambda *_ign: self.copy(self._flows_tsv(flows), _("{n} conexiones copiadas", n=len(flows))))
            tools.append(ct)
            inner = vbox(8)
            inner.append(tools)
            inner.append(table([(_("Veredicto"), 0.9), (_("Proceso"), 1.3), (_("Destino"), 1.7), (_("Tor"), 0.8), ("VirusTotal", 0.8),
                                (_("Organización"), 1.6), ("", 0.2)], rows))
            title = f"{cc_flag(p['country'])} {p['name'] or _('Ubicación desconocida')} · {len(flows)} conexiones"
            self.map_detail.append(card(title, inner))
            return
        if kind == "hop":
            pairs = [(_("Tipo"), p.get("type")), (_("Nodo"), p.get("label")), ("IP", p.get("ip")),
                     (_("País"), f"{cc_flag(p.get('country'))} {p.get('country') or '?'}"), (_("Huella"), p.get("fp"))]
        elif kind == "history":
            pairs = [(_("Capa"), p["layer"]), (_("Elemento"), p["label"]), (_("País"), f"{cc_flag(p.get('country'))} {p.get('country')}"),
                     (_("Desde"), iso(p["started"])), (_("Hasta"), iso(p["ended"]) if p["ended"] else _("activo"))]
        elif kind == "home":
            pairs = [(_("Origen"), p.get("country")), (_("Estimado por"), p.get("geo_source"))]
        else:
            pairs = [(_("País"), p.get("name")), (_("Tiempo de salida (7 días)"), fmt_duration(p.get("seconds")))]
        grid = table([(_("Campo"), 1.0), (_("Valor"), 3.0)], [[k, v if v is not None else "—"] for k, v in pairs])
        ip = p.get("ip") or (p.get("label") if kind == "history" else None)
        suffix = None
        if ip:
            suffix = Gtk.Button(icon_name="edit-copy-symbolic", tooltip_text=_("Copiar"))
            suffix.add_css_class("flat")
            suffix.connect("clicked", lambda *_ign: self.copy(str(ip), _("Copiado")))
        self.map_detail.append(card(_("Detalle"), grid, suffix))

    def render_hist(self):
        box = self.pages["hist"]
        clear(box)
        box.append(card(_("Sesiones"), table(
            [(_("Inicio"), 1.2), (_("Duración"), 1.0), (_("Interfaz"), 0.8), (_("VPN"), 1.4), (_("IP pública"), 1.2), (_("Cierre"), 1.4)],
            [[iso(s["started"]), fmt_duration(s["duration"]), s["egress_iface"], s["vpn"] or "—", s["public_ip"] or "—",
              reason_label(s["end_reason"]) if s["end_reason"] else pill("info", _("En curso"), icon=False)] for s in self.data.get("sessions") or []], max_rows=40)))
        box.append(card(_("Contadores de tiempo"), table(
            [(_("Elemento"), 2.2), (_("Capa"), 1.0), (_("País"), 0.5), (_("Usos"), 0.4), (_("Total"), 1.0), (_("En curso"), 1.0)],
            [[c["label"], c["layer"], c["country"] or "—", str(c["uses"]), c["total_fmt"], c.get("current_fmt") or ""]
             for c in self.data.get("counters") or []], max_rows=60)))
        box.append(card(_("Timeline"), table(
            [(_("Hora"), 1.1), (_("Severidad"), 0.8), (_("Evento"), 1.4), (_("Detalle"), 3.2)],
            [[iso(e["ts"]), sev_pill(e["severity"]), e["kind"],
              json.dumps(e["data"], ensure_ascii=False)[:140]] for e in self.data.get("timeline") or []], max_rows=80)))

    def render_fix(self):
        box = self.pages["fix"]
        clear(box)
        head = hbox(10)
        head.append(Gtk.Image.new_from_icon_name("dialog-information-symbolic"))
        head.append(lbl(_("Los comandos no se ejecutan solos: cópialos, revísalos y lánzalos tú. Las etiquetas indican "
                          "si necesitan privilegios o si cortan la conexión."), "kpi-sub", wrap=True))
        box.append(head)
        fixes = sorted(self.data.get("fixes") or [], key=lambda f: SEV_ORDER.index(f.get("severity", "info"))
                       if f.get("severity", "info") in SEV_ORDER else 9)
        if not fixes:
            box.append(card(None, lbl(_("No hay acciones pendientes."), "empty")))
        for fx in fixes:
            inner = vbox(8)
            if fx.get("why") or fx.get("finding"):
                inner.append(lbl(fx.get("why") or fx.get("finding"), "kpi-sub", wrap=True))
            for n, s_ in enumerate(fx["steps"], 1):
                line = hbox(10)
                desc = vbox(4)
                top = hbox(6)
                top.append(lbl(f"{n}. {s_['desc']}", "td", wrap=True))
                top.get_first_child().set_hexpand(True)
                if s_["root"]:
                    t = lbl(_("Necesita root"), "cmd-tag cmd-tag-root")
                    t.set_tooltip_text(_("Se ejecuta con privilegios: puede cambiar la configuración del sistema"))
                    top.append(t)
                if s_["disruptive"]:
                    t = lbl(_("Corta la conexión"), "cmd-tag cmd-tag-disruptive")
                    t.set_tooltip_text(_("Interrumpe la conectividad mientras se aplica: hazlo cuando no estés en medio de algo"))
                    top.append(t)
                if s_.get("cmd") and not s_["root"] and not s_["disruptive"]:
                    top.append(lbl(_("Sin privilegios"), "cmd-tag cmd-tag-read"))
                desc.append(top)
                if s_.get("cmd"):
                    desc.append(lbl(s_["cmd"], "cmd", wrap=True, selectable=True))
                desc.set_hexpand(True)
                line.append(desc)
                if s_.get("cmd"):
                    b = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.END, tooltip_text=_("Copiar"))
                    b.add_css_class("flat")
                    b.connect("clicked", lambda _b, c=s_["cmd"]: self.copy(c))
                    line.append(b)
                inner.append(line)
            if fx.get("verify") and fx["verify"] != "—":
                ver = hbox(8)
                ver.append(lbl(_("Comprobar después").upper(), "card-title"))
                v = lbl(fx["verify"], "cmd", wrap=True, selectable=True)
                v.set_hexpand(True)
                ver.append(v)
                inner.append(ver)
            sev = fx.get("severity") or "info"
            suffix = sev_pill(sev)
            if fx.get("check") == "dns_plaintext":
                quick = hbox(6)
                quick.append(suffix)
                b = Gtk.Button(label=_("Cifrar DNS ahora"))
                b.add_css_class("suggested-action")
                b.connect("clicked", lambda *_ign: self.tools_dns_apply())
                quick.append(b)
                suffix = quick
            c = card(fx["title"], inner, suffix)
            c.add_css_class("callout")
            c.add_css_class(f"callout-{SEV_STATUS.get(sev, 'neutral')}")
            box.append(c)

    def render_intel(self):
        from .. import intel as intel_mod
        box = self.pages["intel"]
        clear(box)
        keys = self.data.get("intel_keys") or {}
        stored = intel_mod.load_keys()
        kg = Adw.PreferencesGroup(title=_("API keys"),
                                  description=_("Escribe la clave y pulsa Intro o ✓ para guardarla. Se guardan solo en este equipo ({v1}, permisos 0600) y nunca se muestran, ni se envían al daemon ni a los logs.", v1=tilde(intel_mod.secrets_path())))
        for name, title, provider in KEY_ROWS:
            row = Adw.PasswordEntryRow(title=title, show_apply_button=True)
            row.connect("apply", self.on_key_apply, name)
            if name in stored:
                saved = pill("good", _("guardada"))
                saved.set_valign(Gtk.Align.CENTER)
                row.add_suffix(saved)
                if provider:
                    t = Gtk.Button(label=_("Probar"), valign=Gtk.Align.CENTER, tooltip_text=_("Consulta 8.8.8.8 con esta clave"))
                    t.add_css_class("flat")
                    t.connect("clicked", lambda _b, p=provider: self.call_bg(
                        "intel_test", {"provider": p}, lambda r: self.toast(f"{r['provider']}: {r['detail']}")))
                    row.add_suffix(t)
                d = Gtk.Button(icon_name="user-trash-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Borrar clave"))
                d.add_css_class("flat")
                d.connect("clicked", lambda _b, n=name: self.on_key_delete(n))
                row.add_suffix(d)
            kg.add(row)
        box.append(kg)
        row = hbox(12, homogeneous=True)
        for p, stx in (keys.get("providers") or {}).items():
            k = KPI(p)
            ok = not stx.startswith("falta")
            k.set(_("Configurado") if ok else _("Sin clave"), stx, "good" if ok else "warning", _("Listo") if ok else _("Pendiente"))
            row.append(k.widget)
        box.append(row)
        bar = hbox(8)
        btn = Gtk.Button(label=_("Escanear historial"))
        btn.add_css_class("suggested-action")
        btn.set_sensitive(bool(keys.get("consent")))
        btn.connect("clicked", lambda *_ign: self.call_bg("intel_scan", {"background": True},
                                                       lambda r: self.toast(f"Escaneando {r['count']} IPs…")))
        bar.append(btn)
        bar.append(lbl(_("Las consultas solo salen por VPN o Tor (o sin VPN si lo permites en Ajustes)."), "kpi-sub"))
        box.append(bar)
        order = {"malicioso": 0, "expuesto": 1, "sospechoso": 2}
        results = sorted(self.data.get("intel") or [], key=lambda x: order.get(x["verdict"], 9))
        rows = []
        def vlabel(res):
            """Veredicto de un proveedor → texto traducido (o su estado: sin clave, cuota, error…)."""
            res = res or {}
            if res.get("verdict") in INTEL_VERDICT and res.get("verdict") is not None:
                return INTEL_VERDICT[res["verdict"]][1]
            st_ = res.get("status")
            return {"sin_clave": _("Sin clave"), "rate_limited": _("Cuota agotada"), "ok": _("Sin veredicto")}.get(
                st_, _("No disponible: {s}", s=st_) if st_ else _("No analizado"))
        for r in results:
            stx, vtxt = INTEL_VERDICT.get(r["verdict"], ("neutral", str(r["verdict"])))
            g = r.get("geo") or {}
            geo = lbl(f"{cc_flag(g.get('country'))} {g.get('country') or '—'}", "td")
            geo.set_tooltip_text(" · ".join(str(x) for x in (g.get("country_name"), g.get("city"),
                                                              f"AS{r['asn']}" if r.get("asn") else None,
                                                              f"fuente: {g.get('source')}" if g.get("source") else None)
                                             if x) or _("sin datos GeoIP"))
            vt = r.get("vt")
            if vt:
                vst = "critical" if vt["malicious"] >= 3 else "warning" if (vt["malicious"] or vt["suspicious"]) else "good"
                vt_cell = pill(vst, f"{vt['malicious']}/{vt['total']}")
                vt_cell.set_tooltip_text(_("{malicious} maliciosos, {suspicious} sospechosos de {total} motores · reputación {v6}", malicious=vt['malicious'], suspicious=vt['suspicious'], total=vt['total'], v6=vt.get('reputation')))
            else:
                vt_cell = lbl(vlabel(r["results"].get("virustotal")), "td")
            gn = r["results"].get("greynoise") or {}
            ports = r.get("shodan_ports") or []
            sh_txt = (_("{n} puertos", n=len(ports)) + (f" · {len(r['shodan_vulns'])} CVE" if r.get("shodan_vulns") else "")
                      if ports else vlabel(r["results"].get("shodan")))
            sh_cell = lbl(sh_txt, "td")
            if ports:
                sh_cell.set_tooltip_text(_("Puertos: ") + ", ".join(map(str, ports[:30])) +
                                         ("\nCVE: " + ", ".join(r["shodan_vulns"][:10]) if r.get("shodan_vulns") else ""))
            copy_btn = Gtk.Button(icon_name="edit-copy-symbolic", valign=Gtk.Align.CENTER, tooltip_text=_("Copiar IP"))
            copy_btn.add_css_class("flat")
            copy_btn.add_css_class("mini")
            copy_btn.connect("clicked", lambda _b, ip=r["ip"]: self.copy(ip, "IP copiada"))
            rows.append([r["ip"], geo, tor_pill(r.get("tor")), r.get("org") or "—", pill(stx, vtxt),
                         vlabel(gn), vt_cell, sh_cell, vlabel(r["results"].get("censys")), copy_btn])
        tools = hbox(8)
        cp = Gtk.Button(label=_("Copiar tabla"), tooltip_text=_("Todos los resultados en formato tabulado"))
        cp.connect("clicked", lambda *_ign: self.copy(self._intel_tsv(results), _("{n} resultados copiados", n=len(results))))
        tools.append(cp)
        ci = Gtk.Button(label=_("Copiar IPs"))
        ci.connect("clicked", lambda *_ign: self.copy("\n".join(r["ip"] for r in results), _("IPs copiadas")))
        tools.append(ci)
        ex = Gtk.Button(label=_("Comprobar en ExoneraTor"),
                        tooltip_text=_("Confirma por Tor si cada IP fue relay de Tor (hasta anteayer). El consenso local "
                                     "y la lista oficial de salidas ya se usan siempre, sin consultas por IP"))
        ex.connect("clicked", lambda *_ign: self.call_bg("intel_tor_check", {"background": True}, lambda r: self.toast(
            _("ExoneraTor: comprobando {count} IPs por Tor…", count=r['count']))))
        tools.append(ex)
        inner = vbox(8)
        inner.append(tools)
        inner.append(table([("IP", 1.2), (_("País"), 0.6), (_("Tor"), 0.7), (_("Organización"), 1.7), (_("Veredicto"), 0.9), ("GreyNoise", 0.8),
                            ("VirusTotal", 0.8), (_("Shodan"), 0.9), (_("Censys"), 0.6), ("", 0.2)], rows,
                           empty=_("Aún no hay resultados: guarda una clave y pulsa «Escanear historial».")))
        box.append(card(_("Resultados · geolocalización local"), inner))
        box.append(lbl(_("Los exits de Tor y servidores VPN suelen figurar como maliciosos por el abuso de otros usuarios: "
                       "indica listas de bloqueo, no algo sobre tu tráfico."), "kpi-sub", wrap=True))

    @staticmethod
    def _intel_tsv(results) -> str:
        lines = [_("ip\tpais\ttor\torganizacion\tasn\tveredicto\tgreynoise\tvt_maliciosos\tvt_total\tshodan_puertos")]
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
            self.toast(_("Clave de {name} guardada", name=name))
        except Exception as e:  # noqa: BLE001
            self.toast(_("No se pudo guardar: {e}", e=e))
        self.sig.pop("intel", None)
        self.call_bg("intel_keys", {}, lambda r: (self.data.__setitem__("intel_keys", r), self.render()))

    def on_key_delete(self, name):
        from .. import intel as intel_mod
        intel_mod.delete_key(name)
        self.toast(_("Clave de {name} borrada", name=name))
        self.sig.pop("intel", None)
        self.call_bg("intel_keys", {}, lambda r: (self.data.__setitem__("intel_keys", r), self.render()))

    # ── ajustes ──
    # ── utilidades: traductor, OCR, DNS, zona horaria, MAC y dependencias ──
    def _confirm(self, heading, body, action, label=_("Aplicar"), destructive=False):
        dlg = Adw.AlertDialog(heading=heading, body=body)
        dlg.add_response("cancel", _("Cancelar"))
        dlg.add_response("go", label)
        if destructive:
            dlg.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)
        else:
            dlg.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)
        dlg.connect("response", lambda _d, r: action() if r == "go" else None)
        dlg.present(self)

    def build_tools(self):
        box = self.pages["tools"]
        clear(box)
        box.append(lbl(_("Herramientas locales de VELA. Lo que modifica el sistema (DNS, MAC) pide consentimiento, "
                         "confirmación y deja un registro; lo demás funciona sin salir de tu máquina."), "kpi-sub", wrap=True))

        # traductor + OCR
        g = card(_("Traductor y OCR"))
        self.tr_in = Gtk.TextView(wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.tr_in.set_top_margin(8)
        self.tr_in.set_bottom_margin(8)
        self.tr_in.set_left_margin(8)
        self.tr_in.set_right_margin(8)
        sw = Gtk.ScrolledWindow()
        sw.set_min_content_height(130)
        sw.set_child(self.tr_in)
        g.append(sw)
        row = hbox(8)
        codes = [c for c in translate.LANGUAGES if c != "auto"]
        self.tr_langs = codes
        try:
            from .. import config as config_mod
            cur = (config_mod.load().get("translate") or {}).get("target", "es")
        except Exception:  # noqa: BLE001
            cur = "es"
        self.tr_lang = Gtk.DropDown(model=Gtk.StringList.new([translate.LANGUAGES[c] for c in codes]),
                                    tooltip_text=_("Idioma de destino"))
        self.tr_lang.set_selected(codes.index(cur) if cur in codes else codes.index("es"))
        row.append(lbl(_("Traducir a"), "td-strong"))
        row.append(self.tr_lang)
        tr_btn = Gtk.Button(label=_("Traducir"))
        tr_btn.add_css_class("suggested-action")
        tr_btn.connect("clicked", lambda *_ign: self.tools_translate())
        row.append(tr_btn)
        ocr_btn = Gtk.Button(label=_("Escanear pantalla y traducir"))
        ocr_btn.connect("clicked", lambda *_ign: self.tools_ocr())
        row.append(ocr_btn)
        ocr_only = Gtk.Button(label=_("Solo OCR"))
        ocr_only.add_css_class("flat")
        ocr_only.set_tooltip_text(_("Captura y reconoce el texto sin traducirlo; útil para comprobar la selección"))
        ocr_only.connect("clicked", lambda *_ign: self.tools_ocr_only())
        row.append(ocr_only)
        clr = Gtk.Button(label=_("Limpiar"))
        clr.add_css_class("flat")
        clr.connect("clicked", lambda *_ign: (self.tr_in.get_buffer().set_text(""), self.tr_out.get_buffer().set_text("")))
        row.append(clr)
        g.append(row)
        self.tr_status = lbl("", "kpi-sub", wrap=True)
        g.append(self.tr_status)
        self.tr_out = Gtk.TextView(editable=False, cursor_visible=False, wrap_mode=Gtk.WrapMode.WORD_CHAR)
        self.tr_out.set_top_margin(8)
        self.tr_out.set_bottom_margin(8)
        self.tr_out.set_left_margin(8)
        self.tr_out.set_right_margin(8)
        sw2 = Gtk.ScrolledWindow()
        sw2.set_min_content_height(130)
        sw2.set_child(self.tr_out)
        g.append(sw2)
        cp = Gtk.Button(label=_("Copiar traducción"))
        cp.add_css_class("flat")
        cp.connect("clicked", lambda *_ign: self.copy(self.tr_out.get_buffer().get_text(
            self.tr_out.get_buffer().get_start_iter(), self.tr_out.get_buffer().get_end_iter(), False),
            _("Traducción copiada")))
        g.append(cp)
        box.append(g)

        # DNS
        d = card(_("DNS cifrado"))
        self.dns_status_lbl = lbl("", "kpi-sub", wrap=True)
        d.append(self.dns_status_lbl)
        drow = hbox(8)
        self.dns_transport = Gtk.DropDown(model=Gtk.StringList.new([_("DoT (systemd-resolved)"), _("DoH (cloudflared)")]))
        self.dns_provider = Gtk.DropDown(model=Gtk.StringList.new(list(dnsfix.PROVIDERS)))
        drow.append(lbl(_("Método"), "td-strong"))
        drow.append(self.dns_transport)
        drow.append(lbl(_("Proveedor"), "td-strong"))
        drow.append(self.dns_provider)
        db = Gtk.Button(label=_("Cifrar DNS"))
        db.add_css_class("suggested-action")
        db.connect("clicked", lambda *_ign: self.tools_dns_apply())
        drow.append(db)
        dr = Gtk.Button(label=_("Restaurar"))
        dr.add_css_class("flat")
        dr.connect("clicked", lambda *_ign: self.tools_dns_restore())
        drow.append(dr)
        d.append(drow)
        d.append(lbl(_("DoT cambia el DNS del sistema y puede sustituir el de la VPN: VELA guarda una copia y puede "
                       "revertirlo. DoH requiere cloudflared."), "kpi-sub", wrap=True))
        box.append(d)

        # zona horaria
        tz = card(_("Abrir una aplicación con otra zona horaria"))
        tz.append(lbl(_("Arranca la app con TZ=<zona>; la zona del escritorio no cambia. Las apps que reutilizan una "
                        "instancia por D-Bus pueden no heredarla."), "kpi-sub", wrap=True))
        self.tz_apps_all = applaunch.apps()
        self.tz_apps = list(self.tz_apps_all)
        self.tz_search = Gtk.SearchEntry(placeholder_text=_("Buscar aplicación…"))
        self.tz_search.connect("search-changed", lambda *_ign: self._tz_filter())
        tz.append(self.tz_search)
        self.tz_app_dd = Gtk.DropDown(model=Gtk.StringList.new([a["name"] for a in self.tz_apps] or ["—"]))
        tz.append(self.tz_app_dd)
        self.tz_zone_dd = Gtk.DropDown(model=Gtk.StringList.new(applaunch.timezone_names()))
        try:
            z = applaunch.current_timezone()
            names = applaunch.timezone_names()
            self.tz_zone_dd.set_selected(names.index(z) if z in names else 0)
        except Exception:  # noqa: BLE001
            pass
        tz.append(self.tz_zone_dd)
        lrow = hbox(8)
        lb = Gtk.Button(label=_("Abrir con esta zona"))
        lb.add_css_class("suggested-action")
        lb.connect("clicked", lambda *_ign: self.tools_launch_tz())
        lrow.append(lb)
        self.tz_cmd = Gtk.Entry(placeholder_text=_("…o un comando (opcional): firefox --private-window"))
        self.tz_cmd.set_hexpand(True)
        lrow.append(self.tz_cmd)
        lc = Gtk.Button(label=_("Ejecutar comando"))
        lc.add_css_class("flat")
        lc.connect("clicked", lambda *_ign: self.tools_launch_cmd())
        lrow.append(lc)
        tz.append(lrow)
        self.tz_status = lbl("", "kpi-sub", wrap=True)
        tz.append(self.tz_status)
        box.append(tz)

        # MAC
        m = card(_("Cambiador de MAC"))
        m.append(lbl(_("Cambio temporal: la conexión se corta unos segundos y NetworkManager puede restaurarla al "
                       "reconectar. Se guarda la MAC original para poder volver."), "kpi-sub", wrap=True))
        self.mac_ifaces = [i for i in mac_mod.interfaces() if i.get("kind") == "física"]
        self.mac_dd = Gtk.DropDown(model=Gtk.StringList.new([
            _("{name} · {mac}", name=i["name"], mac=i["mac"]) for i in self.mac_ifaces] or ["—"]))
        self.mac_dd.connect("notify::selected", lambda *_ign: self._mac_selected())
        m.append(self.mac_dd)
        self.mac_lbl = lbl("", "kpi-sub", wrap=True)
        m.append(self.mac_lbl)
        mrow = hbox(8)
        self.mac_entry = Gtk.Entry(placeholder_text="02:11:22:33:44:55")
        self.mac_entry.set_hexpand(True)
        mrow.append(self.mac_entry)
        rb = Gtk.Button(label=_("Aleatoria"))
        rb.connect("clicked", lambda *_ign: self.mac_entry.set_text(mac_mod.random_mac()))
        mrow.append(rb)
        sb = Gtk.Button(label=_("Aplicar"))
        sb.add_css_class("suggested-action")
        sb.connect("clicked", lambda *_ign: self.tools_mac_set())
        mrow.append(sb)
        rs = Gtk.Button(label=_("Restaurar original"))
        rs.add_css_class("flat")
        rs.connect("clicked", lambda *_ign: self.tools_mac_restore())
        mrow.append(rs)
        m.append(mrow)
        self.mac_status = lbl("", "kpi-sub", wrap=True)
        m.append(self.mac_status)
        box.append(m)
        self._mac_selected()

        # dependencias
        dep = card(_("Dependencias opcionales"))
        self.dep_lbl = lbl("", "kpi-sub", wrap=True)
        dep.append(self.dep_lbl)
        drow2 = hbox(8)
        for label, feat in ((_("Instalar OCR"), ["ocr", "capture"]), (_("Instalar MAC"), ["mac"]),
                            (_("Comprobar"), None)):
            b = Gtk.Button(label=label)
            b.add_css_class("flat")
            b.connect("clicked", lambda _b, f=feat: self.tools_deps(f))
            drow2.append(b)
        ob = Gtk.Button(label=_("Instalar Ollama + modelo"))
        ob.add_css_class("suggested-action")
        ob.connect("clicked", lambda *_ign: self.tools_ollama())
        drow2.append(ob)
        dep.append(drow2)
        box.append(dep)

        dat = card(_("Datos"))
        self.tools_data_lbl = lbl("", "kpi-sub", wrap=True)
        dat.append(self.tools_data_lbl)
        brows = hbox(8)
        for label, cb in ((_("Exportar"), self.data_export), (_("Importar"), self.data_import),
                          (_("Borrar…"), self.data_reset)):
            b = Gtk.Button(label=label)
            b.add_css_class("flat")
            b.connect("clicked", lambda _b, f=cb: f())
            brows.append(b)
        dat.append(brows)
        box.append(dat)
        self._tools_status()

    def _tz_filter(self):
        q = (self.tz_search.get_text() or "").strip().lower()
        self.tz_apps = [a for a in self.tz_apps_all if not q or q in a["name"].lower() or q in a["id"].lower()]
        self.tz_app_dd.set_model(Gtk.StringList.new([a["name"] for a in self.tz_apps] or ["—"]))

    def _mac_selected(self):
        if not self.mac_ifaces:
            self.mac_lbl.set_text(_("No hay interfaces disponibles"))
            return
        i = self.mac_ifaces[min(self.mac_dd.get_selected(), len(self.mac_ifaces) - 1)]
        self.mac_lbl.set_text(_("Actual: {mac} · permanente: {perm} · {kind} · {state}", mac=i["mac"],
                                perm=i.get("permanent") or _("desconocida"), kind=i["kind"], state=i["state"]))

    def _tools_status(self):
        self._tools_checked = time.monotonic()
        try:
            st = translate.status()
            self.tr_status.set_text((_("Motor: {engine} · {endpoint} · modelo {model}", engine=st["engine"],
                                       endpoint=st["endpoint"], model=st.get("model") or "?")
                                     if st["ok"] else _("Sin LLM local. Instala Ollama y descarga un modelo.")))
        except Exception as e:  # noqa: BLE001
            self.tr_status.set_text(str(e))
        try:
            d = dnsfix.status()
            self.dns_status_lbl.set_text(_("DNS cifrado: {state} · {resolvers}", state={
                True: _("sí"), False: _("no"), None: _("sin verificar")}[d.get("encrypted")],
                resolvers=", ".join(f"{r['addr']} [{r['transport']}]" for r in d.get("resolvers") or []) or "—"))
        except Exception as e:  # noqa: BLE001
            self.dns_status_lbl.set_text(str(e))
        try:
            sm = deps.summary()
            bad = [x for x in sm if not x["ok"]]
            self.dep_lbl.set_text(_("Todo instalado.") if not bad else
                                  _("Falta: {items}", items=", ".join(x["title"] for x in bad)))
        except Exception as e:  # noqa: BLE001
            self.dep_lbl.set_text(str(e))
        d = self.data.get("data_info") or {}
        if hasattr(self, "tools_data_lbl"):
            rows = d.get("rows") or {}
            self.tools_data_lbl.set_text(_("{db} · sesiones {sessions} · eventos {events}", db=d.get("database") or "—",
                                            sessions=rows.get("sessions", 0), events=rows.get("events", 0)))

    def render_tools(self):
        if time.monotonic() - getattr(self, "_tools_checked", 0) > 30:
            self._tools_checked = time.monotonic()
            self._tools_status()

    def tools_translate(self):
        buf = self.tr_in.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), False)
        target = self.tr_langs[self.tr_lang.get_selected()]
        if not text.strip():
            self.toast(_("Escribe o pega un texto"))
            return
        self.tr_status.set_text(_("Traduciendo…"))

        def work():
            try:
                r = translate.translate(text, target=target)
                def done():
                    self.tr_out.get_buffer().set_text(r["text"])
                    self.tr_status.set_text(_("Traducido con {engine} · {model}", engine=r["engine"], model=r["model"]))
                GLib.idle_add(done)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(self.tr_status.set_text, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def tools_ocr(self):
        target = self.tr_langs[self.tr_lang.get_selected()]
        self.tr_status.set_text(_("Selecciona la región de la pantalla…"))

        def work():
            try:
                r = ocr.scan_and_translate(target=target)
                def done():
                    text = (r.get("ocr") or {}).get("text") or ""
                    if text:
                        self.tr_in.get_buffer().set_text(text)
                    if r.get("error"):
                        self.tr_status.set_text(_("OCR: {e}", e=r["error"]))
                        self.toast(_("OCR: {e}", e=r["error"]))
                        return
                    self.tr_out.get_buffer().set_text(r["translation"]["text"])
                    self.tr_status.set_text(_("OCR ({langs}) y traducción listos", langs="+".join(r["ocr"]["languages"])))
                    if r.get("captured", {}).get("path"):
                        Path(r["captured"]["path"]).unlink(missing_ok=True)
                GLib.idle_add(done)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(self.tr_status.set_text, _("Error: {e}", e=e))
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def tools_ocr_only(self):
        self.tr_status.set_text(_("Selecciona la región de la pantalla…"))

        def work():
            cap = None
            try:
                cap = ocr.capture_region()
                res = ocr.ocr_image(cap["path"])
                def done():
                    self.tr_in.get_buffer().set_text(res["text"])
                    self.tr_status.set_text(_("OCR ({langs}, PSM {psm}) listo", langs="+".join(res["languages"]),
                                              psm=res.get("psm", "?")))
                    if not res["text"]:
                        self.toast(_("No se reconoció texto en la selección"))
                GLib.idle_add(done)
            except Exception as e:  # noqa: BLE001
                GLib.idle_add(self.tr_status.set_text, _("OCR: {e}", e=e))
                GLib.idle_add(self.toast, _("OCR: {e}", e=e))
            finally:
                if cap:
                    Path(cap["path"]).unlink(missing_ok=True)
        threading.Thread(target=work, daemon=True).start()

    def tools_dns_apply(self):
        transport = "dot" if self.dns_transport.get_selected() == 0 else "doh"
        provider = list(dnsfix.PROVIDERS)[self.dns_provider.get_selected()]
        try:
            p = dnsfix.plan(transport, provider)
        except Exception as e:  # noqa: BLE001
            self.toast(str(e))
            return
        body = _("Se modificará {file} y se reiniciará systemd-resolved. Comandos: {cmds}",
                 file=p["file"], cmds="; ".join(p["commands"]))
        self._confirm(_("¿Cifrar el DNS del sistema?"), body, lambda: self._dns_apply_bg(transport, provider),
                      _("Cifrar"), destructive=False)

    def _dns_apply_bg(self, transport, provider):
        def work():
            try:
                r = dnsfix.apply(transport, provider)
                GLib.idle_add(self._after_dns, r, "dns_encrypt")
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def _after_dns(self, r, action="dns_encrypt"):
        self.call_bg("log_action", {"action": action, "detail": {k: r.get(k) for k in ("ok", "transport",
                                                                                       "provider", "error")}})
        self.toast(_("DNS cifrado y verificado") if r.get("ok") else
                   _("No se pudo cifrar: {e}", e=r.get("error") or "?"))
        self._tools_status()
        self.refresh_after(["dns", "leaks"])

    def tools_dns_restore(self):
        self._confirm(_("¿Restaurar el DNS anterior?"),
                      _("Se elimina la configuración de VELA y se reinicia systemd-resolved."),
                      self._dns_restore_bg, _("Restaurar"), destructive=True)

    def _dns_restore_bg(self):
        def work():
            try:
                r = dnsfix.restore()
                GLib.idle_add(self._after_dns, r, "dns_restore")
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def tools_launch_tz(self):
        if not self.tz_apps:
            self.toast(_("No se encontraron aplicaciones .desktop"))
            return
        app = self.tz_apps[min(self.tz_app_dd.get_selected(), len(self.tz_apps) - 1)]
        tz = applaunch.timezone_names()[self.tz_zone_dd.get_selected()]
        try:
            r = applaunch.launch(app, tz)
            self.tz_status.set_text(_("Lanzado: {cmd} · TZ={tz}", cmd=" ".join(r["command"]), tz=tz)
                                    if r.get("ok") else _("Error: {e}", e=r.get("error")))
        except Exception as e:  # noqa: BLE001
            self.tz_status.set_text(_("Error: {e}", e=e))

    def tools_launch_cmd(self):
        cmd = self.tz_cmd.get_text().strip()
        if not cmd:
            self.toast(_("Escribe un comando"))
            return
        tz = applaunch.timezone_names()[self.tz_zone_dd.get_selected()]
        try:
            r = applaunch.launch_command(cmd, tz)
            self.tz_status.set_text(_("Lanzado con TZ={tz}: {cmd}", tz=tz, cmd=" ".join(r["command"]))
                                    if r.get("ok") else _("Error: {e}", e=r.get("error")))
        except Exception as e:  # noqa: BLE001
            self.tz_status.set_text(_("Error: {e}", e=e))

    def tools_mac_set(self):
        if not self.mac_ifaces:
            return
        i = self.mac_ifaces[min(self.mac_dd.get_selected(), len(self.mac_ifaces) - 1)]
        mac = self.mac_entry.get_text().strip()
        if not mac:
            self.toast(_("Escribe una MAC o pulsa Aleatoria"))
            return
        self._confirm(_("¿Cambiar la MAC de {iface}?", iface=i["name"]),
                      _("La conexión se cortará unos segundos. Se guarda la MAC actual para restaurarla."),
                      lambda: self._mac_bg(i["name"], mac), _("Cambiar"), destructive=True)

    def _mac_bg(self, iface, mac):
        def work():
            try:
                r = mac_mod.set_mac(iface, mac=mac, apply=True)
                GLib.idle_add(self._after_mac, r, "mac_change")
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def _after_mac(self, r, action="mac_change"):
        self.call_bg("log_action", {"action": action, "detail": {"ok": r.get("ok"), "iface": r.get("iface"),
                                                                 "old": r.get("old"), "new": r.get("actual")}})
        self.mac_status.set_text(_("MAC de {iface}: {mac}", iface=r.get("iface"), mac=r.get("actual"))
                                 if r.get("ok") else _("Error: {e}", e=r.get("error")))
        self.mac_ifaces = [i for i in mac_mod.interfaces() if i.get("kind") == "física"]
        self.mac_dd.set_model(Gtk.StringList.new([_("{name} · {mac}", name=i["name"], mac=i["mac"])
                                                  for i in self.mac_ifaces] or ["—"]))
        self._mac_selected()
        if r.get("ok"):
            self.refresh_after(["network", "networks", "leaks"])

    def tools_mac_restore(self):
        if not self.mac_ifaces:
            return
        i = self.mac_ifaces[min(self.mac_dd.get_selected(), len(self.mac_ifaces) - 1)]
        self._confirm(_("¿Restaurar la MAC original de {iface}?", iface=i["name"]),
                      _("La conexión se cortará unos segundos."),
                      lambda: self._mac_restore_bg(i["name"]), _("Restaurar"), destructive=True)

    def _mac_restore_bg(self, iface):
        def work():
            try:
                r = mac_mod.restore(iface, apply=True)
                GLib.idle_add(self._after_mac, r, "mac_restore")
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def tools_deps(self, features):
        if features is None:
            self._tools_status()
            self.toast(_("Dependencias comprobadas"))
            return
        pl = deps.plan(features)
        if not pl["packages"]:
            self.toast(_("No falta ningún paquete"))
            return
        self._confirm(_("¿Instalar dependencias?"),
                      _("Paquetes: {pkgs}\nComando: {cmd}", pkgs=", ".join(pl["packages"]),
                        cmd=" ".join(pl["command"] or [])),
                      lambda: self._deps_bg(features), _("Instalar"))

    def _deps_bg(self, features):
        def work():
            try:
                r = deps.install(features, yes=True)
                GLib.idle_add(self.toast, _("Dependencias instaladas") if r.get("ok")
                              else _("No se pudo instalar: {e}", e=r.get("error")))
                GLib.idle_add(self._tools_status)
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def tools_ollama(self):
        self._confirm(_("¿Instalar Ollama y el modelo?"),
                      _("Se descarga el instalador oficial de ollama.com y el modelo qwen2.5:1.5b (≈1 GB). "
                        "Es una petición externa; el texto que traduzcas luego se queda en tu máquina."),
                      self._ollama_bg, _("Instalar"))

    def _ollama_bg(self):
        def work():
            r = deps.install_ollama(yes=True)
            GLib.idle_add(self.toast, _("Ollama listo con {model}", model=r.get("model")) if r.get("ok")
                          else _("No se pudo instalar: {e}", e=r.get("error")))
            GLib.idle_add(self._tools_status)
        threading.Thread(target=work, daemon=True).start()

    # ── Errores y auditoría ──
    def render_errors(self):
        box = self.pages["errors"]
        clear(box)
        data = self.data.get("logs") or {}
        paths = data.get("paths") or logs.paths()
        head = hbox(8)
        head.append(lbl(_("Registros locales de VELA. No se envían a ningún servidor."), "kpi-sub", wrap=True))
        head.append(Gtk.Box(hexpand=True))
        ref = Gtk.Button(label=_("Actualizar"))
        ref.add_css_class("flat")
        ref.connect("clicked", lambda *_ign: self.refresh(full=True, force_slow=True))
        head.append(ref)
        folder = Gtk.Button(label=_("Abrir carpeta"))
        folder.add_css_class("flat")
        folder.connect("clicked", lambda *_ign: self._open_url("file://" + str(logs.state_dir())))
        head.append(folder)
        box.append(head)
        box.append(lbl(_("Auditoría: {audit} · Errores: {errors}", audit=paths.get("audit"),
                         errors=paths.get("errors")), "kpi-sub", wrap=True))

        row = hbox(12)
        err_card = card(_("Errores ({n})", n=len(data.get("errors") or [])))
        errs = data.get("errors") or []
        err_card.append(table([(_("Hora"), 1.0), (_("Nivel"), 0.7), (_("Mensaje"), 3.0), (_("Detalle"), 2.2)],
                              [[iso(e.get("ts")) if e.get("ts") else "—", str(e.get("level") or e.get("type") or "error"),
                                e.get("message") or "", _log_detail(e)] for e in errs], max_rows=200,
                              empty=_("sin errores registrados")))
        err_card.append(_log_buttons(self, "errors", errs))
        err_card.set_hexpand(True)
        row.append(err_card)

        audit_card = card(_("Auditoría ({n})", n=len(data.get("audit") or [])))
        audit = data.get("audit") or []
        audit_card.append(table([(_("Hora"), 1.0), (_("Actor"), 0.9), (_("Acción"), 1.5), (_("Detalle"), 3.0)],
                                [[iso(a.get("ts")) if a.get("ts") else "—", a.get("actor") or "—",
                                  a.get("action") or "", _log_detail(a)] for a in audit], max_rows=200,
                                empty=_("sin acciones registradas")))
        audit_card.append(_log_buttons(self, "audit", audit))
        audit_card.set_hexpand(True)
        row.append(audit_card)
        box.append(row)

    def _log_clear(self, kind):
        def done(_r):
            self.refresh_ui(_("Registro borrado"))
            return False
        self.call_bg("logs_clear", {"kind": kind}, done)

    # ── About ──
    def build_about(self):
        box = self.pages["about"]
        clear(box)
        head = hbox(16)
        try:
            img = Gtk.Image.new_from_file(str(BRAND_DIR / "vela-symbol-256.png"))
            img.set_pixel_size(96)
            head.append(img)
        except Exception:  # noqa: BLE001
            pass
        titles = vbox(4)
        titles.append(lbl("VELA", "brand-title"))
        titles.append(lbl(_(TAGLINE), "kpi-sub", wrap=True))
        titles.append(lbl(_("Vigilant Egress & Leak Analyst · versión {v}", v=about_mod.app_info()["version"]),
                          "kpi-sub", wrap=True))
        head.append(titles)
        box.append(card(None, head))
        left = card(_("Creador"))
        # avatar redondo de tamaño fijo: la imagen se ve entera escalada (antes se estiraba al ancho y se recortaba)
        self.about_avatar = Adw.Avatar(size=112, show_initials=True, text=about_mod.PROFILE.get("name") or about_mod.PROFILE.get("login") or "VELA",
                                       halign=Gtk.Align.START, valign=Gtk.Align.START)
        self._set_avatar(about_mod.BUNDLED_AVATAR if about_mod.BUNDLED_AVATAR.exists()
                         else BRAND_DIR / "vela-symbol-256.png")
        prof_row = hbox(16)
        prof_row.append(self.about_avatar)
        self.about_profile_lbl = lbl("", "td", wrap=True)
        self.about_profile_lbl.set_valign(Gtk.Align.CENTER)
        self.about_profile_lbl.set_hexpand(True)
        prof_row.append(self.about_profile_lbl)
        left.append(prof_row)
        links = hbox(8)
        gh = Gtk.Button(label="GitHub")
        gh.connect("clicked", lambda *_ign: self._open_url(about_mod.PROFILE["github"]))
        links.append(gh)
        web = Gtk.Button(label=_("Sitio web"))
        web.connect("clicked", lambda *_ign: self._open_url(about_mod.PROFILE["blog"]))
        links.append(web)
        cp = Gtk.Button(label=_("Copiar perfil"))
        cp.add_css_class("flat")
        cp.connect("clicked", lambda *_ign: self.copy(about_mod.PROFILE["github"], _("Perfil copiado")))
        links.append(cp)
        sync = Gtk.Button(label=_("Sincronizar perfil"))
        sync.add_css_class("suggested-action")
        sync.connect("clicked", lambda *_ign: self._about_sync())
        links.append(sync)
        left.append(links)
        box.append(left)
        info = about_mod.app_info()
        right = card(_("Aplicación"))
        right.append(table([(_("Campo"), 1.0), (_("Valor"), 3.0)], [
            [_("Versión"), info["version"]], [_("Python"), info["python"]], [_("GTK"), info["gtk"] or "—"],
            [_("libadwaita"), info["libadwaita"] or "—"], [_("Sistema"), info["platform"]],
            [_("Repositorio"), info["repo"]], [_("Licencia"), info["license"]]]))
        right.append(lbl(_("Funciones").upper(), "card-title"))
        right.append(lbl(" · ".join(t for _k, t, _i in PAGES), "kpi-sub", wrap=True))
        right.append(lbl(_("Créditos").upper(), "card-title"))
        right.append(lbl("\n".join("• " + x for x in info["credits"]), "kpi-sub", wrap=True))
        box.append(right)
        self._about_fill()

    def _open_url(self, url):
        try:
            Gio.AppInfo.launch_default_for_uri(url, None)
        except Exception as e:  # noqa: BLE001
            self.toast(str(e))

    def _about_fill(self, prof=None):
        prof = prof or about_mod.profile()
        self.about_profile_lbl.set_text(
            _("{name} (@{login})\n{bio}\n{location} · {blog}\nRepos: {repos} · Seguidores: {followers}",
              name=prof.get("name"), login=prof.get("login"), bio=prof.get("bio"), location=prof.get("location"),
              blog=prof.get("blog"), repos=prof.get("public_repos") or "—", followers=prof.get("followers") or "—")
            + (f"\n{prof['error']}" if prof.get("error") else ""))
        avatar = prof.get("avatar")
        if not avatar and about_mod.BUNDLED_AVATAR.exists():
            avatar = str(about_mod.BUNDLED_AVATAR)
        if prof.get("name") or prof.get("login"):
            self.about_avatar.set_text(prof.get("name") or prof.get("login"))
        if avatar and Path(avatar).exists():
            self._set_avatar(avatar)

    def _set_avatar(self, path):
        try:
            self.about_avatar.set_custom_image(Gdk.Texture.new_from_filename(str(path)))
        except Exception:  # noqa: BLE001
            self.about_avatar.set_custom_image(None)        # sin imagen: iniciales

    def _about_sync(self):
        from .. import config as config_mod
        try:
            cfg = config_mod.load()
        except Exception as e:  # noqa: BLE001
            self.toast(_("No se pudo leer la configuración: {e}", e=e))
            return
        if not (cfg.get("consent") or {}).get("about_profile_lookup"):
            dlg = Adw.AlertDialog(
                heading=_("¿Sincronizar el perfil de GitHub?"),
                body=_("VELA consultará api.github.com y descargará el avatar público de j0rd1s3rr4n0. "
                       "No envía datos personales; la petición sale desde tu conexión y se guarda en caché local."))
            dlg.add_response("cancel", _("Cancelar"))
            dlg.add_response("allow", _("Permitir y sincronizar"))
            dlg.set_response_appearance("allow", Adw.ResponseAppearance.SUGGESTED)
            dlg.connect("response", lambda _d, r: self._about_allow_sync() if r == "allow" else None)
            dlg.present(self)
            return
        self._about_sync_now()

    def _about_allow_sync(self):
        def done(_r):
            self.toast(_("Consentimiento guardado"))
            self._about_sync_now()
            return False
        self.call_bg("settings_set", {"changes": {"consent.about_profile_lookup": True}}, done)

    def _about_sync_now(self):
        self.about_profile_lbl.set_text(_("Sincronizando perfil público de GitHub…"))

        def work():
            try:
                prof = about_mod.profile(refresh=True)
                GLib.idle_add(self._about_fill, prof)
                GLib.idle_add(self.toast, _("Perfil sincronizado") if not prof.get("error")
                              else _("No se pudo sincronizar: {e}", e=prof.get("error")))
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def render_about(self):
        self._about_fill()

    def render_settings(self):
        box = self.pages["settings"]
        clear(box)
        s = self.data.get("settings")
        if not s:
            box.append(lbl(self.data.get("settings_error") or "cargando…"))
            return
        v = s["values"]
        auto = s.get("autostart") or {}

        box.append(self.appearance_group())
        box.append(self.language_group(v))
        box.append(self.notifications_group())

        def switch(group, key, title, subtitle, invert=False):
            r = Adw.SwitchRow(title=GLib.markup_escape_text(title), subtitle=GLib.markup_escape_text(subtitle))
            r.set_active(bool(v.get(key)) != invert)
            r.connect("notify::active", lambda row, _p: self.set_setting(key, row.get_active() != invert))
            group.add(r)

        g = Adw.PreferencesGroup(title=_("Monitorización y persistencia"),
                                 description=_("El historial solo se guarda mientras el daemon está en marcha."))
        ar = Adw.SwitchRow(title=_("Iniciar con la sesión"), subtitle=_("Servicio de usuario de systemd: monitoriza y guarda el "
                           "historial aunque la app esté cerrada") + ("" if auto.get("available") else _(" (systemd no disponible)")))
        ar.set_active(bool(auto.get("enabled")))
        ar.set_sensitive(bool(auto.get("available")))
        ar.connect("notify::active", self.on_autostart)
        g.add(ar)
        tr = Adw.SwitchRow(title=_("Icono en la bandeja del sistema"),
                           subtitle=_("Estado y controles desde la barra superior, también al iniciar sesión"))
        tr.set_active(bool(auto.get("tray_autostart")))
        tr.connect("notify::active", self.on_tray)
        g.add(tr)
        switch(g, "public_ip.require_tunnel", _("Comprobar la IP pública siempre"),
               _("Desactivado: solo por la VPN. Activado: también sin VPN (el servicio de eco ve tu IP real)"), invert=True)
        switch(g, "leakwatch.enabled", _("Vigilante de fugas en tiempo real"), _("Revisa las conexiones cada 2 s"))
        ret = Adw.SpinRow.new_with_range(0, 3650, 1)
        ret.set_title(_("Retención del historial (días)"))
        ret.set_subtitle(_("0 = sin límite"))
        ret.set_value(v.get("storage.retention_days") or 0)
        ret.connect("notify::value", lambda r, _p: self.set_setting("storage.retention_days", int(r.get_value()), quiet=True))
        g.add(ret)
        box.append(g)

        g = Adw.PreferencesGroup(title=_("Consentimientos"),
                                 description=_("Todo lo que genera tráfico hacia terceros o modifica el sistema."))
        for key, title, sub_ in (
                ("consent.direct_ip_checks", _("Consultar la IP pública por la ruta por defecto"), _("El servicio de eco verá tu IP de salida")),
                ("consent.tor_ip_checks", _("Comprobar la IP de salida de Tor"), _("Vía check.torproject.org a través de Tor")),
                ("consent.threat_intel_lookups", _("Threat intel (GreyNoise, VirusTotal, Shodan, Censys)"), _("Los servicios sabrán qué IPs consultas")),
                ("consent.active_dns_leak_test", _("Test activo de fugas DNS"), _("Un servicio externo verá tus resolvers")),
                ("consent.allow_rotation_changes", _("Permitir rotaciones reales"), _("Cambia conexiones VPN/proxy/Tor de verdad")),
                ("consent.allow_killswitch", _("Permitir el kill-switch propio (nftables)"), _("Necesita sudo sin contraseña o pkexec")),
                ("consent.allow_dns_changes", _("Permitir cifrar el DNS del sistema"), _("Modifica systemd-resolved; guarda copia y permite revertir")),
                ("consent.allow_mac_changes", _("Permitir cambiar la MAC"), _("Corta la conexión unos segundos y requiere pkexec/sudo")),
                ("consent.llm_remote", _("Permitir una API de traducción remota"), _("El texto saldría de tu máquina; por defecto solo LLM local")),
                ("consent.about_profile_lookup", _("Sincronizar el perfil del About"), _("Consulta api.github.com y descarga el avatar"))):
            switch(g, key, title, sub_)
        box.append(g)

        g = Adw.PreferencesGroup(title=_("Fugas y threat intel"))
        cr = Adw.ComboRow(title=_("Si se detecta una fuga"), subtitle=_("Aplicar el kill-switch exige el consentimiento de arriba"))
        cr.set_model(Gtk.StringList.new([_("Solo avisar"), _("Aplicar el kill-switch")]))
        cr.set_selected(1 if v.get("leakwatch.on_leak") == "killswitch" else 0)
        cr.connect("notify::selected", lambda r, _p: self.set_setting("leakwatch.on_leak",
                                                                       "killswitch" if r.get_selected() == 1 else "alert"))
        g.add(cr)
        switch(g, "intel.auto_live", _("Consultar automáticamente en VirusTotal las IPs a las que te conectas"),
               _("Puntuación en Tiempo real + aviso si es sospechosa. VirusTotal (Google) verá esos destinos"))
        nt = Adw.ComboRow(title=_("Notificar puntuaciones de VirusTotal"))
        nt.set_model(Gtk.StringList.new([_("Solo sospechosas o maliciosas"), _("Todas las IPs puntuadas")]))
        nt.set_selected(1 if v.get("intel.live_notify") == "all" else 0)
        nt.connect("notify::selected", lambda r, _p: self.set_setting("intel.live_notify",
                                                                       "all" if r.get_selected() == 1 else "flagged"))
        g.add(nt)
        lim = Adw.SpinRow.new_with_range(0, 5000, 10)
        lim.set_title(_("Tope diario de consultas automáticas"))
        lim.set_subtitle(_("La API gratuita de VirusTotal permite 500 al día y 4 por minuto"))
        lim.set_value(v.get("intel.live_daily_limit") or 400)
        lim.connect("notify::value", lambda r, _p: self.set_setting("intel.live_daily_limit", int(r.get_value()), quiet=True))
        g.add(lim)
        switch(g, "intel.via_tor", _("Consultas de threat intel por Tor"), _("Algunos servicios limitan o bloquean Tor"))
        switch(g, "intel.allow_direct", _("Permitir consultas sin VPN"), _("Saldrían desde tu IP real"))
        box.append(g)
        g = Adw.PreferencesGroup(title=_("Anomalías y traducción"),
                                 description=_("La línea base se calcula solo con tu historial local. El traductor "
                                               "usa Ollama/llama.cpp en localhost salvo que actives la API remota."))
        switch(g, "anomaly.enabled", _("Detectar anomalías de red"), _("Volumen, fan-out, procesos y destinos nuevos"))
        sn = Adw.ComboRow(title=_("Sensibilidad"))
        sn.set_model(Gtk.StringList.new([_("Baja"), _("Media"), _("Alta")]))
        sn.set_selected({"baja": 0, "media": 1, "alta": 2}.get(v.get("anomaly.sensitivity"), 1))
        sn.connect("notify::selected", lambda r, _p: self.set_setting(
            "anomaly.sensitivity", ["baja", "media", "alta"][r.get_selected()]))
        g.add(sn)
        wd = Adw.SpinRow.new_with_range(1, 90, 1)
        wd.set_title(_("Ventana de la línea base (días)"))
        wd.set_value(v.get("anomaly.window_days") or 14)
        wd.connect("notify::value", lambda r, _p: self.set_setting("anomaly.window_days", int(r.get_value()), quiet=True))
        g.add(wd)
        te = Adw.ComboRow(title=_("Motor de traducción"))
        te.set_model(Gtk.StringList.new(["auto", "ollama", "llamacpp", "openai"]))
        te.set_selected(["auto", "ollama", "llamacpp", "openai"].index(v.get("translate.engine") or "auto"))
        te.connect("notify::selected", lambda r, _p: self.set_setting(
            "translate.engine", ["auto", "ollama", "llamacpp", "openai"][r.get_selected()]))
        g.add(te)
        model = Adw.EntryRow(title=_("Modelo de traducción"))
        model.set_text(v.get("translate.model") or "qwen2.5:1.5b")
        model.connect("apply", lambda r: self.set_setting("translate.model", r.get_text()))
        g.add(model)
        box.append(g)
        box.append(self.map_group())
        box.append(self.update_group())
        box.append(self.uninstall_group())
        box.append(self.data_group())
        box.append(lbl(_("Guardado en {v1} (no se modifica tu config.toml)", v1=tilde(s['path'])), "kpi-sub"))

    def data_group(self):
        if getattr(self, "_data_grp", None) is not None:
            self._data_refresh()
            return self._data_grp
        g = Adw.PreferencesGroup(
            title=_("Datos"),
            description=_("Copia de seguridad, importación y borrado. Un backup puede contener datos personales y "
                          "claves: guárdalo en un lugar seguro."))
        self._data_row = Adw.ActionRow(title=_("Base de datos"))
        g.add(self._data_row)
        exp = Adw.ActionRow(title=_("Exportar datos"), subtitle=_("Historial, configuración, ajustes y/o secretos"))
        eb = Gtk.Button(label=_("Exportar"), valign=Gtk.Align.CENTER)
        eb.connect("clicked", lambda *_ign: self.data_export())
        exp.add_suffix(eb)
        g.add(exp)
        imp = Adw.ActionRow(title=_("Importar datos"), subtitle=_("Fusionar o reemplazar el historial actual"))
        ib = Gtk.Button(label=_("Importar"), valign=Gtk.Align.CENTER)
        ib.connect("clicked", lambda *_ign: self.data_import())
        imp.add_suffix(ib)
        g.add(imp)
        rst = Adw.ActionRow(title=_("Borrar datos"), subtitle=_("Historial o todos los datos de VELA (no borra el código)"))
        rb = Gtk.Button(label=_("Borrar…"), valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
        rb.connect("clicked", lambda *_ign: self.data_reset())
        rst.add_suffix(rb)
        g.add(rst)
        self._data_grp = g
        self._data_refresh()
        return g

    def _data_refresh(self):
        d = self.data.get("data_info") or {}
        if d.get("rows"):
            self._data_row.set_subtitle(_("{db} · sesiones {sessions} · eventos {events} · hallazgos {findings}",
                                          db=d.get("database"), sessions=d["rows"].get("sessions", 0),
                                          events=d["rows"].get("events", 0), findings=d["rows"].get("findings", 0)))

    def _file_save(self, cb, name):
        dlg = Gtk.FileDialog(title=_("Guardar backup"), initial_name=name)

        def done(d, res):
            try:
                f = d.save_finish(res)
                cb(f.get_path())
            except GLib.Error:
                pass
        dlg.save(self, None, done)

    def _file_open(self, cb):
        dlg = Gtk.FileDialog(title=_("Abrir backup"))

        def done(d, res):
            try:
                f = d.open_finish(res)
                cb(f.get_path())
            except GLib.Error:
                pass
        dlg.open(self, None, done)

    def data_export(self):
        box = vbox(6)
        checks = {}
        for key, label, active in (("history", _("Historial (sesiones, eventos, hallazgos)"), True),
                                   ("config", _("Configuración (config.toml)"), False),
                                   ("settings", _("Ajustes de la app"), True),
                                   ("secrets", _("Secretos (claves de API)"), False)):
            c = Gtk.CheckButton(label=label)
            c.set_active(active)
            checks[key] = c
            box.append(c)
        dlg = Adw.AlertDialog(heading=_("¿Qué incluir en el backup?"),
                              body=_("El historial se exporta siempre con credenciales redactadas."))
        dlg.set_extra_child(box)
        dlg.add_response("cancel", _("Cancelar"))
        dlg.add_response("go", _("Elegir destino"))
        dlg.set_response_appearance("go", Adw.ResponseAppearance.SUGGESTED)
        dlg.connect("response", lambda _d, r: self._file_save(
            lambda path: self._data_export_bg(path, {k: c.get_active() for k, c in checks.items()},
                                              checks["secrets"].get_active()),
            f"vela-backup-{time.strftime('%Y%m%d-%H%M')}.json") if r == "go" else None)
        dlg.present(self)

    def _data_export_bg(self, path, include, secrets):
        include = {**include, "secrets": bool(secrets)}

        def work():
            try:
                r = self.b.call("data_export", path=path, include=include)
                GLib.idle_add(self.toast, _("Backup escrito en {path}", path=tilde(r["path"])))
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def data_import(self):
        def chosen(path):
            try:
                info = backup_mod.inspect_bundle(path)
            except Exception as e:  # noqa: BLE001
                self.toast(_("Backup no válido: {e}", e=e))
                return
            body = _("Manifiesto de VELA {version} · {size} bytes · partes: {parts}",
                     version=(info.get("manifest") or {}).get("version", "?"), size=info["size"],
                     parts=", ".join(info.get("parts") or []))
            dlg = Adw.AlertDialog(heading=_("¿Importar este backup?"), body=body)
            sec = None
            if info.get("has", {}).get("secrets"):
                box = vbox(6)
                sec = Gtk.CheckButton(label=_("Incluir también los secretos del backup"))
                box.append(sec)
                dlg.set_extra_child(box)
            dlg.add_response("cancel", _("Cancelar"))
            dlg.add_response("merge", _("Fusionar"))
            dlg.add_response("replace", _("Reemplazar historial"))
            dlg.set_response_appearance("replace", Adw.ResponseAppearance.DESTRUCTIVE)
            dlg.connect("response", lambda _d, r: self._data_import_bg(path, r, bool(sec and sec.get_active()))
                         if r in ("merge", "replace") else None)
            dlg.present(self)
        self._file_open(chosen)

    def _data_import_bg(self, path, mode, secrets=False):
        def work():
            try:
                r = self.b.call("data_import", path=path, mode=mode,
                                include={"history": True, "config": True, "settings": True, "secrets": secrets})
                msg = _("Importado: {n}", n=json.dumps(r.get("history", {}).get("imported", {}))) if r.get("ok") else _("Error al importar")
                if r.get("restart_required"):
                    msg += _(" · reinicia VELA para aplicar la configuración importada")
                GLib.idle_add(self.toast, msg)
                GLib.idle_add(self.refresh_ui)
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    def data_reset(self):
        box = vbox(6)
        keep = Gtk.CheckButton(label=_("Guardar una copia antes de borrar"))
        keep.set_active(True)
        box.append(keep)
        dlg = Adw.AlertDialog(heading=_("¿Qué quieres borrar?"),
                              body=_("Esto no se puede deshacer. El historial incluye sesiones, eventos y hallazgos; "
                                     "«todo» borra también ajustes, configuración y secretos."))
        dlg.set_extra_child(box)
        dlg.add_response("cancel", _("Cancelar"))
        dlg.add_response("history", _("Solo historial"))
        dlg.add_response("all", _("Todos los datos"))
        dlg.set_response_appearance("all", Adw.ResponseAppearance.DESTRUCTIVE)
        dlg.connect("response", lambda _d, r: self._data_reset_bg(r, keep.get_active())
                     if r in ("history", "all") else None)
        dlg.present(self)

    def _data_reset_bg(self, scope, keep):
        def work():
            try:
                r = self.b.call("data_reset", scope=scope, keep_backup=keep)
                msg = _("Datos borrados") if r.get("ok") else _("No se pudo borrar")
                if r.get("restart_required"):
                    msg += _(" · reinicia VELA para aplicar los valores por defecto")
                GLib.idle_add(self.toast, msg)
                GLib.idle_add(self.refresh_ui)
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la interfaz"), e)
                GLib.idle_add(self.toast, _("Error: {e}", e=e))
        threading.Thread(target=work, daemon=True).start()

    # ── mapa OpenStreetMap ──
    MAP_VIA = [("auto", _("Automático: Tor y, si no hay, la VPN")), ("tor", _("Solo por Tor")), ("vpn", _("Solo por la VPN")),
               ("direct", _("Directo (tu IP real; solo descarga ficheros públicos del mundo entero)"))]

    def map_group(self):
        """Grupo persistente (sobrevive a los redibujados de Ajustes mientras se genera el mapa)."""
        if getattr(self, "_map_grp", None) is not None:
            self._map_status_update()
            return self._map_grp
        g = Adw.PreferencesGroup(
            title=_("Mapa (OpenStreetMap)"),
            description=_("Mapa propio hecho con datos de OpenStreetMap e incorporado en la app: costas, países, "
                        "capitales y ciudades, con los colores del tema y más detalle al acercar. Funciona sin conexión: "
                        "mirar el mapa no pide nada a ningún servidor. Actualizarlo es opcional (descarga ≈25 MB)."))
        self._map_row = Adw.ActionRow(title=_("Estado"))
        g.add(self._map_row)
        self._map_via = Adw.ComboRow(title=_("Descargar por"))
        self._map_via.set_model(Gtk.StringList.new([t for _ign, t in self.MAP_VIA]))
        g.add(self._map_via)
        self._map_bar = Gtk.ProgressBar(show_text=True, visible=False, valign=Gtk.Align.CENTER, hexpand=True)
        self._map_btn = Gtk.Button(label=_("Generar mapa"), valign=Gtk.Align.CENTER, css_classes=["suggested-action"])
        self._map_btn.connect("clicked", lambda _b: self.map_build())
        act = Adw.ActionRow(title=_("Actualizar con datos recientes de OpenStreetMap"),
                            subtitle=_("Fuentes: osmdata.openstreetmap.de (tierra) y Overpass API (nombres de lugares)"))
        act.add_suffix(self._map_bar)
        act.add_suffix(self._map_btn)
        g.add(act)
        self._map_grp = g
        self._map_status_update()
        return g

    def _map_status_update(self):
        st = osmmap.status()
        if st["installed"]:
            self._map_row.set_subtitle(_("En uso: {source} · {v3:.1f} MB · {places} lugares · datos de {v7} · {attribution} (ODbL)", source=st['source'], v3=st['bytes'] / 1e6, places=st['places'], v7=iso(st['created'])[:10], attribution=st['attribution']))
            self._map_btn.set_label(_("Actualizar"))
        else:
            self._map_row.set_subtitle(_("No instalado: el mapa usa un contorno básico dibujado a mano"))

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
                        _ign, f, msg = line.split(" ", 2)
                        GLib.idle_add(lambda f=float(f), m=msg: (self._map_bar.set_fraction(f), self._map_bar.set_text(m),
                                                                False)[-1])
                    elif line.startswith("error "):
                        err = line[6:]
                    elif line.startswith("result "):
                        res = json.loads(line[7:])
                pr.wait()
                if pr.returncode and not err:
                    err = _("código {returncode}", returncode=pr.returncode)
            except Exception as e:  # noqa: BLE001
                err = str(e)
            GLib.idle_add(self._map_done, err, res)
        threading.Thread(target=work, daemon=True).start()

    def _map_done(self, err, res):
        self._map_btn.set_sensitive(True)
        self._map_bar.set_visible(False)
        if err:
            self.toast(_("No se pudo generar el mapa: {err}", err=err))
        else:
            extra = _(" (sin nombres: {places_error})", places_error=res['places_error']) if res and res.get("places_error") else ""
            self.toast(_("Mapa OpenStreetMap listo{extra}", extra=extra))
            self.mapv._base = None
            self.mapv.queue_draw()
        self._map_status_update()
        return False

    # ── apariencia (persistente: no se reconstruye con cada refresco de Ajustes) ──
    APPEARANCE = [("system", _("Seguir al sistema")), ("light", _("Claro")), ("dark", _("Oscuro"))]
    DENSITY = [("comfortable", _("Cómoda")), ("compact", _("Compacta"))]
    MOTION = [("system", _("Según el sistema")), ("reduced", _("Reducido")), ("full", _("Completo"))]

    def appearance_group(self):
        if getattr(self, "_app_grp", None) is not None:
            return self._app_grp
        prefs = self.themes.prefs
        g = Adw.PreferencesGroup(title=_("Apariencia"),
                                 description=_("Se aplica al instante y se guarda en tus ajustes. El daemon y las "
                                               "conexiones no se tocan."))
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=5, min_children_per_line=2,
                           column_spacing=10, row_spacing=10, homogeneous=True)
        flow.set_margin_bottom(10)
        self._theme_cards = {}
        for tid in themes.ids():
            th = themes.get(tid)
            btn = Gtk.Button(tooltip_text=_(th["description"]))
            btn.add_css_class("flat")
            inner = vbox(6)
            inner.append(ThemePreview(tid))
            inner.append(lbl(th["name"], "td-strong"))
            btn.set_child(inner)
            btn.update_property([Gtk.AccessibleProperty.LABEL], [th["name"]])
            btn.connect("clicked", lambda _b, t=tid: self.set_appearance(theme=t))
            card_ = vbox(0)
            card_.add_css_class("card")
            card_.add_css_class("theme-card")
            card_.append(btn)
            self._theme_cards[tid] = card_
            flow.append(card_)
        g.add(flow)
        g2 = Adw.PreferencesGroup()
        self._app_combos = {}

        def combo(title, subtitle, options, key):
            r = Adw.ComboRow(title=title, subtitle=subtitle)
            r.set_model(Gtk.StringList.new([t for _k, t in options]))
            keys = [k for k, _t in options]
            r.set_selected(keys.index(prefs[key]) if prefs[key] in keys else 0)
            h = r.connect("notify::selected", lambda row, _p: self.set_appearance(**{key: keys[row.get_selected()]}))
            self._app_combos[key] = (r, keys, h)
            g2.add(r)
        combo(_("Modo"), _("Claro, oscuro o el que use tu escritorio (cambia solo si el escritorio cambia)"),
              self.APPEARANCE, "appearance")
        combo(_("Densidad"), _("Compacta reduce márgenes y filas; el texto mantiene su tamaño"), self.DENSITY, "density")
        combo(_("Animaciones"), _("Reducido desactiva las transiciones de la interfaz"), self.MOTION, "motion")
        a11y = Adw.ActionRow(title=_("Estados con icono y texto"),
                             subtitle=_("Siempre activo: ningún estado se indica solo con color (✔ ▲ ◆ ✖ ● y su texto)"))
        a11y.add_suffix(Gtk.Image.new_from_icon_name("emblem-ok-symbolic"))
        g2.add(a11y)
        both = vbox(18)
        both.append(g)
        both.append(g2)
        self._app_grp = both
        self.themes.listeners.append(lambda *_a: self._appearance_sync())
        self._appearance_sync()
        return both

    def _appearance_sync(self):
        prefs = self.themes.prefs
        for tid, c in getattr(self, "_theme_cards", {}).items():
            (c.add_css_class if tid == prefs["theme"] else c.remove_css_class)("selected")
        for key, (row, keys, h) in getattr(self, "_app_combos", {}).items():
            if prefs[key] in keys and row.get_selected() != keys.index(prefs[key]):
                row.handler_block(h)
                row.set_selected(keys.index(prefs[key]))
                row.handler_unblock(h)

    def set_appearance(self, **changes):
        before = dict(self.themes.prefs)
        prefs = self.themes.apply(**changes)
        diff = {f"ui.{k}": v for k, v in prefs.items() if before.get(k) != v}
        self._appearance_sync()
        if diff:
            self.call_bg("settings_set", {"changes": diff})

    # ── actualizaciones (persistente; solo bajo petición, por Tor/VPN) ──
    def update_group(self):
        if getattr(self, "_upd_grp", None) is not None:
            return self._upd_grp
        g = Adw.PreferencesGroup(
            title=_("Actualizaciones"),
            description=_("VELA nunca busca actualizaciones por su cuenta. Al pulsar «Buscar», consulta tu repositorio git "
                          "por Tor o por la VPN y te enseña los cambios antes de instalarlos. Actualizar solo avanza tu "
                          "copia (sin tocar cambios locales) y reinicia el servicio unos segundos."))
        self._upd_row = Adw.ActionRow(title=_("Versión instalada"))
        g.add(self._upd_row)
        self._upd_via = Adw.ComboRow(title=_("Consultar por"))
        self._upd_via.set_model(Gtk.StringList.new([t for _ign, t in self.UPD_VIA]))
        g.add(self._upd_via)
        self._upd_res = Adw.ExpanderRow(title=_("Novedades"), subtitle=_("Pulsa «Buscar» para comprobarlo"),
                                        enable_expansion=False)
        g.add(self._upd_res)
        self._upd_bar = Gtk.ProgressBar(show_text=True, visible=False, valign=Gtk.Align.CENTER, hexpand=True)
        self._upd_check = Gtk.Button(label=_("Buscar"), valign=Gtk.Align.CENTER)
        self._upd_check.connect("clicked", lambda _b: self.update_run(check=True))
        self._upd_apply = Gtk.Button(label=_("Actualizar"), valign=Gtk.Align.CENTER, sensitive=False,
                                     css_classes=["suggested-action"])
        self._upd_apply.connect("clicked", lambda _b: self.update_confirm())
        act = Adw.ActionRow(title=_("Buscar e instalar"))
        act.add_suffix(self._upd_bar)
        act.add_suffix(self._upd_check)
        act.add_suffix(self._upd_apply)
        g.add(act)
        self._upd_grp = g
        self._upd_rows = []
        self._update_status()
        return g

    UPD_VIA = [("auto", _("Automático: Tor y, si no hay, la VPN")), ("tor", _("Solo por Tor")),
               ("vpn", _("Solo por la VPN")), ("direct", _("Directo (el servidor git verá tu IP real)"))]

    def _update_status(self):
        from .. import updater
        st = updater.status()
        cm = f" · {st['installed_commit'][:7]}" if st.get("installed_commit") else ""
        src = _(" · origen {src}", src=tilde(st["source"])) if st.get("source") else ""
        self._upd_row.set_subtitle(f"VELA {st['installed_version']}{cm}{src}" + (f"\n{st['hint']}" if st.get("hint") else ""))
        self._upd_check.set_sensitive(bool(st.get("git")))

    def update_run(self, check, protect="restart"):
        import subprocess
        via = self.UPD_VIA[self._upd_via.get_selected()][0]
        cmd = [sys.executable, "-m", "vela", "update", "--via", via, "--progress"] + (
            ["--check"] if check else ["--yes", "--protect", protect])
        root = Path(__file__).resolve().parents[2]
        self._upd_check.set_sensitive(False)
        self._upd_apply.set_sensitive(False)
        self._upd_bar.set_visible(True)
        self._upd_bar.set_fraction(0.05)
        self._upd_bar.set_text(_("consultando…") if check else _("actualizando…"))
        if check:
            self._upd_bar.pulse()

        def work():
            err, res = None, None
            try:
                import os
                pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=str(root),
                                      env={**os.environ, "PYTHONPATH": str(root)})
                for line in pr.stdout:
                    line = line.rstrip()
                    if line.startswith("progress "):
                        _ign, f, msg = line.split(" ", 2)
                        GLib.idle_add(lambda f=float(f), m=msg: (self._upd_bar.set_fraction(f), self._upd_bar.set_text(m),
                                                                False)[-1])
                    elif line.startswith("error "):
                        err = line[6:]
                    elif line.startswith("result "):
                        res = json.loads(line[7:])
                pr.wait()
                if pr.returncode and not err:
                    err = _("código {returncode}", returncode=pr.returncode)
            except Exception as e:  # noqa: BLE001
                err = str(e)
            GLib.idle_add(self._update_done, check, err, res)
        threading.Thread(target=work, daemon=True).start()

    def _update_done(self, check, err, res):
        self._upd_bar.set_visible(False)
        self._update_status()
        for r in self._upd_rows:
            self._upd_res.remove(r)
        self._upd_rows = []
        if err:
            self._upd_res.set_subtitle(_("No se pudo comprobar: {err}", err=err))
            self._upd_res.set_enable_expansion(False)
            self.toast(_("Actualizaciones: {err}", err=err))
            return False
        if not check:
            self._upd_res.set_subtitle(res.get("message") or "")
            if res.get("updated"):
                if res.get("killswitch_left_on"):
                    self.toast(res.get("message") or "")
                    return False
                self.toast(_("VELA actualizado: se vuelve a abrir con la versión nueva…"))
                GLib.timeout_add(1500, self._relaunch)           # «cerrar y que posteriormente se abra»
            return False
        if not res.get("available"):
            self._upd_res.set_subtitle(_("Ya tienes la última versión (consultado por {route})", route=res.get("route")))
            self._upd_res.set_enable_expansion(False)
            return False
        if res.get("behind"):
            sub = _("{n} cambios nuevos{v} · consultado por {route}", n=res["behind"], route=res.get("route"),
                    v=_(" · versión {v}", v=res["new_version"]) if res.get("new_version") else "")
        else:
            sub = _("El clon ya tiene una versión más nueva que la instalada")
        blockers = []
        if res.get("dirty"):
            blockers.append(_("Tienes cambios sin guardar en el clon: guárdalos o descártalos antes de actualizar."))
        if res.get("ahead"):
            blockers.append(_("Tu rama tiene {n} commits propios que no están en el remoto: resuélvelo con git.", n=res["ahead"]))
        self._upd_res.set_subtitle(sub + ("\n" + " ".join(blockers) if blockers else ""))
        for cm in res.get("commits") or []:
            r = Adw.ActionRow(title=GLib.markup_escape_text(cm["subject"]), subtitle=f"{cm['id']} · {cm['date']}")
            self._upd_res.add_row(r)
            self._upd_rows.append(r)
        self._upd_res.set_enable_expansion(bool(self._upd_rows))
        self._upd_res.set_expanded(bool(self._upd_rows))
        self._upd_apply.set_sensitive(not blockers)
        return False

    # ── desinstalar ──
    def uninstall_group(self):
        g = Adw.PreferencesGroup(title=_("Desinstalar"),
                                 description=_("Quita el servicio, la bandeja, el lanzador, los comandos y el programa. Tus "
                                               "datos se conservan salvo que pidas borrarlos. Tu repositorio git no se toca."))
        row = Adw.ActionRow(title=_("Desinstalar VELA"),
                            subtitle=_("También desde el menú de aplicaciones (clic derecho en VELA) o con «vela uninstall»"))
        b = Gtk.Button(label=_("Desinstalar…"), valign=Gtk.Align.CENTER, css_classes=["destructive-action"])
        b.connect("clicked", lambda _b: self.uninstall_dialog())
        row.add_suffix(b)
        g.add(row)
        return g

    def uninstall_dialog(self):
        from .. import uninstall
        from ..util import tilde
        p = uninstall.plan(False)
        d = Adw.AlertDialog(heading=_("¿Desinstalar VELA?"),
                            body=_("Se quitarán el servicio velad, la bandeja, el lanzador, los comandos «vela» y «velad» y "
                                   "la copia instalada ({n} elementos). La app se cerrará al terminar.",
                                   n=len(p["files"]) + len(p["dirs"])))
        purge = Gtk.CheckButton(label=_("Borrar también mis datos: historial, ajustes y claves de API (no se puede deshacer)"))
        extra = vbox(6)
        extra.append(purge)
        data = [tilde(x) for x in uninstall.data_dirs() if x.exists()]
        if data:
            extra.append(lbl(", ".join(data), "kpi-hint", wrap=True))
        d.set_extra_child(extra)
        d.add_response("cancel", _("Cancelar"))
        d.add_response("go", _("Desinstalar"))
        d.set_response_appearance("go", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_default_response("cancel")
        d.set_close_response("cancel")
        d.connect("response", lambda _d, r: r == "go" and self._uninstall_run(purge.get_active()))
        d.present(self)
        return False

    def _uninstall_run(self, purge):
        from .. import uninstall
        self.toast(_("Desinstalando VELA…"))

        def work():
            try:
                res = uninstall.run(purge)
                err = res["errors"]
            except Exception as e:  # noqa: BLE001
                err = [str(e)]
            GLib.idle_add(self._uninstall_done, err)
        threading.Thread(target=work, daemon=True).start()

    def _uninstall_done(self, errors):
        d = Adw.AlertDialog(heading=_("VELA desinstalado") if not errors else _("Desinstalado con avisos"),
                            body=("\n".join(errors) if errors else
                                  _("Gracias por usar VELA. Para volver a instalarlo: ./install.sh desde el repositorio.")))
        d.add_response("close", _("Cerrar VELA"))
        d.connect("response", lambda *_a: self.get_application().quit())
        d.present(self)
        return False

    def update_confirm(self):
        """La descarga ya se ha hecho (con VELA en marcha). Antes de parar VELA para cambiar de versión, el usuario
        elige: kill-switch hasta que arranque la versión nueva, o cerrar y reabrir sin protección."""
        from .. import updater
        opts = updater.protection_options()
        body = _("Para terminar hay que parar VELA unos segundos, instalar la versión nueva y arrancarla. Mientras "
                 "está parado no vigila tus conexiones ni puede activar el kill-switch automático si hay una fuga.\n\n"
                 "• Con kill-switch: se bloquea todo lo que no vaya por la VPN, Tor o la red local hasta que la versión "
                 "nueva responde (permiso solo para esta actualización; puede pedirte la contraseña).\n"
                 "• Sin protección: VELA se cierra y se vuelve a abrir; durante esos segundos tu IP real podría quedar "
                 "expuesta si algo sale fuera del túnel.\n\nTus datos y ajustes se conservan.")
        if opts.get("killswitch_already"):
            body += "\n" + _("El kill-switch ya está activo: se mantiene durante el cambio.")
        elif not opts.get("killswitch"):
            body += "\n" + _("Kill-switch no disponible ahora: {why}", why=opts.get("killswitch_reason") or "—")
        d = Adw.AlertDialog(heading=_("¿Cómo cambiar a la versión nueva?"), body=body)
        d.add_response("cancel", _("Ahora no"))
        d.add_response("restart", _("Sin protección"))
        d.add_response("killswitch", _("Con kill-switch"))
        d.set_response_appearance("restart", Adw.ResponseAppearance.DESTRUCTIVE)
        d.set_response_appearance("killswitch", Adw.ResponseAppearance.SUGGESTED)
        d.set_response_enabled("killswitch", bool(opts.get("killswitch")))
        d.set_default_response("killswitch" if opts.get("killswitch") else "cancel")
        d.connect("response", lambda _d, r: r in ("killswitch", "restart") and self.update_run(check=False, protect=r))
        d.present(self)

    def _relaunch(self):
        """Vuelve a abrir la app con el código recién instalado."""
        import os
        os.environ.pop("VELA_LANG", None)
        root = str(Path(__file__).resolve().parents[2])
        os.environ["PYTHONPATH"] = root + (":" + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
        os.execv(sys.executable, [sys.executable, "-m", "vela", "app"])

    # ── idioma ──
    LANG_CODES = ["auto", "es", "en", "ca", "pt", "fr", "de"]

    def language_group(self, v):
        from .. import i18n
        g = Adw.PreferencesGroup(title=_("Idioma") + " · Language")
        row = Adw.ComboRow(title=_("Idioma de la interfaz"),
                           subtitle=_("Automático usa el idioma del sistema. Se aplica al reiniciar la app."))
        names = [_("Automático (sistema: {lang})", lang=i18n.LANGS.get(i18n._from_env() or i18n.FALLBACK))]
        names += [i18n.LANGS[c] for c in self.LANG_CODES[1:]]
        row.set_model(Gtk.StringList.new(names))
        cur = v.get("ui.language") or "auto"
        row.set_selected(self.LANG_CODES.index(cur) if cur in self.LANG_CODES else 0)

        def changed(r, _p):
            code = self.LANG_CODES[r.get_selected()]
            if code == (v.get("ui.language") or "auto"):
                return
            v["ui.language"] = code
            self.call_bg("settings_set", {"changes": {"ui.language": code}}, lambda _r: self.ask_restart())
        row.connect("notify::selected", changed)
        g.add(row)
        return g

    def notifications_group(self):
        from .. import notifications
        st = notifications.status()
        g = Adw.PreferencesGroup(
            title=_("Notificaciones"),
            description=_("Avisos de escritorio de VELA. Puedes silenciarlos temporalmente o hasta que los reactives."))
        self._notif_status = Adw.ActionRow(title=_("Estado"), subtitle=notifications.describe(st))
        g.add(self._notif_status)
        self._notif_switch = Adw.SwitchRow(title=_("Notificaciones activas"),
                                           subtitle=_("Desactivado = silencio indefinido"))
        self._notif_switch.set_active(bool(st["enabled"]))
        self._notif_handler = self._notif_switch.connect("notify::active", self.on_notifications_switch)
        g.add(self._notif_switch)
        row = Adw.ActionRow(title=_("Silenciar temporalmente"),
                            subtitle=_("El silencio termina solo; «Reactivar» lo cancela antes"))
        for label, secs in ((_("15 min"), 900), (_("1 h"), 3600), (_("8 h"), 8 * 3600), (_("24 h"), 24 * 3600)):
            b = Gtk.Button(label=label, valign=Gtk.Align.CENTER)
            b.add_css_class("flat")
            b.connect("clicked", lambda _b, s=secs: self.set_notifications(s))
            row.add_suffix(b)
        off = Gtk.Button(label=_("Indefinidamente"), valign=Gtk.Align.CENTER)
        off.add_css_class("flat")
        off.connect("clicked", lambda *_ign: self.set_notifications(None))
        row.add_suffix(off)
        on = Gtk.Button(label=_("Reactivar"), valign=Gtk.Align.CENTER)
        on.add_css_class("suggested-action")
        on.connect("clicked", lambda *_ign: self.set_notifications("on"))
        row.add_suffix(on)
        g.add(row)
        return g

    def _refresh_notifications_group(self):
        from .. import notifications
        st = notifications.status()
        if hasattr(self, "_notif_status"):
            self._notif_status.set_subtitle(notifications.describe(st))
        if hasattr(self, "_notif_switch"):
            self._notif_switch.handler_block(self._notif_handler)
            self._notif_switch.set_active(bool(st["enabled"]))
            self._notif_switch.handler_unblock(self._notif_handler)

    def on_notifications_switch(self, row, _p):
        from .. import notifications
        st = notifications.enable() if row.get_active() else notifications.disable()
        self._refresh_notifications_group()
        self.toast(_("Notificaciones: {v1}", v1=notifications.describe(st)))

    def set_notifications(self, seconds):
        from .. import notifications
        st = notifications.enable() if seconds == "on" else notifications.mute(seconds)
        self._refresh_notifications_group()
        self.toast(_("Notificaciones: {v1}", v1=notifications.describe(st)))

    def ask_restart(self, heading=None, body=None):
        d = Adw.AlertDialog(heading=heading or _("Idioma cambiado"),
                            body=body or _("Reinicia VELA para ver toda la interfaz en el nuevo idioma."))
        d.add_response("later", _("Más tarde"))
        d.add_response("restart", _("Reiniciar ahora"))
        d.set_response_appearance("restart", Adw.ResponseAppearance.SUGGESTED)

        def done(dlg, res):
            if dlg.choose_finish(res) == "restart":
                import os
                os.environ.pop("VELA_LANG", None)
                root = str(Path(__file__).resolve().parents[2])
                os.environ["PYTHONPATH"] = root + (":" + os.environ["PYTHONPATH"] if os.environ.get("PYTHONPATH") else "")
                os.execv(sys.executable, [sys.executable, "-m", "vela", "app"])
        d.choose(self, None, done)

    def set_setting(self, key, value, quiet=False):
        self.call_bg("settings_set", {"changes": {key: value}},
                     lambda r: (None if quiet else self.toast(_("Ajuste guardado")),
                                self.call_bg("settings_get", {}, lambda s: self.data.__setitem__("settings", s))))

    def on_tray(self, row, _p):
        from .. import autostart
        if row.get_active():
            autostart.tray_enable()
            self.toast(_("Icono de bandeja activado"))
        else:
            autostart.tray_disable()
            self.toast(_("Icono de bandeja desactivado"))

    def on_autostart(self, row, _p):
        from .. import autostart
        want = row.get_active()

        def work():
            res = autostart.enable() if want else autostart.disable()
            GLib.idle_add(self.toast, (_("Arranque con la sesión activado") if want else _("Arranque con la sesión desactivado"))
                          if res.get("ok") else f"systemd: {res.get('error')}")
            if want:
                ensure_daemon()
        threading.Thread(target=work, daemon=True).start()

    def render_prof(self):
        box = self.pages["prof"]
        clear(box)
        prof = self.data.get("profiles") or {}
        box.append(lbl(_("Un perfil describe lo que quieres exigir. Que esté activo no significa que se cumpla: "
                         "la sección «Comprobado ahora» del perfil activo muestra lo que el motor observa de verdad."),
                       "kpi-sub", wrap=True))
        flow = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=3, min_children_per_line=1,
                           column_spacing=12, row_spacing=12, homogeneous=False)
        for name, p in (prof.get("profiles") or {}).items():
            active = name == prof.get("active")
            inner = vbox(8)
            inner.append(lbl(p.get("description") or "", "kpi-sub", wrap=True))
            inner.append(lbl(_("Exige").upper(), "card-title"))
            tags = Gtk.FlowBox(selection_mode=Gtk.SelectionMode.NONE, max_children_per_line=3, column_spacing=6,
                               row_spacing=6, halign=Gtk.Align.START)
            for on, yes, no in ((p.get("require_vpn"), _("VPN obligatoria"), _("VPN opcional")),
                                (p.get("use_tor"), _("Tor obligatorio"), _("Sin Tor")),
                                (p.get("require_killswitch"), _("Kill-switch obligatorio"), _("Kill-switch opcional"))):
                tags.append(pill("info" if on else "neutral", yes if on else no, icon=False))
            inner.append(tags)
            inner.append(table([(_("Política"), 1.0), (_("Valor"), 2.0)], [
                [_("DNS"), str(p.get("dns_policy") or "—")],
                [_("Retención"), _("{n} días", n=p.get("retention_days")) if p.get("retention_days") else _("sin límite")],
                [_("Países prohibidos"), ", ".join(p.get("forbidden_countries") or []) or "—"],
                [_("Países permitidos"), ", ".join(p.get("allowed_countries") or []) or _("todos")]]))
            if active:
                inner.append(lbl(_("Comprobado ahora").upper(), "card-title"))
                inner.append(self._profile_checks(p))
                suffix = pill("info", _("Perfil activo"), icon=False)
            else:
                suffix = Gtk.Button(label=_("Activar"))
                suffix.add_css_class("flat")
                suffix.connect("clicked", lambda _b, n=name: self.call_bg(
                    "profile_activate", {"name": n},
                    lambda r: (self.toast(_("Perfil activo: {n}", n=n)), self.refresh_ui())))
            c = card(name, inner, suffix)
            if active:
                c.add_css_class("profile-active")
            c.set_size_request(380, -1)
            flow.append(c)
        box.append(flow)

    def _profile_checks(self, p):
        """Requisito del perfil frente a lo observado por el motor (no se deduce nada del propio perfil)."""
        st = self.data.get("status") or {}
        net = st.get("net") or {}
        tunnel = bool((net.get("via_tunnel") or {}).get("ipv4"))
        tor = st.get("tor") or {}
        tor_ok = bool(tor.get("circuit_established"))
        rp = ((st.get("killswitch") or {}).get("external") or {}).get("route_protection") or {}
        ks_ok = bool(rp) and rp.get("ipv4", {}).get("state") == "bloqueado" and bool(net.get("tunnels"))
        enc = (st.get("dns") or {}).get("encrypted")

        def row(need, ok, ok_txt, bad_txt):
            if ok:
                return pill("good", ok_txt)
            return pill("critical" if need else "neutral", bad_txt + (_(" · exigido") if need else ""))
        rows = [
            [_("Túnel VPN"), row(p.get("require_vpn"), tunnel, _("Tráfico por el túnel"), _("Sin túnel"))],
            [_("Tor"), row(p.get("use_tor"), tor_ok, _("Circuito establecido"), _("Sin circuito"))],
            [_("Kill-switch"), row(p.get("require_killswitch"), ks_ok, _("Bloquea si cae el túnel"), _("No verificado"))],
            [_("DNS"), pill("good", _("Cifrado")) if enc else pill("warning" if enc is False else "neutral",
                                                                     _("En claro") if enc is False else _("Sin verificar"))],
        ]
        return table([(_("Requisito"), 1.0), (_("Observado"), 2.0)], rows)

class App(Adw.Application):
    def __init__(self, backend=None):
        super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.DEFAULT_FLAGS)
        self.backend = backend
        self.win = None
        self.pending_uninstall = False
        # acción «app.uninstall»: la usa el lanzador (clic derecho → Desinstalar VELA), también si la app ya está abierta
        act = Gio.SimpleAction.new("uninstall", None)
        act.connect("activate", lambda *_a: (setattr(self, "pending_uninstall", True), self.activate()))
        self.add_action(act)

    def do_activate(self):
        logs.setup()
        if self.win is None:
            # tema: se aplica ANTES de crear la ventana (preferencias leídas del fichero de ajustes)
            self.themes = theme_mod.ThemeManager(Gdk.Display.get_default())
            # icono de la ventana: el SVG del paquete, visible como «<APP_ID>» para el tema de iconos
            theme = Gtk.IconTheme.get_for_display(Gdk.Display.get_default())
            theme.add_search_path(str(_icon_dir()))
            Gtk.Window.set_default_icon_name(APP_ID)
            if self.backend is None:
                ensure_daemon()
            self.win = Window(self, self.backend or connect())
        self.win.present()
        if self.pending_uninstall:
            self.pending_uninstall = False
            GLib.timeout_add(600, self.win.uninstall_dialog)


def _icon_dir() -> Path:
    """Tema de iconos privado con el icono nombrado como el APP_ID (lo que buscan la ventana y el lanzador)."""
    import shutil
    from ..util import xdg_dir
    d = xdg_dir("data") / "icons"
    for n in ICON_SIZES:
        dst = d / "hicolor" / f"{n}x{n}" / "apps" / f"{APP_ID}.png"
        src = BRAND_DIR / f"vela-app-{n}.png"
        if src.exists() and (not dst.exists() or dst.stat().st_mtime < src.stat().st_mtime):
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dst)
    (d / f"{APP_ID}.svg").unlink(missing_ok=True)          # icono anterior (llama), si quedaba
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
Actions=uninstall;

[Desktop Action uninstall]
Name=Desinstalar VELA
Name[en]=Uninstall VELA
Name[ca]=Desinstal·la VELA
Name[pt]=Desinstalar o VELA
Name[fr]=Désinstaller VELA
Name[de]=VELA deinstallieren
Exec={exe} -m vela app --uninstall
"""


def install_desktop() -> str:
    import os
    data_home = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    p = data_home / f"applications/{APP_ID}.desktop"
    p.parent.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    # icono en el tema de iconos del usuario (hicolor, todos los tamaños) para el menú de aplicaciones
    import shutil
    hicolor = data_home / "icons/hicolor"
    for n in ICON_SIZES:
        dst = hicolor / f"{n}x{n}" / "apps" / f"{APP_ID}.png"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(BRAND_DIR / f"vela-app-{n}.png", dst)
    (hicolor / "scalable" / "apps" / f"{APP_ID}.svg").unlink(missing_ok=True)   # la llama anterior tenía prioridad
    p.write_text(DESKTOP.format(exe=f"env PYTHONPATH={root} {sys.executable}", icon=APP_ID))
    os.chmod(p, 0o644)
    return str(p)


def run(backend=None, uninstall=False) -> int:
    app = App(backend)
    if uninstall:
        app.register(None)
        if app.get_is_remote():                 # ya abierta: que la ventana existente pregunte
            app.activate_action("uninstall", None)
            return 0
        app.pending_uninstall = True
    return app.run([sys.argv[0]])
