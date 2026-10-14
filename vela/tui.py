"""TUI con curses (biblioteca estándar).

Teclas: 1-7 / Tab pestañas · ↑↓ PgUp PgDn desplazar · / filtrar · r rotar · l comprobar fugas
        u refrescar · p emergencia · e salir de emergencia · ? ayuda · q salir
"""

from __future__ import annotations

from .i18n import _

import curses
import json
import threading
import time

from . import worldmap
from .util import fmt_duration, iso

TABS = [_("Panel"), _("Sesiones"), _("Contadores"), _("Timeline"), _("Alertas"), _("Mapa"), _("Rotación")]
SEV_PAIR = {"critical": 2, "high": 2, "medium": 3, "warning": 3, "low": 4, "info": 5}
HELP = [
    _("1-7 / Tab   cambiar de pestaña"),
    _("↑ ↓ PgUp PgDn  desplazar"),
    _("/           filtrar la tabla actual (Enter vacío = quitar filtro)"),
    _("r           rotar (t=Tor, p=proxy, v=VPN; d = dry-run)"),
    _("l           ejecutar comprobaciones de fugas (pasivas)"),
    _("u           refrescar ahora"),
    _("p           MODO EMERGENCIA (detiene rotaciones, kill-switch si está permitido)"),
    _("e           salir del modo emergencia"),
    "q           salir",
]


class Poller(threading.Thread):
    def __init__(self, backend, interval: float = 2.0):
        super().__init__(daemon=True)
        self.b = backend
        self.interval = interval
        self.data: dict = {}
        self.error: str | None = None
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.stop = threading.Event()

    def run(self):
        slow_at = 0.0
        while not self.stop.is_set():
            try:
                if not getattr(self.b, "remote", False):
                    self.b.engine.tick()
                d = {"status": self.b.call("status")}
                if time.monotonic() >= slow_at:
                    d.update(sessions=self.b.call("sessions", limit=200), counters=self.b.call("counters"),
                             timeline=self.b.call("timeline", limit=400), map=self.b.call("map"),
                             rotation=self.b.call("rotation_status"))
                    slow_at = time.monotonic() + 10
                with self.lock:
                    self.data.update(d)
                    self.error = None
            except Exception as e:  # noqa: BLE001
                with self.lock:
                    self.error = f"{type(e).__name__}: {e}"
            self.wake.wait(self.interval)
            self.wake.clear()

    def force(self):
        self.wake.set()


class App:
    def __init__(self, scr, backend):
        self.scr = scr
        self.b = backend
        self.tab = 0
        self.scroll = 0
        self.filter = ""
        self.msg = ""
        self.msg_ts = 0.0
        self.show_help = False
        self.poller = Poller(backend)
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        for i, col in enumerate([curses.COLOR_GREEN, curses.COLOR_RED, curses.COLOR_YELLOW, curses.COLOR_CYAN,
                                 curses.COLOR_WHITE, curses.COLOR_BLUE, curses.COLOR_MAGENTA], start=1):
            curses.init_pair(i, col, -1)
        scr.timeout(500)
        scr.keypad(True)

    # ── utilidades de dibujo ──
    def put(self, y, x, text, attr=0):
        h, w = self.scr.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        text = str(text)[: max(0, w - x - (1 if y == h - 1 else 0))]
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def flash(self, msg):
        self.msg, self.msg_ts = msg, time.monotonic()

    def prompt(self, label) -> str:
        h, w = self.scr.getmaxyx()
        curses.echo()
        curses.curs_set(1)
        self.put(h - 1, 0, " " * (w - 1))
        self.put(h - 1, 0, label, curses.A_BOLD)
        self.scr.timeout(-1)
        try:
            s = self.scr.getstr(h - 1, len(label), 60).decode(errors="replace")
        finally:
            curses.noecho()
            curses.curs_set(0)
            self.scr.timeout(500)
        return s.strip()

    def key(self, label) -> str:
        h, w = self.scr.getmaxyx()
        self.put(h - 1, 0, " " * (w - 1))
        self.put(h - 1, 0, label, curses.A_BOLD | curses.color_pair(3))
        self.scr.timeout(-1)
        try:
            ch = self.scr.getch()
        finally:
            self.scr.timeout(500)
        return chr(ch) if 0 <= ch < 256 else ""

    # ── bucle ──
    def run(self):
        self.poller.start()
        while True:
            self.draw()
            ch = self.scr.getch()
            if ch == -1:
                continue
            if ch in (ord("q"), 27):
                break
            if self.show_help:
                self.show_help = False
                continue
            if ord("1") <= ch <= ord(str(len(TABS))):
                self.tab, self.scroll = ch - ord("1"), 0
            elif ch == 9:
                self.tab, self.scroll = (self.tab + 1) % len(TABS), 0
            elif ch == curses.KEY_BTAB:
                self.tab, self.scroll = (self.tab - 1) % len(TABS), 0
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.scroll += 1
            elif ch in (curses.KEY_UP, ord("k")):
                self.scroll = max(0, self.scroll - 1)
            elif ch == curses.KEY_NPAGE:
                self.scroll += 10
            elif ch == curses.KEY_PPAGE:
                self.scroll = max(0, self.scroll - 10)
            elif ch == ord("/"):
                self.filter = self.prompt("filtro: ")
                self.scroll = 0
            elif ch == ord("?"):
                self.show_help = True
            elif ch == ord("u"):
                self.poller.force()
                self.flash("refrescando…")
            elif ch == ord("r"):
                self.do_rotate()
            elif ch == ord("l"):
                self.run_bg(_("comprobando fugas…"), lambda: self.b.call("leaks"),
                            lambda r: f"{sum(f['status'] == 'fail' for f in r)} fallos, "
                                      f"{sum(f['status'] == 'warn' for f in r)} avisos")
            elif ch == ord("p"):
                if self.key(_("¿Activar MODO EMERGENCIA? (s/N) ")) in ("s", "S", "y", "Y"):
                    self.run_bg("emergencia…", lambda: self.b.call("panic"),
                                lambda r: _("EMERGENCIA activa · kill-switch ") +
                                          ("aplicado" if r["killswitch"].get("ok") else f"NO: {r['killswitch'].get('error')}"))
            elif ch == ord("e"):
                self.run_bg("reanudando…", lambda: self.b.call("resume"), lambda r: _("emergencia desactivada"))
        self.poller.stop.set()

    def run_bg(self, label, fn, fmt):
        self.flash(label)

        def work():
            try:
                self.flash(fmt(fn()))
            except Exception as e:  # noqa: BLE001
                self.flash(f"error: {e}")
            self.poller.force()
        threading.Thread(target=work, daemon=True).start()

    def do_rotate(self):
        layer = {"t": "tor", "p": "proxy", "v": "vpn"}.get(self.key(_("Rotar: [t]Tor [p]proxy [v]VPN · Esc cancela ")))
        if not layer:
            return
        mode = self.key(_("{layer}: [d]ry-run  [x] ejecutar  · Esc cancela ", layer=layer))
        if mode not in ("d", "x"):
            return
        dry = mode == "d"
        self.run_bg(f"rotando {layer}…", lambda: self.b.call("rotate", layer=layer, dry_run=dry, force=True),
                    lambda r: _("rotación {layer}: {result} · ", layer=layer, result=r['result']) +
                              " · ".join(f"{'✔' if s['ok'] else '✘'}{s['name']}" for s in r["steps"]))

    # ── dibujo ──
    def draw(self):
        self.scr.erase()
        h, w = self.scr.getmaxyx()
        with self.poller.lock:
            d = dict(self.poller.data)
            err = self.poller.error
        st = d.get("status") or {}
        ex = st.get("exposure") or {}
        title = " VELA "
        self.put(0, 0, " " * (w - 1), curses.A_REVERSE)
        self.put(0, 0, title, curses.A_REVERSE | curses.A_BOLD)
        info = (_("perfil {v1} · exposición {v3}/100 {v5} · {v7} · {v9}", v1=st.get('profile', '?'), v3=ex.get('score', '?'), v5=ex.get('level', ''), v7='daemon' if getattr(self.b, 'remote', False) else _('motor local'), v9=time.strftime('%H:%M:%S')))
        self.put(0, len(title) + 1, info, curses.A_REVERSE)
        if st.get("emergency"):
            self.put(0, w - 13, " EMERGENCIA ", curses.A_REVERSE | curses.color_pair(2) | curses.A_BOLD)
        x = 0
        for i, t in enumerate(TABS):
            label = f" {i + 1}:{t} "
            self.put(1, x, label, curses.A_BOLD | curses.A_REVERSE if i == self.tab else curses.A_DIM)
            x += len(label) + 1
        if self.filter:
            self.put(1, x + 1, f"filtro: {self.filter}", curses.color_pair(3))
        body_h = h - 3
        if self.show_help:
            for i, line in enumerate(HELP):
                self.put(3 + i, 2, line)
        elif not st:
            self.put(3, 2, err or "cargando…", curses.color_pair(2) if err else 0)
        else:
            [self.draw_panel, self.draw_sessions, self.draw_counters, self.draw_timeline, self.draw_alerts,
             self.draw_map, self.draw_rotation][self.tab](d, 2, body_h)
        foot = self.msg if time.monotonic() - self.msg_ts < 8 else (err or "? ayuda · q salir")
        self.put(h - 1, 0, foot[: w - 1], curses.color_pair(2) if err and not self.msg else curses.A_DIM)
        self.scr.refresh()

    def lines(self, rows: list[tuple[str, int]], y0: int, height: int):
        if self.filter:
            rows = [r for r in rows if self.filter.lower() in r[0].lower()]
        self.scroll = min(self.scroll, max(0, len(rows) - height))
        for i, (text, attr) in enumerate(rows[self.scroll:self.scroll + height]):
            self.put(y0 + i, 1, text, attr)

    def section(self, y, title):
        self.put(y, 1, title, curses.A_BOLD | curses.color_pair(4))
        return y + 1

    def draw_panel(self, d, y, h):
        st = d["status"]
        obs = st.get("obs") or {}
        net = st["net"]
        y = self.section(y, _("Topología de salida"))
        chain = obs.get("chain", [])
        self.put(y, 2, "  ──▶  ".join(f"[{c['type']}] {c.get('ip') or c.get('label')}" for c in chain))
        y += 1
        e4 = net["egress"].get("ipv4") or {}
        self.put(y, 2, _("salida IPv4 {v1} · túnel {v3} · IPv6 {v5} · túneles {v7}", v1=e4.get('dev'), v3='SÍ' if net['via_tunnel'].get('ipv4') else 'no', v5='sí' if net['egress'].get('ipv6') else 'sin ruta', v7=net['tunnels'] or '-'))
        y += 1
        wan = st.get("wan") or {}
        pub = st.get("public") or {}
        self.put(y, 2, _("IP WAN router: {v1}", v1=wan.get('ip') if wan.get('ok') else (wan.get('error') or 'no comprobada')[:60]))
        y += 1
        for route, r in pub.items():
            txt = (f"{r['ip']} ({(r.get('geo') or {}).get('country') or '?'}) {iso(r['ts'])}" if r.get("ok")
                   else (r.get("error") or "")[:80])
            self.put(y, 2, _("IP pública [{route}]: {txt}", route=route, txt=txt), 0 if r.get("ok") else curses.A_DIM)
            y += 1
        y += 1
        t = st.get("tor") or {}
        y = self.section(y, _("Tor"))
        if t.get("available"):
            g, e = t.get("guard") or {}, t.get("exit") or {}
            self.put(y, 2, f"{t.get('version')} · bootstrap {t.get('bootstrap')}% · {t.get('circuit_count')} circuitos · "
                           f"{t.get('stream_count')} streams" + (_(" · Tor Browser (solo observación)") if t.get("observe_only") else ""))
            y += 1
            tc = obs.get("tor_chain") or []
            self.put(y, 2, "  ──▶  ".join(f"{c['type'][4:]}: {c['label']} [{c.get('country') or '?'}]" for c in tc)
                     or f"guard {g.get('nick')} → exit {e.get('nick')}", curses.color_pair(7))
            y += 1
        else:
            self.put(y, 2, t.get("error") or _("no disponible"), curses.A_DIM)
            y += 1
        y += 1
        dn = st.get("dns") or {}
        y = self.section(y, "DNS")
        res = (dn.get("encryption") or {}).get("resolvers") or []
        self.put(y, 2, _("efectivo ({v1}): ", v1=dn.get('effective_source')) +
                 (", ".join(f"{r['addr']} {r['provider'] or '?'} [{r['transport']}]" for r in res) or "-") +
                 f" · cifrado {({True: 'sí', False: 'NO', None: '?'})[dn.get('encrypted')]}",
                 curses.color_pair(1 if dn.get("encrypted") else 3))
        kx = (st.get("killswitch") or {}).get("external") or {}
        rp = kx.get("route_protection") or {}
        if rp:
            y += 1
            self.put(y, 2, _("kill-switch {v1}: si cae el túnel IPv4 {state}, IPv6 {state2}", v1=', '.join(kx.get('declared_by') or []) or '-', state=rp['ipv4']['state'], state2=rp['ipv6']['state']),
                     curses.color_pair(1 if rp["ipv4"]["state"] == "bloqueado" else 2))
        y += 2
        y = self.section(y, _("Contadores en curso"))
        sess = st.get("session")
        if sess:
            self.put(y, 2, _("sesión {id}  {duration}", id=sess['id'], duration=fmt_duration(sess['duration'])), curses.A_BOLD)
            y += 1
        for layer, c in (st.get("live_counters") or {}).items():
            if y >= h - 6:
                break
            self.put(y, 2, f"{layer:18} {c['label'][:42]:42} actual {fmt_duration(c['current'])} · total {fmt_duration(c['total'])}")
            y += 1
        y += 1
        y = self.section(y, _("Rotación"))
        for layer, r in (st.get("rotation") or {}).items():
            rem = fmt_duration(r["remaining"]) if r.get("remaining") is not None else "—"
            self.put(y, 2, _("{layer:6} {adapter:16} activa {v4} · {v6} · próxima en {rem} · {rotations_last_hour}/{max_per_hour} última hora", layer=layer, adapter=r['adapter'], v4='sí' if r['enabled'] else 'no', v6='disponible' if r['available'] else r['reason'][:50], rem=rem, rotations_last_hour=r['rotations_last_hour'], max_per_hour=r['max_per_hour']))
            y += 1
        fs = st.get("findings") or []
        if fs and y < h:
            y = self.section(y + 1, _("Alertas ({n})", n=len(fs)))
            for f in fs[: max(0, h - y)]:
                self.put(y, 2, f"{f['severity'].upper():8} {f['title']}", curses.color_pair(SEV_PAIR.get(f["severity"], 5)))
                y += 1

    def draw_sessions(self, d, y, h):
        self.put(y, 1, f"{'inicio':19} {'fin':19} {'duración':15} {'perfil':10} {'iface':9} {'vpn':10} {'ip pública':16} "
                       f"{'ip wan':16} cierre", curses.A_BOLD)
        rows = []
        for s in d.get("sessions", []):
            rows.append((f"{iso(s['started']):19} {(iso(s['ended']) if s['ended'] else 'ACTIVA'):19} "
                         f"{fmt_duration(s['duration']):15} {str(s['profile'])[:10]:10} {str(s['egress_iface'])[:9]:9} "
                         f"{str(s['vpn'] or '-')[:10]:10} {str(s['public_ip'] or '-'):16} {str(s['wan_ip'] or '-'):16} "
                         f"{s['end_reason'] or ''}", curses.color_pair(1) if not s["ended"] else 0))
        self.lines(rows, y + 1, h - 1)

    def draw_counters(self, d, y, h):
        self.put(y, 1, f"{'capa':18} {'elemento':44} {'país':5} {'usos':>5} {'total':15} {'en curso':15}", curses.A_BOLD)
        rows = [(f"{c['layer']:18} {c['label'][:44]:44} {str(c['country'] or '-'):5} {c['uses']:>5} "
                 f"{c['total_fmt']:15} {c['current_fmt'] or '':15}", curses.color_pair(1) if c["active"] else 0)
                for c in d.get("counters", [])]
        self.lines(rows, y + 1, h - 1)

    def draw_timeline(self, d, y, h):
        rows = [(f"{iso(e['ts'])} {e['severity'][:4].upper():4} {e['kind']:26} "
                 f"{json.dumps(e['data'], ensure_ascii=False)[:120]}", curses.color_pair(SEV_PAIR.get(e["severity"], 5)))
                for e in d.get("timeline", [])]
        self.lines(rows, y, h)

    def draw_alerts(self, d, y, h):
        rows = []
        for f in (d["status"].get("findings") or []):
            rows.append((f"{f['severity'].upper():8} {f['status']:5} {f['title']}", curses.color_pair(SEV_PAIR.get(f["severity"], 5)) | curses.A_BOLD))
            rows.append((f"    observado: {f['observed']}", 0))
            rows.append((_("    método: {method} [{mode}] · confianza {confidence}", method=f['method'], mode=f['mode'], confidence=f['confidence']), curses.A_DIM))
            rows.append((f"    limitaciones: {f['limitations']}", curses.A_DIM))
            rows.append((_("    recomendación: {recommendation}", recommendation=f['recommendation']), curses.color_pair(4)))
        ex = d["status"].get("exposure") or {}
        rows.append(("", 0))
        rows.append((_("Indicadores de exposición ({v1}/100):", v1=ex.get('score')), curses.A_BOLD))
        for i in ex.get("indicators", []):
            rows.append((f"  {'●' if i['present'] else '○'} {i['label']} (peso {i['weight']})",
                         curses.color_pair(2) if i["present"] else curses.A_DIM))
        rows.append((ex.get("disclaimer", ""), curses.A_DIM))
        self.lines(rows or [(_("sin alertas"), curses.color_pair(1))], y, h)

    def draw_map(self, d, y, h):
        m = d.get("map") or {}
        _ign, w = self.scr.getmaxyx()
        cols, rows_n = max(20, w - 2), max(8, h - 4)
        markers = []
        legend = []
        for item in m.get("history", []):
            markers.append((item["lat"], item["lon"], "·" if item["layer"] != "tor_exit" else "x"))
        home = m.get("home") or {}
        if home.get("lat") is not None:
            markers.append((home["lat"], home["lon"], "H"))
            legend.append(_("H casa ({v1}, {v3})", v1=home.get('country'), v3=home.get('geo_source')))
        for hop, ch in zip(m.get("tor_chain", []), "GME"):
            if hop.get("lat") is not None:
                markers.append((hop["lat"], hop["lon"], ch))
                legend.append(f"{ch} {hop['type']} {hop['label']} [{hop.get('country')}]")
        for hop in m.get("chain", []):
            if hop["type"] == "internet" and hop.get("lat") is not None:
                markers.append((hop["lat"], hop["lon"], "@"))
                legend.append(f"@ salida {hop['label']} [{hop.get('country')}]")
        grid = worldmap.ascii_map(cols, rows_n, markers)
        for i, line in enumerate(grid):
            self.put(y + i, 1, line, curses.color_pair(6))
            for j, ch in enumerate(line):
                if ch in "HGME@x":
                    self.put(y + i, 1 + j, ch, curses.A_BOLD | curses.color_pair(2 if ch in "E@x" else 1))
        ly = y + rows_n
        self.put(ly, 1, " · ".join(legend) or _("sin ubicaciones conocidas"), curses.A_DIM)
        osm = _(" · © OpenStreetMap contributors") if worldmap.osm_rings() is not None else ""
        self.put(ly + 1, 1, _("x = exits de Tor históricos · · = otras salidas históricas") + osm + " · " + (m.get("note") or "")[:110],
                 curses.A_DIM)

    def draw_rotation(self, d, y, h):
        r = d.get("rotation") or {}
        rows = []
        for layer, st in (r.get("status") or {}).items():
            rem = fmt_duration(st["remaining"]) if st.get("remaining") is not None else "—"
            rows.append((_("{layer:6} {adapter:16} activa={enabled} disponible={available} {reason} próxima en {rem} ({rotations_last_hour}/{max_per_hour} h)", layer=layer, adapter=st['adapter'], enabled=st['enabled'], available=st['available'], reason=st['reason'], rem=rem, rotations_last_hour=st['rotations_last_hour'], max_per_hour=st['max_per_hour']), curses.A_BOLD))
            pol = (r.get("policies") or {}).get(layer, {})
            rows.append((_("       política: ") + ", ".join(f"{k}={v}" for k, v in pol.items()), curses.A_DIM))
        rows.append(("", 0))
        rows.append((_("Historial (r = rotar):"), curses.A_BOLD))
        for x in r.get("history", []):
            ok = x["result"] in ("ok", "dry_run_ok")
            rows.append((f"{iso(x['ts'])} {x['layer']:6} {x['result']:12} {'dry-run ' if x['dry_run'] else ''}"
                         f"{x['from_target'] or '-'} → {x['to_target'] or '-'}", curses.color_pair(1 if ok else 3)))
        self.lines(rows, y, h)


def run(backend):
    curses.wrapper(lambda scr: App(scr, backend).run())
