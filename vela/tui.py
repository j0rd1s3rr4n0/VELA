"""TUI con curses (biblioteca estándar).

Diseño pensado para terminales pequeñas (80×24 incluidos): la barra de pestañas se desplaza
alrededor de la pestaña activa, todo el contenido se ajusta al ancho y **todas** las vistas
(Panel, Sesiones, Contadores, Timeline, Alertas, Mapa, Rotación) se pueden desplazar.

Teclas: 1-7 / ← → / Tab pestañas · ↑↓ PgUp PgDn Inicio Fin desplazar · / filtrar
        r rotar · l fugas · u refrescar · p emergencia · e salir de emergencia · ? ayuda · q salir
"""

from __future__ import annotations

from .i18n import _

import curses
import json
import textwrap
import threading
import time

from . import logs, worldmap
from .util import fmt_duration, iso

TABS = [_("Panel"), _("Sesiones"), _("Contadores"), _("Timeline"), _("Alertas"), _("Mapa"), _("Rotación"),
        _("Errores")]
SEV_PAIR = {"critical": 2, "high": 2, "medium": 3, "warning": 3, "low": 4, "info": 5}
HELP = [
    _("1-8 · ← → · Tab / Shift+Tab   cambiar de pestaña"),
    _("↑ ↓ · j k · PgUp PgDn · Inicio/Fin   desplazar el contenido"),
    _("/   filtrar la vista actual (Enter vacío = quitar filtro)"),
    _("r   rotar (t=Tor, p=proxy, v=VPN; d = dry-run)"),
    _("l   ejecutar comprobaciones de fugas (pasivas)"),
    _("u   refrescar ahora"),
    _("p   MODO EMERGENCIA (detiene rotaciones, kill-switch si está permitido)"),
    _("e   salir del modo emergencia"),
    _("? o Esc   cerrar esta ayuda · q   salir"),
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
                    for key, method, params in (
                            ("sessions", "sessions", {"limit": 300}),
                            ("counters", "counters", {}),
                            ("timeline", "timeline", {"limit": 500}),
                            ("map", "map", {}),
                            ("rotation", "rotation_status", {}),
                            ("anomalies", "anomalies", {}),
                            ("logs", "logs", {"limit": 200})):
                        try:
                            d[key] = self.b.call(method, **params)
                        except Exception as e:  # noqa: BLE001
                            d[f"{key}_error"] = f"{type(e).__name__}: {e}"
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
        self.colors = False
        self.poller = Poller(backend)
        self.width, self.height = scr.getmaxyx()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        try:
            curses.start_color()
            curses.use_default_colors()
            for i, col in enumerate([curses.COLOR_GREEN, curses.COLOR_RED, curses.COLOR_YELLOW,
                                     curses.COLOR_CYAN, curses.COLOR_WHITE, curses.COLOR_BLUE,
                                     curses.COLOR_MAGENTA], start=1):
                curses.init_pair(i, col, -1)
            self.colors = True
        except curses.error:
            self.colors = False
        scr.timeout(500)
        scr.keypad(True)

    # ── colores y dibujo ──
    def cp(self, n):
        return curses.color_pair(n) if self.colors else 0

    def put(self, y, x, text, attr=0):
        h, w = self.height, self.width
        if y < 0 or y >= h or x >= w:
            return
        text = str(text).replace("\t", "    ")
        text = text[: max(0, w - x - (1 if y == h - 1 else 0))]
        try:
            self.scr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def flash(self, msg):
        self.msg, self.msg_ts = str(msg), time.monotonic()

    def wrap(self, text, width=None):
        width = max(8, (width or self.width - 3))
        out = []
        for part in str(text).splitlines() or [""]:
            if not part:
                out.append("")
                continue
            out.extend(textwrap.wrap(part, width=width, break_long_words=True,
                                     break_on_hyphens=False, replace_whitespace=False) or [""])
        return out

    def add(self, lines, text, attr=0, indent=1):
        prefix = " " * indent
        for i, part in enumerate(self.wrap(text, self.width - indent - 1)):
            lines.append((prefix + part, attr if i == 0 else attr))

    def section(self, lines, title):
        lines.append(("", 0))
        lines.append((" " + title.upper(), curses.A_BOLD | self.cp(4)))

    def prompt(self, label) -> str:
        h, w = self.height, self.width
        try:
            curses.echo()
            curses.curs_set(1)
            self.put(h - 1, 0, " " * (w - 1))
            self.put(h - 1, 0, label, curses.A_BOLD)
            self.scr.timeout(-1)
            s = self.scr.getstr(h - 1, len(label), max(1, w - len(label) - 2)).decode(errors="replace")
        except (curses.error, OSError):
            s = ""
        finally:
            try:
                curses.noecho()
                curses.curs_set(0)
            except curses.error:
                pass
            self.scr.timeout(500)
        return s.strip()

    def key(self, label) -> str:
        h, w = self.height, self.width
        self.put(h - 1, 0, " " * (w - 1))
        self.put(h - 1, 0, label, curses.A_BOLD | self.cp(3))
        self.scr.timeout(-1)
        try:
            ch = self.scr.getch()
        except curses.error:
            ch = -1
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
            if ch == curses.KEY_RESIZE:
                continue
            if self.show_help:
                if ch in (27, ord("q"), ord("?")):
                    self.show_help = False
                continue
            if ch in (ord("q"), 27):
                break
            if ord("1") <= ch <= ord(str(len(TABS))):
                self.tab, self.scroll = ch - ord("1"), 0
            elif ch in (9, curses.KEY_RIGHT, ord("]")):
                self.tab, self.scroll = (self.tab + 1) % len(TABS), 0
            elif ch in (curses.KEY_BTAB, curses.KEY_LEFT, ord("[")):
                self.tab, self.scroll = (self.tab - 1) % len(TABS), 0
            elif ch in (curses.KEY_DOWN, ord("j")):
                self.scroll += 1
            elif ch in (curses.KEY_UP, ord("k")):
                self.scroll = max(0, self.scroll - 1)
            elif ch == curses.KEY_NPAGE:
                self.scroll += 10
            elif ch == curses.KEY_PPAGE:
                self.scroll = max(0, self.scroll - 10)
            elif ch in (curses.KEY_HOME, ord("g")):
                self.scroll = 0
            elif ch in (curses.KEY_END, ord("G")):
                self.scroll = 10 ** 9
            elif ch == ord("/"):
                self.filter = self.prompt("filtro: ")
                self.scroll = 0
            elif ch == ord("?"):
                self.show_help = True
            elif ch == ord("u"):
                self.poller.force()
                self.flash(_("refrescando…"))
            elif ch == ord("r"):
                self.do_rotate()
            elif ch == ord("l"):
                self.run_bg(_("comprobando fugas…"), lambda: self.b.call("leaks"),
                            lambda r: _("{fail} fallos, {warn} avisos",
                                        fail=sum(f["status"] == "fail" for f in r),
                                        warn=sum(f["status"] == "warn" for f in r)))
            elif ch == ord("p"):
                if self.key(_("¿Activar MODO EMERGENCIA? (s/N) ")) in ("s", "S", "y", "Y"):
                    self.run_bg("emergencia…", lambda: self.b.call("panic"),
                                lambda r: _("EMERGENCIA activa · kill-switch ") +
                                          (_("aplicado") if r["killswitch"].get("ok")
                                           else _("NO: {e}", e=r["killswitch"].get("error"))))
            elif ch == ord("e"):
                self.run_bg(_("reanudando…"), lambda: self.b.call("resume"),
                            lambda r: _("emergencia desactivada"))
        self.poller.stop.set()

    def run_bg(self, label, fn, fmt):
        self.flash(label)

        def work():
            try:
                self.flash(fmt(fn()))
            except Exception as e:  # noqa: BLE001
                logs.error(_("error en la TUI"), e)
                self.flash(f"error: {e}")
            self.poller.force()
        threading.Thread(target=work, daemon=True).start()

    def do_rotate(self):
        layer = {"t": "tor", "p": "proxy", "v": "vpn"}.get(
            self.key(_("Rotar: [t]Tor [p]proxy [v]VPN · Esc cancela ")))
        if not layer:
            return
        mode = self.key(_("{layer}: [d]ry-run  [x] ejecutar  · Esc cancela ", layer=layer))
        if mode not in ("d", "x"):
            return
        dry = mode == "d"
        self.run_bg(_("rotando {layer}…", layer=layer),
                    lambda: self.b.call("rotate", layer=layer, dry_run=dry, force=True),
                    lambda r: _("rotación {layer}: {result} · ", layer=layer, result=r["result"]) +
                              " · ".join(f"{'✔' if s['ok'] else '✘'}{s['name']}" for s in r["steps"]))

    # ── dibujo ──
    def draw(self):
        try:
            self.height, self.width = self.scr.getmaxyx()
            self.scr.erase()
        except curses.error:
            return
        if self.height < 4 or self.width < 20:
            self.put(0, 0, "VELA: terminal demasiado pequeña")
            self.scr.refresh()
            return
        with self.poller.lock:
            d = dict(self.poller.data)
            err = self.poller.error
        st = d.get("status") or {}
        self.draw_header(st, err)
        body_h = self.height - 3
        try:
            lines = self.view(d, err)
        except Exception as e:  # noqa: BLE001 — una vista rota no debe dejar la TUI en blanco
            lines = [(_("Error dibujando esta pestaña: {e}", e=e), curses.A_BOLD | self.cp(2)),
                     (_("Pulsa u para refrescar o 1-7 para cambiar de pestaña.", ), curses.A_DIM)]
        if self.filter:
            needle = self.filter.lower()
            lines = [ln for ln in lines if needle in ln[0].lower()]
        max_scroll = max(0, len(lines) - body_h)
        self.scroll = max(0, min(self.scroll, max_scroll))
        for i, (text, attr) in enumerate(lines[self.scroll:self.scroll + body_h]):
            self.put(2 + i, 1, text, attr)
        self.draw_scrollbar(len(lines), body_h)
        self.draw_footer(err, len(lines), body_h)
        try:
            self.scr.refresh()
        except curses.error:
            pass

    def draw_header(self, st, err):
        ex = st.get("exposure") or {}
        title = " VELA "
        self.put(0, 0, " " * (self.width - 1), curses.A_REVERSE)
        self.put(0, 0, title, curses.A_REVERSE | curses.A_BOLD)
        info = _("perfil {v1} · exposición {v3}/100 {v5} · {v7} · {v9}",
                 v1=st.get("profile", "?"), v3=ex.get("score", "?"), v5=ex.get("level", ""),
                 v7=_("daemon") if getattr(self.b, "remote", False) else _("motor local"),
                 v9=time.strftime("%H:%M:%S"))
        self.put(0, len(title) + 1, info, curses.A_REVERSE)
        if st.get("emergency"):
            self.put(0, max(0, self.width - 13), " EMERGENCIA ", curses.A_REVERSE | self.cp(2) | curses.A_BOLD)
        self.draw_tabs()

    def draw_tabs(self):
        labels = [f"{i + 1}:{t}" for i, t in enumerate(TABS)]
        sep = "  "
        full = sep.join(labels)
        if len(full) <= self.width - 10:
            visible = labels
            left = right = ""
        else:
            # ventana alrededor de la pestaña activa; la activa siempre visible
            visible = [labels[self.tab]]
            budget = self.width - 12
            i = 1
            while True:
                added = False
                if self.tab + i < len(labels) and len(sep.join(visible + [labels[self.tab + i]])) <= budget:
                    visible.append(labels[self.tab + i])
                    added = True
                if self.tab - i >= 0 and len(sep.join([labels[self.tab - i]] + visible)) <= budget:
                    visible.insert(0, labels[self.tab - i])
                    added = True
                if not added:
                    break
                i += 1
            left = "◀ " if labels.index(visible[0]) > 0 else "  "
            right = " ▶" if labels.index(visible[-1]) < len(labels) - 1 else "  "
        x = 0
        if left:
            self.put(1, x, left, curses.A_DIM | self.cp(3))
            x += len(left)
        for label in visible:
            idx = int(label.split(":", 1)[0]) - 1
            attr = (curses.A_BOLD | curses.A_REVERSE) if idx == self.tab else curses.A_DIM
            self.put(1, x, label, attr)
            x += len(label) + 2
        if right:
            self.put(1, min(x, self.width - 3), right, curses.A_DIM | self.cp(3))
        pos = f" {self.tab + 1}/{len(TABS)} "
        self.put(1, max(0, self.width - len(pos) - 1), pos, curses.A_DIM)

    def draw_scrollbar(self, total, body_h):
        if total <= body_h:
            return
        x = self.width - 1
        track = max(1, body_h)
        thumb = max(1, int(track * body_h / total))
        start = int((track - thumb) * self.scroll / max(1, total - body_h))
        for i in range(body_h):
            ch = "█" if start <= i < start + thumb else "│"
            self.put(2 + i, x, ch, curses.A_DIM | self.cp(4))

    def draw_footer(self, err, total, body_h):
        if self.msg and time.monotonic() - self.msg_ts < 8:
            left = self.msg
            attr = self.cp(3)
        elif err:
            left = err
            attr = self.cp(2)
        else:
            left = _("? ayuda · ↑↓ desplazar · Tab/←→ pestañas · q salir")
            attr = curses.A_DIM
        if total > body_h:
            left = _("{a}-{b}/{n} · ", a=self.scroll + 1,
                     b=min(total, self.scroll + body_h), n=total) + left
        self.put(self.height - 1, 0, left, attr)

    def view(self, d, err):
        if self.show_help:
            return [(" " + line, curses.A_BOLD if i == 0 else 0) for i, line in enumerate(HELP)]
        st = d.get("status") or {}
        if not st:
            return [(err or _("cargando…"), curses.A_BOLD | self.cp(2) if err else curses.A_DIM)]
        return [self.panel_lines, self.sessions_lines, self.counters_lines, self.timeline_lines,
                self.alerts_lines, self.map_lines, self.rotation_lines, self.logs_lines][self.tab](d)

    # ── vistas ──
    def panel_lines(self, d):
        st = d["status"]
        obs = st.get("obs") or {}
        net = st.get("net") or {}
        lines = []
        self.section(lines, _("Topología de salida"))
        chain = obs.get("chain", [])
        self.add(lines, "  ──▶  ".join(f"[{c['type']}] {c.get('ip') or c.get('label')}" for c in chain), indent=1)
        e4 = (net.get("egress") or {}).get("ipv4") or {}
        self.add(lines, _("salida IPv4 {v1} · túnel {v3} · IPv6 {v5} · túneles {v7}",
                          v1=e4.get("dev"), v3=_("SÍ") if (net.get("via_tunnel") or {}).get("ipv4") else _("no"),
                          v5=_("sí") if (net.get("egress") or {}).get("ipv6") else _("sin ruta"),
                          v7=net.get("tunnels") or "-"))
        wan = st.get("wan") or {}
        self.add(lines, _("IP WAN router: {v1}", v1=wan.get("ip") if wan.get("ok") else
                          (wan.get("error") or _("no comprobada"))))
        for route, r in (st.get("public") or {}).items():
            txt = (f"{r['ip']} ({(r.get('geo') or {}).get('country') or '?'}) {iso(r['ts'])}" if r.get("ok")
                   else (r.get("error") or "")[:80])
            self.add(lines, _("IP pública [{route}]: {txt}", route=route, txt=txt), 0 if r.get("ok") else curses.A_DIM)

        self.section(lines, "Tor")
        t = st.get("tor") or {}
        if t.get("available"):
            g, e = t.get("guard") or {}, t.get("exit") or {}
            self.add(lines, f"{t.get('version')} · bootstrap {t.get('bootstrap')}% · {t.get('circuit_count')} "
                            f"{_('circuitos')} · {t.get('stream_count')} streams" +
                            (_(" · Tor Browser (solo observación)") if t.get("observe_only") else ""))
            tc = obs.get("tor_chain") or []
            self.add(lines, "  ──▶  ".join(f"{c['type'][4:]}: {c['label']} [{c.get('country') or '?'}]" for c in tc)
                     or f"guard {g.get('nick')} → exit {e.get('nick')}", self.cp(7))
        else:
            self.add(lines, t.get("error") or _("no disponible"), curses.A_DIM)

        self.section(lines, "DNS")
        dn = st.get("dns") or {}
        res = (dn.get("encryption") or {}).get("resolvers") or []
        self.add(lines, _("efectivo ({v1}): ", v1=dn.get("effective_source")) +
                 (", ".join(f"{r['addr']} {r['provider'] or '?'} [{r['transport']}]" for r in res) or "-") +
                 f" · {_('cifrado')} {({True: 'sí', False: 'NO', None: '?'}).get(dn.get('encrypted'), '?')}",
                 self.cp(1 if dn.get("encrypted") else 3))
        kx = (st.get("killswitch") or {}).get("external") or {}
        rp = kx.get("route_protection") or {}
        if rp:
            self.add(lines, _("kill-switch {v1}: si cae el túnel IPv4 {state}, IPv6 {state2}",
                              v1=", ".join(kx.get("declared_by") or []) or "-",
                              state=rp["ipv4"]["state"], state2=rp["ipv6"]["state"]),
                     self.cp(1 if rp["ipv4"]["state"] == "bloqueado" else 2))

        self.section(lines, _("Contadores en curso"))
        sess = st.get("session")
        if sess:
            self.add(lines, _("sesión {id}  {duration}", id=sess["id"], duration=fmt_duration(sess["duration"])),
                     curses.A_BOLD)
        for layer, c in (st.get("live_counters") or {}).items():
            self.add(lines, f"{layer:18} {c['label'][:42]:42} {_('actual')} {fmt_duration(c['current'])} · "
                            f"{_('total')} {fmt_duration(c['total'])}")

        self.section(lines, _("Rotación"))
        for layer, r in (st.get("rotation") or {}).items():
            rem = fmt_duration(r["remaining"]) if r.get("remaining") is not None else "—"
            self.add(lines, _("{layer:6} {adapter:16} activa {v4} · {v6} · próxima en {rem} · "
                              "{rotations_last_hour}/{max_per_hour} última hora",
                              layer=layer, adapter=r["adapter"], v4=_("sí") if r["enabled"] else _("no"),
                              v6=_("disponible") if r["available"] else r["reason"][:50], rem=rem,
                              rotations_last_hour=r["rotations_last_hour"], max_per_hour=r["max_per_hour"]))

        anomalies = d.get("anomalies") or []
        self.section(lines, _("Anomalías de red ({n})", n=len(anomalies)))
        if anomalies:
            for a in anomalies[:12]:
                self.add(lines, _("{sev} · {type}: {detail}", sev=a.get("severity", "info").upper(),
                                  type=a.get("type", ""), detail=a.get("detail", "")),
                         self.cp(SEV_PAIR.get(a.get("severity"), 5)))
        else:
            self.add(lines, _("sin anomalías en la ventana analizada"), curses.A_DIM)

        fs = st.get("findings") or []
        if fs:
            self.section(lines, _("Alertas ({n})", n=len(fs)))
            for f in fs[:20]:
                self.add(lines, f"{f['severity'].upper():8} {f['title']}",
                         self.cp(SEV_PAIR.get(f["severity"], 5)))
        return lines

    def sessions_lines(self, d):
        header = (f"{_('inicio'):19} {_('fin'):19} {_('duración'):15} {_('perfil'):10} {_('iface'):9} "
                  f"{_('vpn'):10} {_('IP pública'):16} {_('cierre')}")
        lines = [(header, curses.A_BOLD)]
        for s in d.get("sessions", []):
            lines.append((f"{iso(s['started']):19} {(iso(s['ended']) if s['ended'] else _('ACTIVA')):19} "
                          f"{fmt_duration(s['duration']):15} {str(s['profile'])[:10]:10} "
                          f"{str(s['egress_iface'])[:9]:9} {str(s['vpn'] or '-')[:10]:10} "
                          f"{str(s['public_ip'] or '-'):16} {s['end_reason'] or ''}",
                          self.cp(1) if not s["ended"] else 0))
        return lines

    def counters_lines(self, d):
        lines = [(f"{_('capa'):18} {_('elemento'):44} {_('país'):5} {_('usos'):>5} {_('total'):15} {_('en curso'):15}",
                  curses.A_BOLD)]
        for c in d.get("counters", []):
            lines.append((f"{c['layer']:18} {c['label'][:44]:44} {str(c['country'] or '-'):5} {c['uses']:>5} "
                          f"{c['total_fmt']:15} {c['current_fmt'] or '':15}",
                          self.cp(1) if c["active"] else 0))
        return lines

    def timeline_lines(self, d):
        return [(f"{iso(e['ts'])} {e['severity'][:4].upper():4} {e['kind']:26} "
                 f"{json.dumps(e['data'], ensure_ascii=False)[:140]}",
                 self.cp(SEV_PAIR.get(e["severity"], 5))) for e in d.get("timeline", [])]

    def alerts_lines(self, d):
        lines = []
        for f in (d["status"].get("findings") or []):
            lines.append((f"{f['severity'].upper():8} {f['status']:5} {f['title']}",
                          self.cp(SEV_PAIR.get(f["severity"], 5)) | curses.A_BOLD))
            self.add(lines, _("observado: {v1}", v1=f["observed"]), 0, indent=4)
            self.add(lines, _("método: {method} [{mode}] · confianza {confidence}",
                              method=f["method"], mode=f["mode"], confidence=f["confidence"]), curses.A_DIM, indent=4)
            self.add(lines, _("limitaciones: {v1}", v1=f["limitations"]), curses.A_DIM, indent=4)
            self.add(lines, _("recomendación: {v1}", v1=f["recommendation"]), self.cp(4), indent=4)
        ex = d["status"].get("exposure") or {}
        lines.append(("", 0))
        lines.append((_("Indicadores de exposición ({v1}/100):", v1=ex.get("score")), curses.A_BOLD))
        for i in ex.get("indicators", []):
            lines.append((f"  {'●' if i['present'] else '○'} {i['label']} ({_('peso')} {i['weight']})",
                          self.cp(2) if i["present"] else curses.A_DIM))
        lines.append((ex.get("disclaimer", ""), curses.A_DIM))
        return lines or [(_("sin alertas"), self.cp(1))]

    def map_lines(self, d):
        m = d.get("map") or {}
        cols = max(20, self.width - 4)
        rows_n = max(6, min(26, self.height - 10))
        markers, legend = [], []
        for item in m.get("history", []):
            if item.get("lat") is not None:
                markers.append((item["lat"], item["lon"], "·" if item["layer"] != "tor_exit" else "x"))
        home = m.get("home") or {}
        if home.get("lat") is not None:
            markers.append((home["lat"], home["lon"], "H"))
            legend.append(_("H casa ({v1}, {v3})", v1=home.get("country"), v3=home.get("geo_source")))
        for hop, ch in zip(m.get("tor_chain", []), "GME"):
            if hop.get("lat") is not None:
                markers.append((hop["lat"], hop["lon"], ch))
                legend.append(f"{ch} {hop['type']} {hop['label']} [{hop.get('country')}]")
        for hop in m.get("chain", []):
            if hop.get("type") == "internet" and hop.get("lat") is not None:
                markers.append((hop["lat"], hop["lon"], "@"))
                legend.append(f"@ {_('salida')} {hop['label']} [{hop.get('country')}]")
        grid = worldmap.ascii_map(cols, rows_n, markers)
        lines = []
        for line in grid:
            lines.append((line, self.cp(6)))
        lines.append(("", 0))
        self.add(lines, " · ".join(legend) or _("sin ubicaciones conocidas"), curses.A_DIM)
        osm = _(" · © OpenStreetMap contributors") if worldmap.osm_rings() is not None else ""
        self.add(lines, _("x = exits de Tor históricos · · = otras salidas históricas") + osm + " · " +
                 (m.get("note") or "")[:160], curses.A_DIM)
        return lines

    def rotation_lines(self, d):
        r = d.get("rotation") or {}
        lines = []
        for layer, st in (r.get("status") or {}).items():
            rem = fmt_duration(st["remaining"]) if st.get("remaining") is not None else "—"
            self.add(lines, _("{layer:6} {adapter:16} activa={enabled} disponible={available} {reason} "
                              "próxima en {rem} ({rotations_last_hour}/{max_per_hour} h)",
                              layer=layer, adapter=st["adapter"], enabled=st["enabled"],
                              available=st["available"], reason=st["reason"], rem=rem,
                              rotations_last_hour=st["rotations_last_hour"], max_per_hour=st["max_per_hour"]),
                     curses.A_BOLD)
            pol = (r.get("policies") or {}).get(layer, {})
            self.add(lines, _("política: ") + ", ".join(f"{k}={v}" for k, v in pol.items()), curses.A_DIM, indent=7)
        lines.append(("", 0))
        lines.append((_("Historial (r = rotar):"), curses.A_BOLD))
        for x in r.get("history", []):
            ok = x["result"] in ("ok", "dry_run_ok")
            self.add(lines, f"{iso(x['ts'])} {x['layer']:6} {x['result']:12} "
                            f"{'dry-run ' if x['dry_run'] else ''}{x['from_target'] or '-'} → {x['to_target'] or '-'}",
                     self.cp(1 if ok else 3))
        return lines


    def logs_lines(self, d):
        logs = d.get("logs") or {}
        lines = []
        self.section(lines, _("Errores ({n})", n=len(logs.get("errors") or [])))
        for e in (logs.get("errors") or [])[:80]:
            detail = e.get("exception") or e.get("message") or ""
            if e.get("traceback"):
                detail += " · " + e["traceback"].strip().splitlines()[-1]
            lines.append((f"{iso(e.get('ts'))} {str(e.get('level') or 'error')[:8]:8} "
                          f"{str(e.get('type') or '')[:18]:18} {str(detail)[:160]}",
                          self.cp(2)))
        if not (logs.get("errors") or []):
            lines.append((_("sin errores registrados"), curses.A_DIM))
        self.section(lines, _("Auditoría ({n})", n=len(logs.get("audit") or [])))
        for a in (logs.get("audit") or [])[:80]:
            detail = a.get("detail")
            try:
                detail = json.dumps(detail, ensure_ascii=False, default=str) if detail is not None else ""
            except (TypeError, ValueError):
                detail = str(detail)
            lines.append((f"{iso(a.get('ts'))} {str(a.get('actor') or '-')[:12]:12} "
                          f"{str(a.get('action') or '')[:24]:24} {str(detail)[:130]}", 0))
        if not (logs.get("audit") or []):
            lines.append((_("sin acciones registradas"), curses.A_DIM))
        return lines


def run(backend):
    logs.setup()
    curses.wrapper(lambda scr: App(scr, backend).run())
