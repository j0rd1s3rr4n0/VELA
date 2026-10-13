"""Icono de bandeja (StatusNotifierItem / AppIndicator) para VELA.

Proceso ligero e independiente de la ventana principal (GTK 3 + AyatanaAppIndicator3, que es lo que
muestra la extensión AppIndicator de Ubuntu/GNOME, KDE, XFCE…). Habla con `velad` por el socket UNIX.

  * Icono según el estado: protegido / exposición media / alerta.
  * Menú con el estado en vivo y controles: abrir la app, comprobar IP y fugas, perfil, Tor, emergencia,
    ajustes rápidos, iniciar el daemon.
  * Notificaciones de escritorio para eventos altos/críticos (fugas, caída del túnel, IP real expuesta…).
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3 as AppIndicator  # noqa: E402
from gi.repository import GLib, Gtk  # noqa: E402

from .autostart import tray_pid_path as pid_path, tray_running  # noqa: E402
from .ipc import Client, IPCError, ping  # noqa: E402
from .util import private_dir, runtime_dir, which  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
ICONS = {"ok": "security-high-symbolic", "warn": "security-medium-symbolic", "alert": "security-low-symbolic",
         "off": "network-offline-symbolic"}
NOTIFY_KINDS = {"ip_leak", "dns_leak_live", "public_ip_is_real", "direct_exposure", "killswitch_change",
                "route_change", "tor_unavailable", "gateway_mac_change", "vm_isolation_broken", "rotation_failed",
                "emergency", "wifi_open", "tor_check_failed", "killswitch_auto", "intel_live_score"}


def notify(title: str, body: str, urgency: str = "normal"):
    if which("notify-send"):
        subprocess.Popen(["notify-send", "-a", "VELA", "-i", ICONS["alert"], "-u", urgency, title, body],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def spawn(*args: str):
    subprocess.Popen([sys.executable, "-m", "vela", *args], env={**os.environ, "PYTHONPATH": str(ROOT)},
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)


def cc_flag(cc: str | None) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc.upper())


EVENT_TEXT = {
    "ip_leak": "Conexión fuera del túnel con tu IP real",
    "dns_leak_live": "Consulta DNS fuera del túnel",
    "public_ip_is_real": "Internet ve tu IP real con la VPN conectada",
    "direct_exposure": "Sin VPN: hay conexiones con tu IP real",
    "killswitch_change": "Cambió la protección del kill-switch",
    "route_change": "La ruta de salida ha cambiado",
    "tor_unavailable": "Tor ha dejado de estar disponible",
    "gateway_mac_change": "Posible ARP spoofing: cambió la MAC del router",
    "vm_isolation_broken": "Una red de VMs aislada tiene salida",
    "rotation_failed": "Una rotación ha fallado",
    "emergency": "Modo de emergencia activado",
    "wifi_open": "Conectado a una WiFi abierta",
    "tor_check_failed": "check.torproject.org dice que NO sales por Tor",
    "killswitch_auto": "Kill-switch aplicado automáticamente por una fuga",
}


class Tray:
    def __init__(self):
        self.client = Client(timeout=30)
        self.ind = AppIndicator.Indicator.new("vela-command-center", ICONS["off"],
                                              AppIndicator.IndicatorCategory.APPLICATION_STATUS)
        self.ind.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.ind.set_title("VELA")
        self.status: dict | None = None
        self.leak: dict | None = None
        self.settings: dict | None = None
        self.profiles: dict | None = None
        self._updating = False
        self.menu = Gtk.Menu()
        self.build_menu()
        self.ind.set_menu(self.menu)
        GLib.timeout_add_seconds(5, self.poll)
        self.poll()
        threading.Thread(target=self.events, daemon=True).start()

    # ── menú ──
    def item(self, label, cb=None, sensitive=True):
        it = Gtk.MenuItem(label=label)
        it.set_sensitive(sensitive and cb is not None)
        if cb:
            it.connect("activate", lambda *_: cb())
        self.menu.append(it) if not hasattr(self, "_sub") or self._sub is None else self._sub.append(it)
        return it

    def build_menu(self):
        for c in self.menu.get_children():
            self.menu.remove(c)
        self._sub = None
        self.info = {k: self.info_item() for k in ("vpn", "ip", "exp", "conn", "ks", "dns")}
        self.menu.append(Gtk.SeparatorMenuItem())
        self.item("Abrir VELA", lambda: spawn("app"))
        self.item("Comprobar la IP pública ahora", self.check_ip)
        self.item("Comprobar fugas ahora", self.check_leaks)
        self.menu.append(Gtk.SeparatorMenuItem())
        # perfiles
        prof_item = Gtk.MenuItem(label="Perfil")
        self.prof_menu = Gtk.Menu()
        prof_item.set_submenu(self.prof_menu)
        self.menu.append(prof_item)
        # tor
        tor_item = Gtk.MenuItem(label="Tor")
        tor_menu = Gtk.Menu()
        for label, dry in (("Nuevo circuito (simular)", True), ("Nuevo circuito (NEWNYM)", False)):
            it = Gtk.MenuItem(label=label)
            it.connect("activate", lambda _i, d=dry: self.rotate_tor(d))
            tor_menu.append(it)
        tor_item.set_submenu(tor_menu)
        self.menu.append(tor_item)
        # ajustes rápidos
        quick = Gtk.MenuItem(label="Ajustes rápidos")
        self.quick_menu = Gtk.Menu()
        self.quick = {}
        for key, label, invert, on_value in (
                ("public_ip.require_tunnel", "Comprobar la IP pública siempre", True, None),
                ("leakwatch.enabled", "Vigilante de fugas en tiempo real", False, None),
                ("leakwatch.on_leak", "Kill-switch automático ante una fuga", False, "killswitch"),
                ("consent.threat_intel_lookups", "Permitir threat intel", False, None)):
            ck = Gtk.CheckMenuItem(label=label)
            ck.connect("toggled", self.on_quick, key, invert, on_value)
            self.quick_menu.append(ck)
            self.quick[key] = (ck, invert, on_value)
        quick.set_submenu(self.quick_menu)
        self.menu.append(quick)
        self.menu.append(Gtk.SeparatorMenuItem())
        self.emerg = Gtk.MenuItem(label="Modo de emergencia")
        self.emerg.connect("activate", lambda *_: self.toggle_emergency())
        self.menu.append(self.emerg)
        self.daemon_item = Gtk.MenuItem(label="Iniciar el daemon")
        self.daemon_item.connect("activate", lambda *_: spawn("daemon", "start"))
        self.menu.append(self.daemon_item)
        self.menu.append(Gtk.SeparatorMenuItem())
        q = Gtk.MenuItem(label="Cerrar el icono de la bandeja")
        q.connect("activate", lambda *_: Gtk.main_quit())
        self.menu.append(q)
        self.menu.show_all()

    def info_item(self):
        it = Gtk.MenuItem(label="…")
        it.set_sensitive(False)
        self.menu.append(it)
        return it

    # ── datos ──
    def bg(self, fn, done=None):
        def work():
            try:
                r = fn()
                if done:
                    GLib.idle_add(done, r)
            except (OSError, IPCError, ValueError) as e:
                GLib.idle_add(notify, "VELA", f"Error: {e}")
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        if getattr(self, "_polling", False):   # no lanzar otra consulta si la anterior sigue en curso
            return True
        self._polling = True

        def work():
            d = {}
            if ping():
                try:
                    d["status"] = self.client.call("status")
                    d["leak"] = self.client.call("leakwatch")
                    d["settings"] = self.client.call("settings_get")
                    d["profiles"] = self.client.call("profiles")
                except (OSError, IPCError, ValueError) as e:
                    d["error"] = str(e)
            self._polling = False
            GLib.idle_add(self.apply, d)
        threading.Thread(target=work, daemon=True).start()
        return True

    def apply(self, d):
        self.status, self.leak = d.get("status"), d.get("leak")
        self.settings, self.profiles = d.get("settings"), d.get("profiles")
        st = self.status
        self.daemon_item.set_visible(st is None)
        if not st:
            self.ind.set_icon_full(ICONS["off"], "daemon detenido")
            self.info["vpn"].set_label("Daemon detenido: sin monitorización")
            for k in ("ip", "exp", "conn", "ks", "dns"):
                self.info[k].set_label("—")
            return False
        net, obs = st["net"], st.get("obs") or {}
        sm = (self.leak or {}).get("summary") or {}
        ex = st["exposure"]
        tunnel = net["via_tunnel"].get("ipv4")
        if sm.get("fugas") or (st.get("public", {}).get("default") or {}).get("leak"):
            state = "alert"
        elif not tunnel or ex["level"] == "alta":
            state = "warn" if tunnel else "alert"
        else:
            state = "ok" if ex["level"] == "baja" else "warn"
        desc = {"ok": "protegido", "warn": "exposición media", "alert": "alerta"}[state]
        self.ind.set_icon_full(ICONS[state], f"VELA: {desc}")
        vpn = (obs.get("vpn") or {}).get("label")
        self.info["vpn"].set_label(f"{'🟢' if tunnel else '🔴'} VPN: {vpn if tunnel else 'desconectada'}")
        pub = (st.get("public") or {}).get("default") or {}
        if pub.get("ok"):
            tag = "IP REAL" if pub.get("is_real_ip") or not pub.get("via_tunnel") else "IP de la VPN"
            self.info["ip"].set_label(f"IP pública: {pub['ip']} ({(pub.get('geo') or {}).get('country') or '?'} · {tag})")
        else:
            self.info["ip"].set_label("IP pública: sin comprobar")
        self.info["exp"].set_label(f"Exposición: {ex['score']}/100 ({ex['level']}) · perfil {st['profile']}")
        self.info["conn"].set_label(f"Conexiones: {sm.get('fugas', 0)} fugas · {sm.get('directas', 0)} directas · "
                                    f"{sm.get('protegidas', 0)} protegidas")
        kx = (st.get("killswitch") or {}).get("external") or {}
        rp = kx.get("route_protection") or {}
        self.info["ks"].set_label("Kill-switch: " + (f"si cae el túnel IPv4 {rp['ipv4']['state']}" if rp else "—"))
        d = st.get("dns") or {}
        res = (d.get("encryption") or {}).get("resolvers") or [{}]
        self.info["dns"].set_label(f"DNS: {res[0].get('provider') or res[0].get('addr') or '—'} · "
                                   f"{'cifrado' if d.get('encrypted') else 'en claro' if d.get('encrypted') is False else '?'}")
        self.emerg.set_label("Salir del modo de emergencia" if st.get("emergency") else "Modo de emergencia…")
        self._updating = True
        vals = (self.settings or {}).get("values") or {}
        for key, (ck, invert, on_value) in self.quick.items():
            v = vals.get(key)
            ck.set_active((v == on_value) if on_value else (bool(v) != invert))
        for c in self.prof_menu.get_children():
            self.prof_menu.remove(c)
        group = None
        for name in (self.profiles or {}).get("profiles", {}):
            it = Gtk.RadioMenuItem.new_with_label_from_widget(group, name)
            group = group or it
            it.set_active(name == st["profile"])
            it.connect("toggled", self.on_profile, name)
            self.prof_menu.append(it)
        self.prof_menu.show_all()
        self._updating = False
        return False

    # ── acciones ──
    def check_ip(self):
        def done(rs):
            for r in rs:
                if r.get("ok"):
                    notify("IP pública", f"[{r['route']}] {r['ip']} ({(r.get('geo') or {}).get('country_name') or '?'})"
                           + ("  ← ¡TU IP REAL!" if r.get("is_real_ip") and r.get("via_tunnel") else ""))
                else:
                    notify("IP pública", f"[{r['route']}] {r.get('error')}")
            self.poll()
        self.bg(lambda: self.client.call("public_ip"), done)

    def check_leaks(self):
        def done(found):
            bad = [f for f in found if f["status"] == "fail"]
            notify("Comprobación de fugas", "Sin fallos" if not bad else
                   "\n".join(f"• {f['title']}" for f in bad[:6]), "critical" if bad else "normal")
        self.bg(lambda: self.client.call("leaks"), done)

    def rotate_tor(self, dry):
        def done(r):
            notify("Tor", f"{'Simulación' if dry else 'NEWNYM'}: {r['result']}"
                   + ("" if r["result"] in ("ok", "dry_run_ok") else
                      " — " + "; ".join(s["detail"] for s in r["steps"] if not s["ok"])))
        self.bg(lambda: self.client.call("rotate", layer="tor", dry_run=dry, force=True), done)

    def toggle_emergency(self):
        if (self.status or {}).get("emergency"):
            self.bg(lambda: self.client.call("resume"), lambda r: (notify("VELA", "Emergencia desactivada"), self.poll()))
            return
        dlg = Gtk.MessageDialog(message_type=Gtk.MessageType.WARNING, buttons=Gtk.ButtonsType.OK_CANCEL,
                                text="¿Activar el modo de emergencia?")
        dlg.format_secondary_text("Detiene las rotaciones y, si está permitido, aplica el kill-switch. "
                                  "No borra datos ni cambia la configuración.")
        ok = dlg.run() == Gtk.ResponseType.OK
        dlg.destroy()
        if ok:
            self.bg(lambda: self.client.call("panic"), lambda r: (notify(
                "Modo de emergencia", "Activo · kill-switch " + ("aplicado" if r["killswitch"].get("ok") else
                                                                  f"no aplicado ({r['killswitch'].get('error')})"),
                "critical"), self.poll()))

    def on_profile(self, item, name):
        if self._updating or not item.get_active():
            return
        self.bg(lambda: self.client.call("profile_activate", name=name),
                lambda r: (notify("Perfil", f"Activo: {name}"), self.poll()))

    def on_quick(self, ck, key, invert, on_value):
        if self._updating:
            return
        active = ck.get_active()
        value = (on_value if active else "alert") if on_value else (active != invert)
        self.bg(lambda: self.client.call("settings_set", changes={key: value}), lambda r: self.poll())

    # ── notificaciones ──
    def events(self):
        while True:
            gen = None
            try:
                if not ping():
                    time.sleep(5)
                    continue
                gen = Client(timeout=None).subscribe()
                for ev in gen:
                    if ev["kind"] == "intel_live_score":
                        dd = ev.get("data") or {}
                        if dd.get("notify"):
                            flag = cc_flag(dd.get("country"))
                            GLib.idle_add(notify, f"VirusTotal {dd['score']} · {dd['ip']}",
                                          f"{flag} {dd.get('country_name') or '?'} · {dd.get('as_owner') or ''}\n"
                                          f"{dd.get('process') or '?'} → puerto {dd.get('port')}",
                                          "critical" if ev["severity"] == "high" else "normal")
                        continue
                    if ev["kind"] in NOTIFY_KINDS and ev["severity"] in ("high", "critical"):
                        data = ev.get("data") or {}
                        extra = data.get("process") or data.get("ip") or data.get("network") or data.get("detail") or ""
                        GLib.idle_add(notify, EVENT_TEXT.get(ev["kind"], ev["kind"]), str(extra)[:180],
                                      "critical" if ev["severity"] == "critical" else "normal")
                        GLib.idle_add(self.poll)
            except Exception:  # noqa: BLE001 — reconectar si el daemon se reinicia
                time.sleep(5)
            finally:
                if gen is not None:
                    gen.close()


def run() -> int:
    if tray_running():
        print("el icono de la bandeja ya está en marcha")
        return 0
    private_dir(runtime_dir())
    pid_path().write_text(str(os.getpid()))
    import signal
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGTERM, lambda: (Gtk.main_quit(), False)[1])
    GLib.unix_signal_add(GLib.PRIORITY_DEFAULT, signal.SIGINT, lambda: (Gtk.main_quit(), False)[1])
    try:
        Tray()
        Gtk.main()
    finally:
        try:
            pid_path().unlink()
        except OSError:
            pass
    return 0
