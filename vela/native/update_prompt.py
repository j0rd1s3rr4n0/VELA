"""Ventana «¿Cómo cambiar de versión?» que abre install.sh al instalar encima de un VELA ya instalado.

La descarga ya está hecha (con VELA en marcha); falta parar la versión vieja, copiar la nueva y arrancarla.
Imprime la elección por la salida estándar: «killswitch», «restart» o «cancel» (y sale con 0, 0 o 1).
Uso: python3 -m vela.native.update_prompt [--current X] [--new Y]
"""

from __future__ import annotations

import argparse
import sys

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, Gdk, Gtk  # noqa: E402

from ..i18n import _  # noqa: E402
from .. import updater  # noqa: E402

CHOICES = ("killswitch", "restart", "cancel")


def _row(title: str, body: str, button: str, css: str, sensitive: bool, cb):
    """Tarjeta de opción: título, explicación y botón."""
    box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
    box.add_css_class("card")
    t = Gtk.Label(label=title, xalign=0, wrap=True)
    t.add_css_class("heading")
    box.append(t)
    b = Gtk.Label(label=body, xalign=0, wrap=True)
    b.add_css_class("dim-label")
    box.append(b)
    btn = Gtk.Button(label=button, halign=Gtk.Align.END, sensitive=sensitive)
    btn.add_css_class(css)
    btn.connect("clicked", lambda *_a: cb())
    box.append(btn)
    return box


def run(current: str | None = None, new: str | None = None, on_ready=None) -> str:
    choice = {"value": "cancel"}
    opts = updater.protection_options()
    app = Adw.Application(application_id="io.github.j0rd1s3rr4n0.VelaUpdatePrompt")

    def activate(application):
        from . import theme as theme_mod
        theme_mod.ThemeManager(Gdk.Display.get_default())
        win = Adw.ApplicationWindow(application=application, title=_("Actualizar VELA"), default_width=560)
        win.add_css_class("vela")
        tv = Adw.ToolbarView()
        tv.add_top_bar(Adw.HeaderBar(show_title=False))
        body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        for side in ("top", "bottom", "start", "end"):
            getattr(body, f"set_margin_{side}")(18)
        title = Gtk.Label(label=_("La versión nueva ya está descargada"), xalign=0, wrap=True)
        title.add_css_class("title-2")
        body.append(title)
        ver = (_("De {a} a {b}. ", a=current, b=new) if current and new else "")
        intro = Gtk.Label(xalign=0, wrap=True, label=ver + _(
            "Para terminar hay que parar VELA unos segundos, copiar la versión nueva y arrancarla. Mientras está "
            "parado no vigila tus conexiones ni puede activar el kill-switch automático si hay una fuga."))
        body.append(intro)

        def pick(v):
            choice["value"] = v
            win.close()
        ks_body = _("Antes de parar VELA se bloquea todo el tráfico que no vaya por la VPN, Tor o la red local, y "
                    "se desbloquea en cuanto la versión nueva responde. Sin VPN conectada, durante esos segundos solo "
                    "funcionarán la red local y Tor. Elegirlo da permiso solo para esta actualización (puede pedirte "
                    "la contraseña).")
        if opts.get("killswitch_already"):
            ks_body = _("El kill-switch ya está activo: se mantiene durante el cambio y se deja como estaba.")
        elif not opts.get("killswitch"):
            ks_body += "\n" + _("No disponible ahora: {why}", why=opts.get("killswitch_reason") or "—")
        body.append(_row(_("Protegido con kill-switch (recomendado)"), ks_body, _("Actualizar con kill-switch"),
                         "suggested-action", bool(opts.get("killswitch")), lambda: pick("killswitch")))
        body.append(_row(_("Cerrar y volver a abrir"),
                         _("VELA se cierra, se instala la versión nueva y se vuelve a abrir. Durante esos segundos no "
                           "hay protección: si algo sale fuera del túnel, tu IP real podría quedar expuesta."),
                         _("Actualizar sin protección"), "destructive-action", True, lambda: pick("restart")))
        cancel = Gtk.Button(label=_("Ahora no"), halign=Gtk.Align.END)
        cancel.add_css_class("flat")
        cancel.connect("clicked", lambda *_a: pick("cancel"))
        body.append(cancel)
        tv.set_content(body)
        win.set_content(tv)
        win.present()
        if on_ready:
            on_ready(win)

    app.connect("activate", activate)
    app.run([sys.argv[0]])
    return choice["value"]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--current")
    ap.add_argument("--new")
    a = ap.parse_args()
    v = run(a.current, a.new)
    print(v, flush=True)
    return 1 if v == "cancel" else 0


if __name__ == "__main__":
    sys.exit(main())
