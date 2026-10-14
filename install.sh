#!/usr/bin/env bash
# VELA — instalador para Linux (por usuario, sin pip ni root salvo para dependencias del sistema).
#
#   ./install.sh               instala o actualiza: app, servicio velad, bandeja y lanzador
#   ./install.sh --uninstall   desinstala (conserva tus datos)
#   ./install.sh --uninstall --purge   desinstala y borra también historial, ajustes y claves
#
# Opciones: --yes (sin preguntas) · --no-service · --no-tray · --no-deps · --prefix DIR
#
# Qué hace: copia el paquete a ~/.local/lib/vela, crea los comandos ~/.local/bin/vela y velad,
# instala el lanzador y el icono, el servicio de usuario de systemd (velad) y el icono de bandeja.
# No usa pip: así funciona también en distribuciones con Python «externally managed» (PEP 668).
set -euo pipefail

PREFIX="${HOME}/.local/lib/vela"
BIN="${HOME}/.local/bin"
APP_ID="io.github.j0rd1s3rr4n0.Vela"
YES=0; SERVICE=1; TRAY=1; DEPS=1; MODE=install; PURGE=0
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "${LANG:-}${LANGUAGE:-}" in es*|*:es*) L=es ;; *) L=en ;; esac
t() { if [ "$L" = es ]; then printf '%s' "$1"; else printf '%s' "$2"; fi; }
say()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }
ask()  { [ "$YES" = 1 ] && return 0; local r; read -r -p "$1 [s/N] " r || true; [[ "$r" =~ ^[sSyY]$ ]]; }

while [ $# -gt 0 ]; do
  case "$1" in
    --uninstall) MODE=uninstall ;;
    --purge) PURGE=1 ;;
    --yes|-y) YES=1 ;;
    --no-service) SERVICE=0 ;;
    --no-tray) TRAY=0 ;;
    --no-deps) DEPS=0 ;;
    --prefix) shift; PREFIX="$1" ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "$(t "opción desconocida: $1" "unknown option: $1")" ;;
  esac
  shift
done

[ "$(uname -s)" = Linux ] || die "$(t "este instalador es para Linux (en Windows usa install.ps1)" "this installer is for Linux (on Windows use install.ps1)")"
[ "$(id -u)" != 0 ] || die "$(t "no lo ejecutes como root: VELA se instala para tu usuario" "don't run it as root: VELA installs for your user")"

# la copia instalada va siempre primero en sys.path (aunque se ejecute desde la carpeta del repositorio)
vela() { env PYTHONPATH="$PREFIX" python3 -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from vela.cli import main; sys.exit(main())' "$PREFIX" "$@"; }

# ── desinstalar ─────────────────────────────────────────────────────────────
if [ "$MODE" = uninstall ]; then
  say "$(t "Desinstalando VELA…" "Uninstalling VELA…")"
  if [ -d "$PREFIX/vela" ]; then
    vela daemon disable >/dev/null 2>&1 || true
    vela tray --remove >/dev/null 2>&1 || true
  fi
  systemctl --user disable --now velad.service >/dev/null 2>&1 || true
  rm -f "$HOME/.config/systemd/user/velad.service" "$HOME/.config/autostart/vela-tray.desktop" \
        "$HOME/.local/share/applications/$APP_ID.desktop" \
        "$HOME/.local/share/icons/hicolor/scalable/apps/$APP_ID.svg" "$BIN/vela" "$BIN/velad"
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  rm -rf "$PREFIX"
  ok "$(t "Programa, servicio, bandeja y lanzador eliminados." "Program, service, tray and launcher removed.")"
  if [ "$PURGE" = 1 ]; then
    DATA=("${XDG_CONFIG_HOME:-$HOME/.config}/vela" "${XDG_DATA_HOME:-$HOME/.local/share}/vela"
          "${XDG_STATE_HOME:-$HOME/.local/state}/vela" "${XDG_CACHE_HOME:-$HOME/.cache}/vela")
    warn "$(t "Se borrarán tu historial, ajustes y claves de API:" "This deletes your history, settings and API keys:") ${DATA[*]}"
    if ask "$(t "¿Borrar los datos?" "Delete the data?")"; then rm -rf "${DATA[@]}"; ok "$(t "Datos borrados." "Data deleted.")"; fi
  else
    say "$(t "Tus datos se conservan (historial, ajustes, claves). Bórralos con --uninstall --purge." "Your data is kept (history, settings, keys). Remove it with --uninstall --purge.")"
  fi
  exit 0
fi

# ── comprobaciones ──────────────────────────────────────────────────────────
[ -f "$SRC/vela/__init__.py" ] || die "$(t "ejecútalo desde la carpeta del repositorio de VELA" "run it from the VELA repository folder")"
command -v python3 >/dev/null || die "$(t "falta python3 (≥ 3.10)" "python3 (≥ 3.10) is missing")"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' || die "$(t "hace falta Python ≥ 3.10" "Python ≥ 3.10 is required")"
VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SRC/vela/__init__.py")"
say "$(t "Instalando VELA $VERSION para $USER" "Installing VELA $VERSION for $USER")"

has_gui()  { python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1"); from gi.repository import Gtk, Adw' 2>/dev/null; }
has_tray() { python3 -c 'import gi; gi.require_version("AyatanaAppIndicator3","0.1"); from gi.repository import AyatanaAppIndicator3' 2>/dev/null; }

if [ "$DEPS" = 1 ] && { ! has_gui || { [ "$TRAY" = 1 ] && ! has_tray; } || ! command -v notify-send >/dev/null; }; then
  PM=""; PKGS=""
  if   command -v apt-get >/dev/null; then PM="sudo apt-get install -y"; PKGS="python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-ayatanaappindicator3-0.1 libnotify-bin"
  elif command -v dnf     >/dev/null; then PM="sudo dnf install -y";     PKGS="python3-gobject gtk4 libadwaita libayatana-appindicator-gtk3 libnotify"
  elif command -v pacman  >/dev/null; then PM="sudo pacman -S --needed --noconfirm"; PKGS="python-gobject gtk4 libadwaita libayatana-appindicator libnotify"
  elif command -v zypper  >/dev/null; then PM="sudo zypper install -y"; PKGS="python3-gobject typelib-1_0-Gtk-4_0 typelib-1_0-Adw-1 typelib-1_0-AyatanaAppIndicator3-0_1 libnotify-tools"
  fi
  if [ -n "$PM" ]; then
    warn "$(t "Faltan dependencias de la app de escritorio/bandeja:" "Desktop app/tray dependencies are missing:") $PKGS"
    if ask "$(t "¿Instalarlas ahora con «$PM»?" "Install them now with «$PM»?")"; then $PM $PKGS || warn "$(t "no se pudieron instalar; la CLI funciona igual" "could not install them; the CLI still works")"; fi
  else
    warn "$(t "No reconozco el gestor de paquetes: instala PyGObject, GTK 4, libadwaita y AyatanaAppIndicator3 para la app y la bandeja." "Unknown package manager: install PyGObject, GTK 4, libadwaita and AyatanaAppIndicator3 for the app and tray.")"
  fi
fi
command -v tor >/dev/null || say "$(t "Opcional: instala «tor» para circuitos, comprobaciones por Tor y ExoneraTor." "Optional: install «tor» for circuits, Tor-based checks and ExoneraTor.")"

# ── copiar el programa ──────────────────────────────────────────────────────
mkdir -p "$PREFIX" "$BIN"
rm -rf "$PREFIX/vela.new"
cp -r "$SRC/vela" "$PREFIX/vela.new"
find "$PREFIX/vela.new" -name __pycache__ -type d -prune -exec rm -rf {} +
rm -rf "$PREFIX/vela" && mv "$PREFIX/vela.new" "$PREFIX/vela"
ok "$(t "Programa copiado a $PREFIX" "Program copied to $PREFIX")"

cat > "$BIN/vela" <<EOF
#!/bin/sh
# VELA — Vigilant Egress & Leak Analyst (instalado por install.sh)
exec env PYTHONPATH="$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}" python3 -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from vela.cli import main; sys.exit(main())' "$PREFIX" "\$@"
EOF
cat > "$BIN/velad" <<EOF
#!/bin/sh
exec env PYTHONPATH="$PREFIX\${PYTHONPATH:+:\$PYTHONPATH}" python3 -c 'import sys; sys.path.insert(0, sys.argv.pop(1)); from vela.cli import main; sys.exit(main())' "$PREFIX" daemon run "\$@"
EOF
chmod 755 "$BIN/vela" "$BIN/velad"
ok "$(t "Comandos «vela» y «velad» en $BIN" "«vela» and «velad» commands in $BIN")"
case ":$PATH:" in *":$BIN:"*) ;; *) warn "$(t "$BIN no está en tu PATH: añádelo (p. ej. en ~/.profile) o usa $BIN/vela" "$BIN is not in your PATH: add it (e.g. in ~/.profile) or use $BIN/vela")" ;; esac

# ── integración con el escritorio y servicio ────────────────────────────────
if has_gui; then
  vela app --install >/dev/null && ok "$(t "Lanzador «VELA» en el menú de aplicaciones" "«VELA» launcher in the applications menu")"
else
  warn "$(t "Sin GTK 4/libadwaita: la app de escritorio no estará disponible (CLI, TUI y GUI web sí)" "No GTK 4/libadwaita: the desktop app won't be available (CLI, TUI and web GUI will)")"
fi

if [ "$SERVICE" = 1 ]; then
  if command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
    vela daemon enable >/dev/null
    systemctl --user daemon-reload
    systemctl --user restart velad.service      # por si ya corría una versión anterior
    sleep 2
    if systemctl --user is-active --quiet velad.service; then ok "$(t "Servicio velad activo y habilitado al iniciar sesión" "velad service active and enabled at login")"
    else warn "$(t "El servicio no arrancó: revisa «journalctl --user -u velad»" "The service didn't start: check «journalctl --user -u velad»")"; fi
  else
    warn "$(t "Sin systemd de usuario: arranca el daemon con «vela daemon start»" "No systemd user session: start the daemon with «vela daemon start»")"
  fi
fi

if [ "$TRAY" = 1 ] && has_tray; then
  vela tray --install >/dev/null 2>&1 && ok "$(t "Icono de bandeja al iniciar sesión" "Tray icon at login")" || warn "$(t "no se pudo activar la bandeja" "could not enable the tray")"
fi

if ! id -nG | tr ' ' '\n' | grep -qx debian-tor && getent group debian-tor >/dev/null; then
  say "$(t "Para observar Tor: sudo usermod -aG debian-tor $USER (y vuelve a iniciar sesión)" "To observe Tor: sudo usermod -aG debian-tor $USER (then log in again)")"
fi

echo
ok "$(t "VELA $VERSION instalado. Ábrelo desde el menú o con «vela app»; en la terminal: «vela status»." "VELA $VERSION installed. Open it from the menu or with «vela app»; in a terminal: «vela status».")"
say "$(t "Actualizar: vuelve a ejecutar ./install.sh · Desinstalar: ./install.sh --uninstall" "Update: run ./install.sh again · Uninstall: ./install.sh --uninstall")"
