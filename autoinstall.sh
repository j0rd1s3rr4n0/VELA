#!/usr/bin/env bash
# VELA — autoinstalador para Linux.
#
# Uso recomendado (sin sudo):
#   curl -fsSL https://raw.githubusercontent.com/j0rd1s3rr4n0/VELA/master/autoinstall.sh | bash
#
# También funciona desde un clon:
#   ./autoinstall.sh
#   sudo ./autoinstall.sh          # se redirige al usuario que invocó sudo
#
# Opciones:
#   --dir DIR        clonar/actualizar VELA en DIR (por defecto ~/.local/src/VELA)
#   --branch RAMA    rama a instalar (por defecto master)
#   --all            pasar --with-all a install.sh (OCR + MAC + Ollama/modelo)
#   --with-ocr --with-mac --with-llm
#   --no-deps --no-service --no-tray --prefix DIR --yes
#   --uninstall      desinstalar (pasa --uninstall a install.sh)
#   --help
#
# El script no escribe rutas de usuario fijas: usa HOME/XDG del usuario real. Las
# dependencias del sistema se instalan con el gestor de paquetes y sudo/pkexec.
set -euo pipefail

ORIG_ARGS=("$@")
REPO="j0rd1s3rr4n0/VELA"
BRANCH="${VELA_BRANCH:-master}"
DEST="${VELA_DIR:-}"
EXPLICIT_DIR=0
PASSTHRU=()

say()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m⚠\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
VELA — autoinstalador para Linux.

Uso recomendado (sin sudo):
  curl -fsSL https://raw.githubusercontent.com/j0rd1s3rr4n0/VELA/master/autoinstall.sh | bash

También funciona desde un clon:
  ./autoinstall.sh
  sudo ./autoinstall.sh          # se redirige al usuario que invocó sudo

Opciones:
  --dir DIR        clonar/actualizar VELA en DIR (por defecto ~/.local/src/VELA)
  --branch RAMA    rama a instalar (por defecto master)
  --all            pasar --with-all a install.sh (OCR + MAC + Ollama/modelo)
  --with-ocr --with-mac --with-llm
  --no-deps --no-service --no-tray --prefix DIR --yes
  --uninstall      desinstalar (pasa --uninstall a install.sh)
  --help

Usa HOME/XDG del usuario real. Las dependencias se instalan con el gestor de
paquetes del sistema y sudo/pkexec.
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) shift; [ $# -gt 0 ] || die "--dir necesita una ruta"; DEST="$1"; EXPLICIT_DIR=1 ;;
    --branch) shift; [ $# -gt 0 ] || die "--branch necesita un nombre"; BRANCH="$1" ;;
    --all) PASSTHRU+=(--with-all) ;;
    --with-all|--with-ocr|--with-mac|--with-llm|--no-deps|--no-optional|--no-service|--no-tray|--yes|-y|--uninstall|--purge)
      PASSTHRU+=("$1") ;;
    --prefix) shift; [ $# -gt 0 ] || die "--prefix necesita una ruta"; PASSTHRU+=(--prefix "$1") ;;
    -h|--help) usage; exit 0 ;;
    *) PASSTHRU+=("$1") ;;
  esac
  shift
done

# Home real del usuario, aunque el entorno venga vacío.
if [ -z "${HOME:-}" ]; then
  HOME="$(getent passwd "$(id -un)" 2>/dev/null | cut -d: -f6 || true)"
fi
[ -n "${HOME:-}" ] || die "no puedo determinar el home de $(id -un); define HOME"
[ -n "$DEST" ] || DEST="${HOME}/.local/src/VELA"
TARGET_USER="$(id -un)"

# Si se lanzó con sudo desde un fichero, volver al usuario que invocó sudo.
if [ "$(id -u)" = 0 ] && [ -n "${SUDO_USER:-}" ] && [ "${VELA_AUTO_AS_USER:-0}" != 1 ]; then
  if [ -f "${BASH_SOURCE[0]:-}" ]; then
    TARGET_HOME="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -u "$SUDO_USER" -H env VELA_AUTO_AS_USER=1 bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}"
    elif command -v runuser >/dev/null 2>&1; then
      exec runuser -u "$SUDO_USER" -- env HOME="${TARGET_HOME:-$HOME}" VELA_AUTO_AS_USER=1 bash "${BASH_SOURCE[0]}" "${ORIG_ARGS[@]}"
    fi
  fi
  die "no ejecutes el autoinstalador con sudo cuando se descarga por curl; ejecútalo sin sudo"
fi

have() { command -v "$1" >/dev/null 2>&1; }

pm_family() {
  for pair in "apt-get deb" "dnf rpm" "pacman arch" "zypper suse"; do
    set -- $pair
    have "$1" && { printf '%s\n' "$2"; return; }
  done
}

pm_install() {
  local fam; fam="$(pm_family)"
  [ -n "$fam" ] || { warn "no reconozco el gestor de paquetes; instala a mano: $*"; return 1; }
  local cmd
  case "$fam" in
    deb) cmd=(apt-get install -y) ;;
    rpm) cmd=(dnf install -y) ;;
    arch) cmd=(pacman -S --needed --noconfirm) ;;
    suse) cmd=(zypper install -y) ;;
  esac
  if [ "$(id -u)" = 0 ]; then
    "${cmd[@]}" "$@"
  elif have sudo; then
    sudo "${cmd[@]}" "$@"
  elif have pkexec; then
    pkexec "${cmd[@]}" "$@"
  else
    warn "faltan $* y no hay sudo/pkexec; instálalos a mano"
    return 1
  fi
}

need_tool() {
  local name="$1" pkg="${2:-$1}"
  if ! have "$name"; then
    say "Instalando $pkg (necesario para el autoinstalador)…"
    pm_install "$pkg" || true
  fi
}

# Git es lo ideal; curl/wget y tar permiten la descarga directa si no hay git.
have git || need_tool git git
if have curl; then
  DL=(curl -fL --retry 3 --connect-timeout 15 -o)
elif have wget; then
  DL=(wget -O)
else
  need_tool curl curl
  DL=(curl -fL --retry 3 --connect-timeout 15 -o)
fi
have curl || have wget || die "faltan curl y wget; instala uno para descargar VELA"
command -v tar >/dev/null 2>&1 || need_tool tar tar
have tar || die "falta tar; instálalo para descomprimir VELA"

# ¿Estamos dentro de un clon? Si sí, úsalo salvo que se pida --dir.
LOCAL_SRC=""
if [ "$EXPLICIT_DIR" = 0 ] && [ -f "${BASH_SOURCE[0]:-}" ]; then
  CAND="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  if [ -f "$CAND/vela/__init__.py" ] && [ -f "$CAND/install.sh" ]; then
    LOCAL_SRC="$CAND"
  fi
fi

SRC="$LOCAL_SRC"
if [ -z "$SRC" ]; then
  case "$DEST" in
    /*) ;;
    *) DEST="$PWD/$DEST" ;;
  esac
  if [ -f "$DEST/vela/__init__.py" ] && [ -f "$DEST/install.sh" ]; then
    SRC="$DEST"
    say "Usando la copia existente en $SRC"
    if [ -d "$DEST/.git" ] && have git; then
      say "Actualizando $BRANCH (solo avance)…"
      git -C "$DEST" fetch --depth 1 origin "$BRANCH" >/dev/null 2>&1 || true
      git -C "$DEST" checkout -q "$BRANCH" >/dev/null 2>&1 || true
      git -C "$DEST" pull --ff-only origin "$BRANCH" >/dev/null 2>&1 || warn "no se pudo actualizar; uso la copia actual"
    fi
  elif [ -e "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null || true)" ]; then
    die "$DEST ya existe y no parece un clon de VELA; usa --dir otra-ruta"
  else
    mkdir -p "$(dirname "$DEST")"
    if have git; then
      say "Clonando VELA ($BRANCH) en $DEST…"
      if git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" "$DEST"; then
        SRC="$DEST"
      else
        warn "git clone falló; probando tarball…"
        rm -rf "$DEST"
      fi
    fi
    if [ -z "$SRC" ]; then
      TMP="$(mktemp -d "${TMPDIR:-/tmp}/vela-auto-XXXXXX")"
      trap 'rm -rf "$TMP"' EXIT
      say "Descargando VELA ($BRANCH)…"
      "${DL[@]}" "$TMP/vela.tar.gz" "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" \
        || die "no se pudo descargar VELA"
      tar -xzf "$TMP/vela.tar.gz" -C "$TMP"
      mkdir -p "$DEST"
      # El tarball contiene un único directorio VELA-<rama>.
      cp -a "$TMP"/VELA-*/. "$DEST"/
      SRC="$DEST"
    fi
  fi
fi

[ -n "$SRC" ] && [ -f "$SRC/install.sh" ] || die "no encuentro install.sh en $SRC"
[ -f "$SRC/vela/__init__.py" ] || die "no parece un repositorio de VELA: $SRC"

# En una descarga por curl no hay TTY para las preguntas del instalador.
if [ ! -t 0 ]; then
  found=0
  for a in "${PASSTHRU[@]:-}"; do [ "$a" = "--yes" ] || [ "$a" = "-y" ] && found=1; done
  [ "$found" = 1 ] || PASSTHRU+=(--yes)
fi

say "Instalando VELA para $TARGET_USER desde $SRC…"
cd "$SRC"
chmod +x ./install.sh 2>/dev/null || true
./install.sh "${PASSTHRU[@]}"

ok "VELA instalado."
say "Abrir: vela app  ·  Estado: vela status  ·  Datos: $SRC"
say "Actualizar: cd \"$SRC\" && ./install.sh  ·  Desinstalar: ./install.sh --uninstall"
