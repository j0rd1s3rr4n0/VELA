"""Guardián de git: impide que lleguen al repositorio secretos o datos que te identifican.

Se ejecuta desde los hooks versionados en .githooks/ (core.hooksPath):
  * pre-commit: revisa los ficheros preparados (git add);
  * pre-push: revisa cada commit que se va a enviar y el correo de su autor;
  * `python3 -m opsectools.gitguard all`: revisa todo lo que ya está en el repositorio.

Qué bloquea:
  1. Valores EXACTOS de este equipo: tus claves de API (secrets.toml / variables de entorno) y tus IPs
     reales (WAN del router, IP pública sin VPN, known_real_ips). Los conoce sin guardarlos en ningún sitio.
  2. Patrones genéricos de secretos: claves privadas, PrivateKey de WireGuard, tokens de GitHub/AWS/
     Google/Slack, asignaciones del tipo api_key = "…".
  3. Ficheros que nunca deben versionarse: .devlogs/, bases de datos, secrets.toml, ajustes de la app,
     cookies de Tor, configuraciones de VPN, claves, __pycache__…
Nunca imprime el secreto encontrado: solo fichero, línea y tipo.
Una línea con «gitguard: allow» se excluye de los patrones genéricos (no de los valores exactos).
"""

from __future__ import annotations

import re
import subprocess
import sys

ZERO = "0" * 40
ALLOW = "gitguard: allow"

FORBIDDEN_PATHS = [
    (r"(^|/)\.devlogs/", "registros de desarrollo (capturas con tus IPs, volcados del sistema)"),
    (r"(^|/)__pycache__/|\.py[co]$", "bytecode de Python"),
    (r"\.(db|sqlite3?)(-wal|-shm|-journal)?$", "base de datos (historial de sesiones e IPs)"),
    (r"(^|/)secrets\.toml$", "claves de API"),
    (r"(^|/)(app-settings\.toml|app-state\.json)$", "ajustes personales de la app"),
    (r"(^|/)config\.toml$", "tu configuración (usa config.example.toml)"),
    (r"\.mmdb$", "base GeoIP con licencia propia"),
    (r"(^|/)\.env(\..*)?$", "variables de entorno"),
    (r"\.(pem|key|p12|pfx|kdbx|gpg|asc)$", "clave o almacén de claves"),
    (r"(^|/)id_(rsa|dsa|ecdsa|ed25519)(\.pub)?$", "clave SSH"),
    (r"(^|/)(cookie|control_auth_cookie)$", "cookie de autenticación (Tor)"),
    (r"\.ovpn$|(^|/)wg\d*\.conf$|\.nmconnection$", "configuración de VPN (puede llevar claves privadas)"),
    (r"\.part$", "descarga a medias"),
]

PATTERNS = [
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----")),
    ("PrivateKey de WireGuard", re.compile(r"PrivateKey\s*=\s*[A-Za-z0-9+/]{42,43}=")),
    ("token de GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("clave de AWS", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("clave de Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("token de Slack", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("secreto asignado", re.compile(
        r"(?i)\b[\w.]*(?:api[_-]?key|apikey|secret|token|passw(?:or)?d)[\w.]*\s*[:=]\s*[\"']([A-Za-z0-9_\-+/=.]{20,})[\"']")),
]

NOREPLY = re.compile(r"noreply|no-reply|users\.noreply\.github\.com$|@localhost$|\.invalid$", re.I)


def git(*args, text=True, check=True):
    r = subprocess.run(["git", *args], capture_output=True, text=text)
    if check and r.returncode != 0:
        raise RuntimeError((r.stderr if text else r.stderr.decode(errors="replace")).strip())
    return r.stdout


# ── valores sensibles de ESTE equipo ────────────────────────────────────────

def sensitive_values() -> list[tuple[str, re.Pattern]]:
    """[(tipo, patrón exacto)] con tus claves de API y tus IPs reales; si algo falla, se omite."""
    out = []
    try:
        from . import intel
        for name, v in (intel.load_keys() or {}).items():
            if isinstance(v, str) and len(v) >= 10:
                out.append((f"tu clave de API ({name})", re.compile(re.escape(v))))
    except Exception:  # noqa: BLE001
        pass
    ips = set()
    try:
        from . import config
        ips |= set((config.load().get("public_ip") or {}).get("known_real_ips") or [])
    except Exception:  # noqa: BLE001
        pass
    try:
        from . import intel, store
        if store.default_path().exists():
            st = store.Store()
            try:
                ips |= intel.own_ips(st)
            finally:
                close = getattr(st, "close", None)
                if close:
                    close()
    except Exception:  # noqa: BLE001
        pass
    for ip in sorted(i for i in ips if i):
        out.append(("tu IP real", re.compile(r"(?<![\w.])" + re.escape(ip) + r"(?!\w|\.\d)")))
    return out


# ── revisión ────────────────────────────────────────────────────────────────

def check_path(path: str) -> str | None:
    for rx, why in FORBIDDEN_PATHS:
        if re.search(rx, path):
            return why
    return None


def scan_blob(path: str, data: bytes, exact) -> list[tuple[str, int, str]]:
    found = []
    binary = b"\0" in data[:8000]
    text = data.decode("utf-8", "replace")
    lines = text.splitlines()
    for kind, rx in exact:                       # también en binarios
        for m in rx.finditer(text):
            found.append((path, text.count("\n", 0, m.start()) + 1 if not binary else 0, kind))
    if binary:
        return found
    for n, line in enumerate(lines, 1):
        if ALLOW in line:
            continue
        for kind, rx in PATTERNS:
            if rx.search(line):
                found.append((path, n, kind))
    return found


def scan(items, reader, exact=None) -> list[tuple[str, int, str]]:
    """items: rutas; reader(path) → bytes | None (None = borrado)."""
    exact = sensitive_values() if exact is None else exact
    found = []
    for path in items:
        why = check_path(path)
        if why:
            found.append((path, 0, f"fichero prohibido: {why}"))
            continue
        data = reader(path)
        if data is not None:
            found += scan_blob(path, data, exact)
    return found


def report(found, what: str) -> int:
    if not found:
        return 0
    print(f"\n✖ gitguard: {what} bloqueado — {len(found)} problema(s):", file=sys.stderr)
    for path, line, kind in found[:60]:
        print(f"   {path}{':' + str(line) if line else ''}  →  {kind}", file=sys.stderr)
    if len(found) > 60:
        print(f"   … y {len(found) - 60} más", file=sys.stderr)
    print("\n   Saca el fichero del índice (git rm --cached <fichero>) o quita el dato y vuelve a intentarlo.\n"
          f"   Para un falso positivo de un patrón genérico, añade «{ALLOW}» en esa línea.\n", file=sys.stderr)
    return 1


def email_problem(email: str) -> str | None:
    if not email:
        return None
    if NOREPLY.search(email) or git("config", "--bool", "opsec.allowEmail", check=False).strip() == "true":
        return None
    return (f"el correo del autor ({email}) quedará publicado en cada commit. Usa uno sin datos personales, p. ej. "
            "git config user.email \"<id>+<usuario>@users.noreply.github.com\" (o permite el tuyo con "
            "git config opsec.allowEmail true)")


def pre_commit() -> int:
    paths = [p for p in git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0") if p]
    found = scan(paths, lambda p: git("show", f":{p}", text=False))
    rc = report(found, "commit")
    warn = email_problem(git("config", "user.email", check=False).strip())
    if warn:
        print(f"⚠ gitguard: {warn}", file=sys.stderr)
    return rc


def pre_push(stdin_lines) -> int:
    exact = sensitive_values()
    found, emails = [], set()
    for line in stdin_lines:
        parts = line.split()
        if len(parts) < 4 or parts[1] == ZERO:
            continue
        local, remote = parts[1], parts[3]
        rng = [f"{remote}..{local}"] if remote != ZERO else [local, "--not", "--remotes"]
        for c in [x for x in git("rev-list", *rng).split() if x]:
            emails |= {git("log", "-1", "--format=%ae", c).strip(), git("log", "-1", "--format=%ce", c).strip()}
            paths = [p for p in git("diff-tree", "--no-commit-id", "-r", "-m", "--root", "--name-only",
                                    "--diff-filter=ACMR", "-z", c).split("\0") if p]
            found += [(f"{c[:8]}:{p}", n, k) for p, n, k in
                      scan(sorted(set(paths)), lambda p, c=c: git("show", f"{c}:{p}", text=False), exact)]
    rc = report(found, "push")
    for e in sorted(emails):
        problem = email_problem(e)
        if problem:
            print(f"✖ gitguard: push bloqueado — {problem}", file=sys.stderr)
            rc = 1
    return rc


def check_all() -> int:
    paths = [p for p in git("ls-files", "-z").split("\0") if p]
    found = scan(paths, lambda p: git("show", f":{p}", text=False))
    if not found:
        print(f"✔ gitguard: {len(paths)} ficheros revisados, sin secretos ni datos personales")
    return report(found, "repositorio")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    mode = argv[0] if argv else "all"
    try:
        if mode == "pre-commit":
            return pre_commit()
        if mode == "pre-push":
            return pre_push(sys.stdin.read().splitlines())
        return check_all()
    except RuntimeError as e:
        print(f"gitguard: error de git: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
