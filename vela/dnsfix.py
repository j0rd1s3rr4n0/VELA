"""Aplicar y revertir DNS cifrado (DoT con systemd-resolved o DoH con cloudflared).

Todo cambio del sistema pasa por una comprobación de consentimiento, un backup del fichero
que se va a sustituir y una verificación posterior. La ejecución usa `pkexec` (diálogo del
escritorio) o `sudo -n`; nunca se ejecuta una shell con texto del usuario.

DoT:
  /etc/systemd/resolved.conf.d/90-vela-dot.conf
  [Resolve]
  DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com
  DNSOverTLS=yes

DoH:
  cloudflared proxy-dns en 127.0.0.1:5053 (servicio de usuario)
  systemd-resolved apunta a 127.0.0.1:5053 con DNSOverTLS=no.
"""

from __future__ import annotations

from .i18n import _

import os
import shutil
import time
from pathlib import Path

from . import config as config_mod
from .util import now, private_dir, run, tilde, which, xdg_dir

DOT_FILE = Path("/etc/systemd/resolved.conf.d/90-vela-dot.conf")
DOH_FILE = Path("/etc/systemd/resolved.conf.d/90-vela-doh.conf")
DOH_PORT = 5053
PROVIDERS = {
    "cloudflare": {"name": "Cloudflare", "dot": ["1.1.1.1#cloudflare-dns.com", "1.0.0.1#cloudflare-dns.com"],
                   "doh": ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"]},
    "quad9": {"name": "Quad9", "dot": ["9.9.9.9#dns.quad9.net", "149.112.112.112#dns.quad9.net"],
              "doh": ["https://9.9.9.9/dns-query", "https://149.112.112.112/dns-query"]},
    "google": {"name": "Google", "dot": ["8.8.8.8#dns.google", "8.8.4.4#dns.google"],
               "doh": ["https://8.8.8.8/dns-query", "https://8.8.4.4/dns-query"]},
    "mullvad": {"name": "Mullvad", "dot": ["194.242.2.2#dns.mullvad.net", "194.242.2.3#dns.mullvad.net"],
                "doh": ["https://dns.mullvad.net/dns-query"]},
}
BACKUP_DIR = xdg_dir("state") / "dns-backup"
SERVICE = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config") / "systemd/user/vela-cloudflared.service"


class DnsFixError(RuntimeError):
    pass


def _consent(cfg: dict | None = None) -> bool:
    cfg = cfg or config_mod.load()
    return bool((cfg.get("consent") or {}).get("allow_dns_changes"))


def status(cfg: dict | None = None) -> dict:
    from . import dns
    snap = dns.snapshot()
    enc = snap.get("encryption") or {}
    return {"encrypted": snap.get("encrypted"), "backend": snap.get("backend"),
            "resolvers": enc.get("resolvers") or [], "dot_file": DOT_FILE.exists(), "doh_file": DOH_FILE.exists(),
            "cloudflared": bool(which("cloudflared")), "consent": _consent(cfg)}


def _content(transport: str, provider: str, servers: list[str] | None = None) -> str:
    if transport == "dot":
        if servers:
            dns = " ".join(servers)
        else:
            p = PROVIDERS.get(provider)
            if not p:
                raise DnsFixError(_("proveedor DNS no válido: {provider}", provider=provider))
            dns = " ".join(p["dot"])
        return f"# Generado por VELA. Elimina este fichero para volver al DNS anterior.\n[Resolve]\nDNS={dns}\nDNSOverTLS=yes\n"
    if transport == "doh":
        return (f"# Generado por VELA: systemd-resolved habla con cloudflared en 127.0.0.1:{DOH_PORT}.\n"
                "[Resolve]\nDNS=127.0.0.1:%d\nDNSOverTLS=no\n" % DOH_PORT)
    raise DnsFixError(_("transporte no válido: {transport}", transport=transport))


def _service(provider: str) -> str:
    p = PROVIDERS.get(provider) or PROVIDERS["cloudflare"]
    ups = " ".join(f"--upstream {u}" for u in p["doh"])
    return ("[Unit]\nDescription=VELA DNS-over-HTTPS (cloudflared)\nAfter=network-online.target\n\n"
            "[Service]\nType=simple\nExecStart=%s proxy-dns --address 127.0.0.1 --port %d %s\n"
            "Restart=on-failure\nRestartSec=5\n\n[Install]\nWantedBy=default.target\n"
            % (which("cloudflared") or "/usr/bin/cloudflared", DOH_PORT, ups))


def _priv(args: list[str], input_text: str | None = None, timeout: float = 120) -> tuple[int, str, str]:
    if os.geteuid() == 0:
        return run(args, timeout=timeout, input_text=input_text)
    if which("pkexec"):
        return run(["pkexec", *args], timeout=timeout, input_text=input_text)
    if which("sudo"):
        code, out, err = run(["sudo", "-n", *args], timeout=timeout, input_text=input_text)
        if code == 0:
            return code, out, err
        raise DnsFixError(_("sudo pide contraseña; ejecuta el comando a mano o instala pkexec"))
    raise DnsFixError(_("no hay pkexec ni sudo: no puedo modificar el DNS del sistema"))


def _write_root(path: Path, text: str) -> None:
    code, out, err = _priv(["mkdir", "-p", str(path.parent)])
    if code != 0:
        raise DnsFixError(_("no se pudo crear {path}: {e}", path=str(path.parent), e=(err or out).strip()[:400]))
    code, out, err = _priv(["tee", str(path)], input_text=text)
    if code != 0:
        raise DnsFixError(_("no se pudo escribir {path}: {e}", path=str(path), e=(err or out).strip()[:400]))


def _backup(path: Path) -> Path | None:
    if not path.exists():
        return None
    private_dir(BACKUP_DIR)
    dest = BACKUP_DIR / f"{path.name}.{int(now())}.bak"
    try:
        shutil.copyfile(path, dest)
        os.chmod(dest, 0o600)
        return dest
    except OSError:
        return None


def _restart_resolved() -> dict:
    code, out, err = _priv(["systemctl", "restart", "systemd-resolved"])
    ok = code == 0
    return {"ok": ok, "code": code, "error": None if ok else (err or out).strip()[:400]}


def plan(transport: str = "dot", provider: str = "cloudflare", servers: list[str] | None = None) -> dict:
    """Comandos y ficheros que se tocarían, sin ejecutar nada."""
    if transport == "dot":
        path, content = DOT_FILE, _content("dot", provider, servers)
        cmds = [f"mkdir -p {path.parent}", f"escribir {path}", "systemctl restart systemd-resolved"]
        packages = ["systemd-resolved"]
    elif transport == "doh":
        path, content = DOH_FILE, _content("doh", provider)
        if not which("cloudflared"):
            raise DnsFixError(_("cloudflared no está instalado; usa DoT o instala cloudflared"))
        cmds = [f"escribir {path}", f"crear {SERVICE}", "systemctl --user enable --now vela-cloudflared",
                "systemctl restart systemd-resolved"]
        packages = ["cloudflared"]
    else:
        raise DnsFixError(_("transporte no válido: {transport}", transport=transport))
    return {"transport": transport, "provider": provider, "file": str(path), "content": content,
            "service": str(SERVICE) if transport == "doh" else None, "commands": cmds, "packages": packages,
            "root": True, "consent": _consent()}


def _verify(transport: str) -> dict:
    time.sleep(0.4)
    try:
        from . import dns
        snap = dns.snapshot()
        enc = snap.get("encryption") or {}
        res = enc.get("resolvers") or []
        ok = snap.get("encrypted") is True
        if transport == "doh":
            ok = any(str(r.get("addr", "")).startswith("127.0.0.1") for r in res) and snap.get("encrypted") is True
        return {"ok": bool(ok), "encrypted": snap.get("encrypted"), "resolvers": res}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)}


def apply(transport: str = "dot", provider: str = "cloudflare", servers: list[str] | None = None,
          cfg: dict | None = None, engine=None) -> dict:
    """Aplica DNS cifrado. Requiere `[consent] allow_dns_changes = true`."""
    cfg = cfg or config_mod.load()
    if not _consent(cfg):
        raise DnsFixError(_("activa [consent] allow_dns_changes = true para cambiar el DNS del sistema"))
    p = plan(transport, provider, servers)
    path = Path(p["file"])
    backup = _backup(path)
    result = {"ok": False, "transport": transport, "provider": provider, "file": str(path),
              "backup": tilde(backup) if backup else None, "plan": p}
    try:
        _write_root(path, p["content"])
        if transport == "doh":
            private_dir(SERVICE.parent)
            SERVICE.write_text(_service(provider), encoding="utf-8")
            os.chmod(SERVICE, 0o600)
            code, out, err = run(["systemctl", "--user", "daemon-reload"])
            if code != 0:
                raise DnsFixError(_("systemctl --user falló: {e}", e=(err or out).strip()[:300]))
            code, out, err = run(["systemctl", "--user", "enable", "--now", "vela-cloudflared"])
            if code != 0:
                raise DnsFixError(_("no se pudo iniciar cloudflared: {e}", e=(err or out).strip()[:300]))
        result["restart"] = _restart_resolved()
        if not result["restart"]["ok"]:
            raise DnsFixError(result["restart"].get("error") or _("no se pudo reiniciar systemd-resolved"))
        result["verify"] = _verify(transport)
        result["ok"] = bool(result["verify"].get("ok"))
        if not result["ok"]:
            result["error"] = _("el DNS cambió pero no se pudo verificar el cifrado")
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        # Rollback: si había backup se restaura; si no, se elimina el fichero creado.
        try:
            if backup:
                _write_root(path, backup.read_text(encoding="utf-8"))
            else:
                _priv(["rm", "-f", str(path)])
            _restart_resolved()
            if transport == "doh":
                run(["systemctl", "--user", "disable", "--now", "vela-cloudflared"])
                SERVICE.unlink(missing_ok=True)
            result["rolled_back"] = True
        except Exception as e2:  # noqa: BLE001
            result["rollback_error"] = str(e2)
    if engine is not None:
        try:
            engine.store.audit(getattr(engine, "actor", "cli"), "dns_encrypt",
                               {"transport": transport, "provider": provider, "ok": result["ok"],
                                "error": result.get("error")})
        except Exception:  # noqa: BLE001
            pass
    return result


def restore(cfg: dict | None = None, engine=None) -> dict:
    """Quita la configuración de VELA y reinicia resolved. No toca otras configuraciones."""
    cfg = cfg or config_mod.load()
    if not _consent(cfg):
        raise DnsFixError(_("activa [consent] allow_dns_changes = true para cambiar el DNS del sistema"))
    result = {"ok": False, "removed": []}
    for path in (DOT_FILE, DOH_FILE):
        if path.exists():
            try:
                backups = sorted(BACKUP_DIR.glob(f"{path.name}.*.bak")) if BACKUP_DIR.exists() else []
                if backups:
                    _write_root(path, backups[-1].read_text(encoding="utf-8"))
                    result["removed"].append(_("restaurado {path}", path=str(path)))
                else:
                    _priv(["rm", "-f", str(path)])
                    result["removed"].append(str(path))
            except Exception as e:  # noqa: BLE001
                result["error"] = str(e)
    try:
        run(["systemctl", "--user", "disable", "--now", "vela-cloudflared"])
        SERVICE.unlink(missing_ok=True)
        run(["systemctl", "--user", "daemon-reload"])
    except OSError:
        pass
    result["restart"] = _restart_resolved()
    result["status"] = status(cfg)
    result["ok"] = result["restart"]["ok"]
    if engine is not None:
        try:
            engine.store.audit(getattr(engine, "actor", "cli"), "dns_restore", {"ok": result["ok"]})
        except Exception:  # noqa: BLE001
            pass
    return result
