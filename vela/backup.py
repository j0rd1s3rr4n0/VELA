"""Exportación, importación y borrado de datos de VELA.

Tres operaciones con la misma regla: nada se hace a medias. El backup se escribe primero en un
temporal con permisos 0600 y se renombra al final; la importación valida el manifiesto y los
tipos antes de tocar la base; el reset pide confirmación y puede conservar una copia previa.

Formato:
  * `.json` — un único documento con manifiesto, historial y, si se eligen, configuración,
    ajustes y secretos.
  * `.zip`  — las mismas partes como entradas separadas.

El historial sale de `report.export_data`, que ya redacta credenciales. Los ficheros de
configuración y secretos solo se incluyen si el usuario los marca expresamente.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import tempfile
import zipfile
from pathlib import Path

from . import config as config_mod
from . import __version__
from .util import now, private_dir, tilde, xdg_dir

MANIFEST = "manifest.json"
HISTORY = "history.json"
CONFIG = "config.toml"
SETTINGS = "app-settings.toml"
SECRETS = "secrets.toml"
MAX_BYTES = 256 * 1024 * 1024


def secrets_path() -> Path:
    return xdg_dir("config") / "secrets.toml"


def default_include() -> dict:
    return {"history": True, "config": False, "settings": False, "secrets": False}


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _write_private(path: Path, text: str) -> None:
    private_dir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".vela-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def info(engine) -> dict:
    st = engine.store
    return {
        "database": tilde(st.path),
        "config": tilde(config_mod.config_path()),
        "settings": tilde(config_mod.settings_path()),
        "secrets": tilde(secrets_path()),
        "exists": {"config": config_mod.config_path().exists(), "settings": config_mod.settings_path().exists(),
                   "secrets": secrets_path().exists()},
        "rows": {k: st.count(k) for k in ("sessions", "events", "findings", "rotations", "metrics")},
        "storage": {"encrypted": getattr(st, "encrypted", False), "memory": getattr(st, "memory", False)},
    }


def export_bundle(engine, dest: str | Path, include: dict | None = None) -> dict:
    """Escribe un backup y devuelve un resumen. `include`: history/config/settings/secrets."""
    include = {**default_include(), **(include or {})}
    path = Path(dest).expanduser()
    if path.suffix.lower() not in (".json", ".zip", ".velabackup"):
        path = path.with_suffix(".json")
    private_dir(path.parent)
    from .report import export_data
    history = export_data(engine) if include.get("history", True) else None
    parts: dict[str, str] = {}
    if include.get("config") and config_mod.config_path().exists():
        parts[CONFIG] = _read(config_mod.config_path()) or ""
    if include.get("settings") and config_mod.settings_path().exists():
        parts[SETTINGS] = _read(config_mod.settings_path()) or ""
    if include.get("secrets") and secrets_path().exists():
        parts[SECRETS] = _read(secrets_path()) or ""
    manifest = {
        "app": "VELA", "version": __version__, "created": now(),
        "include": include,
        "counts": {k: len(v or []) for k, v in (history or {}).items() if isinstance(v, list)},
        "parts": sorted(parts),
        "note": _("Puede contener datos personales y claves. Guárdalo en un lugar seguro."),
    }
    if path.suffix.lower() == ".json" or path.suffix.lower() == ".velabackup":
        doc = {"manifest": manifest, "history": history, **parts}
        _write_private(path, json.dumps(doc, ensure_ascii=False, indent=2, default=str))
    else:
        fd, tmp = tempfile.mkstemp(prefix=".vela-", suffix=".zip", dir=str(path.parent))
        os.close(fd)
        try:
            with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr(MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=2))
                if history is not None:
                    z.writestr(HISTORY, json.dumps(history, ensure_ascii=False, indent=2, default=str))
                for name, text in parts.items():
                    z.writestr(name, text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    return {"ok": True, "path": str(path), "size": path.stat().st_size, "manifest": manifest}


def _load(path: Path) -> dict:
    if path.stat().st_size > MAX_BYTES:
        raise ValueError(_("el backup es demasiado grande (máximo {n} MB)", n=MAX_BYTES // (1024 * 1024)))
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            names = set(z.namelist())
            if MANIFEST not in names:
                raise ValueError(_("el ZIP no tiene manifiesto de VELA"))
            manifest = json.loads(z.read(MANIFEST))
            doc = {"manifest": manifest}
            if HISTORY in names:
                doc["history"] = json.loads(z.read(HISTORY))
            for name in (CONFIG, SETTINGS, SECRETS):
                if name in names:
                    doc[name] = z.read(name).decode("utf-8", errors="replace")
            return doc
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or "manifest" not in doc:
        raise ValueError(_("el fichero no es un backup de VELA"))
    return doc


def inspect_bundle(path: str | Path) -> dict:
    p = Path(path).expanduser()
    if not p.exists():
        raise FileNotFoundError(str(p))
    doc = _load(p)
    m = doc.get("manifest") or {}
    if m.get("app") != "VELA":
        raise ValueError(_("el backup pertenece a otra aplicación"))
    return {"path": str(p), "size": p.stat().st_size, "manifest": m,
            "parts": sorted(k for k in doc if k != "manifest"),
            "has": {"history": "history" in doc, "config": CONFIG in doc, "settings": SETTINGS in doc,
                    "secrets": SECRETS in doc}}


def _merge_settings(text: str) -> dict:
    import tomllib
    overlay = config_mod.load_overlay()
    incoming = tomllib.loads(text)
    for section, values in incoming.items():
        if not isinstance(values, dict):
            continue
        target = overlay.setdefault(section, {})
        for k, v in values.items():
            if isinstance(v, dict) and isinstance(target.get(k), dict):
                target[k].update(v)
            else:
                target[k] = v
    config_mod.save_overlay(overlay)
    return {"settings": tilde(config_mod.settings_path())}


def import_bundle(engine, path: str | Path, mode: str = "merge", include: dict | None = None) -> dict:
    """Importa un backup. `mode`: merge (historial y ajustes) o replace (borra el historial antes)."""
    p = Path(path).expanduser()
    doc = _load(p)
    m = doc.get("manifest") or {}
    if m.get("app") != "VELA":
        raise ValueError(_("el backup pertenece a otra aplicación"))
    include = {**default_include(), **(include or {})}
    notes = []
    result = {"ok": True, "mode": mode, "path": str(p), "restart_required": False}
    if include.get("history", True) and isinstance(doc.get("history"), dict):
        result["history"] = engine.store.import_data(doc["history"], mode=mode)
    else:
        notes.append(_("el backup no trae historial"))
    if include.get("settings") and doc.get(SETTINGS):
        try:
            result["settings"] = _merge_settings(doc[SETTINGS])
        except (ValueError, OSError) as e:
            notes.append(_("ajustes no importados: {e}", e=e))
    if include.get("config") and doc.get(CONFIG):
        try:
            config_mod.save_text(doc[CONFIG])
            result["config"] = tilde(config_mod.config_path())
            result["restart_required"] = True
        except (ValueError, OSError) as e:
            notes.append(_("configuración no importada: {e}", e=e))
    if include.get("secrets") and doc.get(SECRETS):
        _write_private(secrets_path(), doc[SECRETS])
        result["secrets"] = tilde(secrets_path())
        result["restart_required"] = True
    result["notes"] = notes
    try:
        engine.store.audit(getattr(engine, "actor", "cli"), "data_import", {"path": str(p), "mode": mode,
                                                                           "include": include})
    except Exception:  # noqa: BLE001
        pass
    return result


def reset(engine, scope: str = "history", keep_backup: bool = False, backup_path: str | None = None) -> dict:
    """Borra datos. scope: history (historial) o all (todo lo de VELA, salvo el código).

    No borra el repositorio ni el mapa base. Devuelve `restart_required` cuando elimina
    configuración que el proceso en marcha tiene cargada.
    """
    if scope not in ("history", "all"):
        raise ValueError(_("alcance de borrado no válido: {scope}", scope=scope))
    result = {"ok": True, "scope": scope, "backup": None, "restart_required": scope == "all"}
    if keep_backup:
        dest = Path(backup_path).expanduser() if backup_path else xdg_dir("data") / f"vela-backup-{int(now())}.json"
        result["backup"] = export_bundle(engine, dest, {**default_include(), "config": True, "settings": True,
                                                        "secrets": True})
    result["deleted"] = engine.store.reset(everything=(scope == "all"))
    if scope == "all":
        removed = []
        for path in (config_mod.config_path(), config_mod.settings_path(), secrets_path(),
                     xdg_dir("config") / "app-state.json"):
            try:
                path.unlink(missing_ok=True)
                removed.append(tilde(path))
            except OSError:
                pass
        cache_dir = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "vela"
        for d in (xdg_dir("data") / "map", cache_dir):
            try:
                import shutil
                shutil.rmtree(d)
                removed.append(tilde(d))
            except OSError:
                pass
        result["removed"] = removed
    try:
        engine.store.audit(getattr(engine, "actor", "cli"), "data_reset", {"scope": scope,
                                                                           "backup": bool(result["backup"])})
    except Exception:  # noqa: BLE001
        pass
    return result
