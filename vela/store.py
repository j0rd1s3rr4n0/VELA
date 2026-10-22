"""Persistencia SQLite (stdlib).

La base NO está cifrada salvo que se use SQLCipher (no disponible por defecto): se protege con
permisos 0600 en un directorio 0700. Con storage.mode = "memory" no se escribe nada en disco.

Modelo:
  sessions  – topología de salida durante un intervalo (ver sessions.py para cuándo se abre una nueva).
  intervals – cada elemento observado (IP pública, servidor VPN, proxy, nodo/circuito Tor, país, ASN,
              perfil, combinación) con inicio/fin → de aquí salen todos los contadores de tiempo.
  events    – cambios y sucesos con severidad.
  findings  – diagnósticos (evidencia, método, limitaciones, confianza, recomendación).
  rotations – intentos de rotación y su resultado.
  audit     – cambios de configuración y acciones del usuario.
"""

from __future__ import annotations

from .i18n import _

import json
import os
import sqlite3
import threading
import uuid
from pathlib import Path

from .util import now, private_dir, redact, xdg_dir

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY, profile TEXT, started REAL NOT NULL, ended REAL, status TEXT,
  fingerprint TEXT, chain TEXT, egress_iface TEXT, local_ip TEXT, wan_ip TEXT, public_ip TEXT,
  vpn TEXT, proxy TEXT, tor_exit TEXT, country TEXT, asn TEXT, dns TEXT, end_reason TEXT
);
CREATE TABLE IF NOT EXISTS intervals (
  id INTEGER PRIMARY KEY, session_id TEXT, profile TEXT, layer TEXT NOT NULL, key TEXT NOT NULL,
  label TEXT, country TEXT, asn TEXT, lat REAL, lon REAL, started REAL NOT NULL, ended REAL, meta TEXT
);
CREATE INDEX IF NOT EXISTS ix_int_layer ON intervals(layer, key);
CREATE INDEX IF NOT EXISTS ix_int_open ON intervals(ended);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, session_id TEXT, profile TEXT, kind TEXT, severity TEXT, data TEXT
);
CREATE INDEX IF NOT EXISTS ix_ev_ts ON events(ts);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, check_id TEXT, title TEXT, severity TEXT, status TEXT,
  mode TEXT, method TEXT, evidence TEXT, observed TEXT, limitations TEXT, confidence TEXT,
  recommendation TEXT, profile TEXT
);
CREATE TABLE IF NOT EXISTS rotations (
  id INTEGER PRIMARY KEY, ts REAL NOT NULL, layer TEXT, adapter TEXT, dry_run INTEGER,
  from_target TEXT, to_target TEXT, result TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts REAL NOT NULL, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS metrics (id INTEGER PRIMARY KEY, ts REAL NOT NULL, key TEXT NOT NULL,
  value REAL, meta TEXT);
CREATE INDEX IF NOT EXISTS ix_metrics_key_ts ON metrics(key, ts);
"""


def default_path() -> Path:
    return xdg_dir("data") / "vela.db"


class Store:
    def __init__(self, path: str | Path | None = None, memory: bool = False):
        self.memory = memory
        if memory:
            self.path = ":memory:"
        else:
            p = Path(path) if path else default_path()
            private_dir(p.parent)
            if not p.exists():
                fd = os.open(p, os.O_WRONLY | os.O_CREAT, 0o600)
                os.close(fd)
            os.chmod(p, 0o600)
            self.path = str(p)
        self.db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            if not memory:
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA secure_delete=ON")
            self.db.executescript(SCHEMA)
        self.encrypted = False

    def close(self):
        with self.lock:
            self.db.close()

    def _x(self, sql: str, args=()):
        with self.lock:
            return self.db.execute(sql, args)

    def _rows(self, sql: str, args=()) -> list[dict]:
        with self.lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    def count(self, table: str) -> int:
        if table not in ("sessions", "intervals", "events", "findings", "rotations", "metrics", "audit"):
            raise ValueError(table)
        with self.lock:
            return int(self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    # ── kv ──
    def get(self, key: str, default=None):
        r = self._rows("SELECT value FROM kv WHERE key=?", (key,))
        return json.loads(r[0]["value"]) if r else default

    def put(self, key: str, value):
        self._x("INSERT INTO kv(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, default=str)))

    # ── sesiones ──
    def open_session(self, profile: str, fp: str, fields: dict, ts: float | None = None) -> str:
        sid = uuid.uuid4().hex[:12]
        self._x("""INSERT INTO sessions(id,profile,started,status,fingerprint,chain,egress_iface,local_ip,wan_ip,
                   public_ip,vpn,proxy,tor_exit,country,asn,dns) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (sid, profile, ts or now(), "active", fp, json.dumps(fields.get("chain", [])),
                 fields.get("egress_iface"), fields.get("local_ip"), fields.get("wan_ip"), fields.get("public_ip"),
                 fields.get("vpn"), fields.get("proxy"), fields.get("tor_exit"), fields.get("country"),
                 fields.get("asn"), json.dumps(fields.get("dns", []))))
        return sid

    def update_session(self, sid: str, **fields):
        allowed = {"status", "chain", "wan_ip", "public_ip", "tor_exit", "country", "asn", "dns", "local_ip"}
        sets, args = [], []
        for k, v in fields.items():
            if k in allowed:
                sets.append(f"{k}=?")
                args.append(json.dumps(v) if isinstance(v, (list, dict)) else v)
        if sets:
            self._x(f"UPDATE sessions SET {','.join(sets)} WHERE id=?", (*args, sid))

    def close_session(self, sid: str, reason: str, ts: float | None = None):
        ts = ts or now()
        self._x("UPDATE sessions SET ended=?, status='closed', end_reason=? WHERE id=? AND ended IS NULL",
                (ts, reason, sid))
        self._x("UPDATE intervals SET ended=? WHERE session_id=? AND ended IS NULL", (ts, sid))

    def sessions(self, limit: int = 50, since: float | None = None, profile: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM sessions WHERE 1=1", []
        if since:
            q += " AND COALESCE(ended, ?) >= ?"
            args += [now(), since]
        if profile:
            q += " AND profile=?"
            args.append(profile)
        q += " ORDER BY started DESC LIMIT ?"
        args.append(limit)
        rows = self._rows(q, args)
        t = now()
        for r in rows:
            r["chain"] = json.loads(r["chain"] or "[]")
            r["dns"] = json.loads(r["dns"] or "[]")
            r["duration"] = (r["ended"] or t) - r["started"]
        return rows

    def open_sessions(self) -> list[dict]:
        return [s for s in self.sessions(limit=10) if s["ended"] is None]

    # ── intervalos / contadores ──
    def open_interval(self, sid: str | None, profile: str, layer: str, key: str, label: str | None = None,
                      geo: dict | None = None, meta: dict | None = None, ts: float | None = None) -> int:
        geo = geo or {}
        cur = self._x("""INSERT INTO intervals(session_id,profile,layer,key,label,country,asn,lat,lon,started,meta)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                      (sid, profile, layer, key, label or key, geo.get("country"),
                       str(geo["asn"]) if geo.get("asn") else None, geo.get("lat"), geo.get("lon"),
                       ts or now(), json.dumps(redact(meta or {}), default=str)))
        return cur.lastrowid

    def close_interval(self, iid: int, ts: float | None = None):
        self._x("UPDATE intervals SET ended=? WHERE id=? AND ended IS NULL", (ts or now(), iid))

    def open_intervals(self) -> list[dict]:
        return self._rows("SELECT * FROM intervals WHERE ended IS NULL")

    def intervals(self, layer: str | None = None, since: float | None = None, until: float | None = None,
                  profile: str | None = None, limit: int = 5000) -> list[dict]:
        q, args = "SELECT * FROM intervals WHERE 1=1", []
        if layer:
            q += " AND layer=?"
            args.append(layer)
        if since:
            q += " AND COALESCE(ended, ?) >= ?"
            args += [now(), since]
        if until:
            q += " AND started <= ?"
            args.append(until)
        if profile:
            q += " AND profile=?"
            args.append(profile)
        q += " ORDER BY started DESC LIMIT ?"
        args.append(limit)
        return self._rows(q, args)

    def counters(self, layer: str | None = None, since: float | None = None, profile: str | None = None) -> list[dict]:
        t = now()
        q = """SELECT layer, key, MAX(label) AS label, MAX(country) AS country, MAX(asn) AS asn,
                      MAX(lat) AS lat, MAX(lon) AS lon, COUNT(*) AS uses,
                      SUM(COALESCE(ended, :t) - MAX(started, :since)) AS total,
                      MIN(started) AS first_seen, MAX(COALESCE(ended, :t)) AS last_seen,
                      SUM(ended IS NULL) AS active,
                      MAX(CASE WHEN ended IS NULL THEN :t - started END) AS current
               FROM intervals WHERE COALESCE(ended, :t) >= :since"""
        args = {"t": t, "since": since or 0}
        if layer:
            q += " AND layer = :layer"
            args["layer"] = layer
        if profile:
            q += " AND profile = :profile"
            args["profile"] = profile
        q += " GROUP BY layer, key ORDER BY active DESC, total DESC"
        return self._rows(q, args)

    # ── eventos / hallazgos / rotaciones / auditoría ──
    def add_event(self, kind: str, severity: str = "info", data: dict | None = None,
                  session_id: str | None = None, profile: str | None = None, ts: float | None = None) -> dict:
        ts = ts or now()
        data = redact(data or {})
        cur = self._x("INSERT INTO events(ts,session_id,profile,kind,severity,data) VALUES(?,?,?,?,?,?)",
                      (ts, session_id, profile, kind, severity, json.dumps(data, default=str)))
        return {"id": cur.lastrowid, "ts": ts, "session_id": session_id, "profile": profile,
                "kind": kind, "severity": severity, "data": data}

    def events(self, limit: int = 100, since: float | None = None, kinds: list[str] | None = None,
               min_severity: str | None = None, session_id: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM events WHERE 1=1", []
        if since:
            q += " AND ts >= ?"
            args.append(since)
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += kinds
        if min_severity:
            levels = SEVERITIES[SEVERITIES.index(min_severity):]
            q += f" AND severity IN ({','.join('?' * len(levels))})"
            args += levels
        if session_id:
            q += " AND session_id=?"
            args.append(session_id)
        q += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit)
        rows = self._rows(q, args)
        for r in rows:
            r["data"] = json.loads(r["data"] or "{}")
        return rows

    def add_finding(self, f: dict, profile: str | None = None) -> int:
        cur = self._x("""INSERT INTO findings(ts,check_id,title,severity,status,mode,method,evidence,observed,
                         limitations,confidence,recommendation,profile) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (f.get("ts") or now(), f["check"], f["title"], f["severity"], f["status"], f["mode"],
                       f["method"], json.dumps(redact(f.get("evidence")), default=str), f.get("observed"),
                       f.get("limitations"), f.get("confidence"), f.get("recommendation"), profile))
        return cur.lastrowid

    def findings(self, limit: int = 100, since: float | None = None) -> list[dict]:
        q, args = "SELECT * FROM findings", []
        if since:
            q += " WHERE ts >= ?"
            args.append(since)
        rows = self._rows(q + " ORDER BY ts DESC LIMIT ?", (*args, limit))
        for r in rows:
            r["evidence"] = json.loads(r["evidence"] or "null")
        return rows

    def add_rotation(self, layer: str, adapter: str, dry_run: bool, from_t, to_t, result: str, detail) -> int:
        cur = self._x("""INSERT INTO rotations(ts,layer,adapter,dry_run,from_target,to_target,result,detail)
                         VALUES(?,?,?,?,?,?,?,?)""",
                      (now(), layer, adapter, int(dry_run), from_t, to_t, result,
                       json.dumps(redact(detail), default=str)))
        return cur.lastrowid

    def rotations(self, limit: int = 100, layer: str | None = None, since: float | None = None) -> list[dict]:
        q, args = "SELECT * FROM rotations WHERE 1=1", []
        if layer:
            q += " AND layer=?"
            args.append(layer)
        if since:
            q += " AND ts >= ?"
            args.append(since)
        rows = self._rows(q + " ORDER BY ts DESC LIMIT ?", (*args, limit))
        for r in rows:
            r["detail"] = json.loads(r["detail"] or "null")
        return rows

    def audit(self, actor: str, action: str, detail=None):
        detail = redact(detail)
        self._x("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
                (now(), actor, action, json.dumps(detail, default=str)))
        if not self.memory and os.environ.get("VELA_NO_AUDIT_FILE") != "1":
            try:
                from . import logs
                logs.audit(actor, action, detail)
            except Exception:  # noqa: BLE001 — la auditoría no debe romper la acción
                pass

    def audit_log(self, limit: int = 100) -> list[dict]:
        return self._rows("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,))

    def clear_audit(self) -> int:
        with self.lock:
            return self.db.execute("DELETE FROM audit").rowcount

    # ── métricas (línea base de anomalías) ──
    def add_metric(self, key: str, value: float | None, meta: dict | None = None, ts: float | None = None) -> int:
        cur = self._x("INSERT INTO metrics(ts,key,value,meta) VALUES(?,?,?,?)",
                      (ts or now(), key, value, json.dumps(redact(meta or {}), default=str)))
        return cur.lastrowid

    def metrics(self, key: str | None = None, since: float | None = None, limit: int = 10000) -> list[dict]:
        q, args = "SELECT * FROM metrics WHERE 1=1", []
        if key:
            q += " AND key=?"
            args.append(key)
        if since:
            q += " AND ts >= ?"
            args.append(since)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(limit)
        rows = self._rows(q, args)
        for r in rows:
            r["meta"] = json.loads(r["meta"] or "{}")
        return rows

    def latest_metric(self, key: str) -> dict | None:
        rows = self.metrics(key=key, limit=1)
        return rows[0] if rows else None

    def prune_metrics(self, before: float) -> int:
        with self.lock:
            return self.db.execute("DELETE FROM metrics WHERE ts < ?", (before,)).rowcount

    # ── importación / borrado ──
    def reset(self, everything: bool = False) -> dict:
        """Borra el histórico. Con `everything` también ajustes en kv y métricas."""
        tables = ["sessions", "intervals", "events", "findings", "rotations", "audit", "metrics"]
        if everything:
            tables += ["kv"]
        counts = {}
        with self.lock:
            for table in tables:
                counts[table] = self.db.execute(f"DELETE FROM {table}").rowcount
            if not self.memory:
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.db.execute("VACUUM")
        return counts

    def import_data(self, data: dict, mode: str = "merge") -> dict:
        """Importa un export de `report.export_data`. `mode`: merge (omite ids repetidos) o replace."""
        if mode not in ("merge", "replace"):
            raise ValueError(_("modo de importación no válido: {mode}", mode=mode))
        if mode == "replace":
            self.reset(everything=False)
        counts = {k: 0 for k in ("sessions", "intervals", "events", "findings", "rotations", "metrics")}

        def j(v):
            return json.dumps(v, default=str) if isinstance(v, (dict, list)) else v

        with self.lock:
            for s in data.get("sessions") or []:
                try:
                    cur = self.db.execute(
                        """INSERT OR IGNORE INTO sessions(id,profile,started,ended,status,fingerprint,chain,
                           egress_iface,local_ip,wan_ip,public_ip,vpn,proxy,tor_exit,country,asn,dns,end_reason)
                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (s.get("id"), s.get("profile"), s.get("started"), s.get("ended"), s.get("status"),
                         s.get("fingerprint"), j(s.get("chain") or []), s.get("egress_iface"), s.get("local_ip"),
                         s.get("wan_ip"), s.get("public_ip"), s.get("vpn"), s.get("proxy"), s.get("tor_exit"),
                         s.get("country"), s.get("asn"), j(s.get("dns") or []), s.get("end_reason")))
                    counts["sessions"] += cur.rowcount
                except sqlite3.Error:
                    continue
            for i in data.get("intervals") or []:
                try:
                    cur = self.db.execute(
                        """INSERT INTO intervals(session_id,profile,layer,key,label,country,asn,lat,lon,started,
                           ended,meta) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (i.get("session_id"), i.get("profile"), i.get("layer"), i.get("key"), i.get("label"),
                         i.get("country"), i.get("asn"), i.get("lat"), i.get("lon"), i.get("started"),
                         i.get("ended"), j(i.get("meta") or {})))
                    counts["intervals"] += cur.rowcount
                except sqlite3.Error:
                    continue
            for e in data.get("events") or []:
                try:
                    cur = self.db.execute(
                        "INSERT INTO events(ts,session_id,profile,kind,severity,data) VALUES(?,?,?,?,?,?)",
                        (e.get("ts"), e.get("session_id"), e.get("profile"), e.get("kind"),
                         e.get("severity") or "info", j(e.get("data") or {})))
                    counts["events"] += cur.rowcount
                except sqlite3.Error:
                    continue
            for f in data.get("findings") or []:
                try:
                    cur = self.db.execute(
                        """INSERT INTO findings(ts,check_id,title,severity,status,mode,method,evidence,observed,
                           limitations,confidence,recommendation,profile) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (f.get("ts"), f.get("check_id"), f.get("title"), f.get("severity"), f.get("status"),
                         f.get("mode"), f.get("method"), j(f.get("evidence")), f.get("observed"),
                         f.get("limitations"), f.get("confidence"), f.get("recommendation"), f.get("profile")))
                    counts["findings"] += cur.rowcount
                except sqlite3.Error:
                    continue
            for r in data.get("rotations") or []:
                try:
                    cur = self.db.execute(
                        """INSERT INTO rotations(ts,layer,adapter,dry_run,from_target,to_target,result,detail)
                           VALUES(?,?,?,?,?,?,?,?)""",
                        (r.get("ts"), r.get("layer"), r.get("adapter"), int(bool(r.get("dry_run"))),
                         r.get("from_target"), r.get("to_target"), r.get("result"), j(r.get("detail"))))
                    counts["rotations"] += cur.rowcount
                except sqlite3.Error:
                    continue
            for m in data.get("metrics") or []:
                try:
                    cur = self.db.execute("INSERT INTO metrics(ts,key,value,meta) VALUES(?,?,?,?)",
                                          (m.get("ts"), m.get("key"), m.get("value"), j(m.get("meta") or {})))
                    counts["metrics"] += cur.rowcount
                except sqlite3.Error:
                    continue
            if not self.memory:
                self.db.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return {"mode": mode, "imported": counts}

    # ── retención ──
    def purge(self, before: float) -> dict:
        """Borra el histórico anterior a `before` (secure_delete activo sobrescribe las páginas)."""
        counts = {}
        with self.lock:
            for table, col in (("events", "ts"), ("findings", "ts"), ("rotations", "ts"), ("metrics", "ts")):
                counts[table] = self.db.execute(f"DELETE FROM {table} WHERE {col} < ?", (before,)).rowcount
            counts["intervals"] = self.db.execute(
                "DELETE FROM intervals WHERE ended IS NOT NULL AND ended < ?", (before,)).rowcount
            counts["sessions"] = self.db.execute(
                "DELETE FROM sessions WHERE ended IS NOT NULL AND ended < ?", (before,)).rowcount
            if not self.memory:
                self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.db.execute("VACUUM")
        return counts


SEVERITIES = ["info", "low", "warning", "medium", "high", "critical"]
