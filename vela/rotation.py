"""Rotation Policy Engine.

Ciclo de rotación segura (cada paso queda registrado):
  1. Hay un destino alternativo válido (no repetición, cooldown, exclusiones).
  2. El adaptador soporta la rotación y hay consentimiento (consent.allow_rotation_changes).
  3. Hay protección contra fugas disponible si la política la exige.
  4. Se bloquea el tráfico (kill-switch) si está configurado y es compatible.
  5. Se rota.
  6. Se verifica conectividad / identidad de salida.
  7. Se valida contra la política (país, ASN, repetición del exit).
  8. Se registra y se libera el tráfico. Si algo falla: rollback; si el rollback falla, el tráfico
     queda bloqueado (fail-closed) y se genera una alerta crítica. Nunca se deja tráfico
     desprotegido en silencio.
"""

from __future__ import annotations

from .i18n import _

import random
import re
import secrets
import time
from dataclasses import dataclass, field

from .util import now, parse_duration, run

_rng = secrets.SystemRandom()


@dataclass
class Target:
    id: str
    label: str = ""
    country: str | None = None
    asn: str | None = None
    meta: dict = field(default_factory=dict)

    def as_dict(self):
        return {"id": self.id, "label": self.label or self.id, "country": self.country, "asn": self.asn}


@dataclass
class Policy:
    enabled: bool = False
    max_ttl: float = 2700
    min_ttl: float = 300
    jitter: float = 600
    no_repeat: int = 3
    cooldown: float = 7200
    max_per_hour: int = 2
    exclude: list = field(default_factory=list)
    exclude_countries: list = field(default_factory=list)
    exclude_asn: list = field(default_factory=list)
    repeat_scope: str = "target"      # target | exit_ip | exit | combination
    require_killswitch: bool = False
    retries_on_repeat: int = 0

    @classmethod
    def from_cfg(cls, c: dict) -> "Policy":
        return cls(
            enabled=bool(c.get("enabled")), max_ttl=parse_duration(c.get("max_ttl", "45m")),
            min_ttl=parse_duration(c.get("min_ttl", "5m")), jitter=parse_duration(c.get("jitter", "0")),
            no_repeat=int(c.get("no_repeat", 3)), cooldown=parse_duration(c.get("cooldown", "0")),
            max_per_hour=int(c.get("max_per_hour", 4)), exclude=list(c.get("exclude", [])),
            exclude_countries=[x.upper() for x in c.get("exclude_countries", [])],
            exclude_asn=[str(x).upper().removeprefix("AS") for x in c.get("exclude_asn", [])],
            repeat_scope=c.get("repeat_scope", "target"), require_killswitch=bool(c.get("require_killswitch")),
            retries_on_repeat=int(c.get("retries_on_repeat", 0)),
        )

    def ttl(self, rng: random.Random = _rng) -> float:
        """Duración variable dentro de [max(min_ttl, max_ttl - jitter), max_ttl]."""
        low = max(self.min_ttl, self.max_ttl - self.jitter)
        return rng.uniform(low, self.max_ttl) if self.max_ttl > low else self.max_ttl


def norm_asn(x) -> str:
    return str(x).strip().upper().removeprefix("AS")


def history_key(entry: dict, scope: str) -> str | None:
    return {"target": entry.get("target"), "exit_ip": entry.get("exit_ip"), "exit": entry.get("exit"),
            "combination": entry.get("combination")}.get(scope) or entry.get("target")


def choose(candidates: list[Target], history: list[dict], policy: Policy, current: str | None = None,
           ts: float | None = None, rng: random.Random = _rng) -> tuple[Target | None, dict]:
    """Elige destino. `history`: [{target, ts, exit_ip, exit, combination}] del más reciente al más antiguo.
    Devuelve (destino o None, motivos de descarte por destino)."""
    ts = ts or now()
    rejected: dict[str, str] = {}
    recent_keys = []
    for h in history:
        k = history_key(h, "target")
        if k not in recent_keys:
            recent_keys.append(k)
    recent = set(recent_keys[:policy.no_repeat])
    last_use = {}
    for h in history:
        last_use.setdefault(h.get("target"), h["ts"])

    pool = []
    for c in candidates:
        if c.id == current:
            rejected[c.id] = _("destino actual")
        elif c.id in policy.exclude or c.label in policy.exclude:
            rejected[c.id] = "excluido"
        elif c.country and c.country.upper() in policy.exclude_countries:
            rejected[c.id] = _("país excluido ({country})", country=c.country)
        elif c.id in recent:
            rejected[c.id] = _("usado en los últimos {no_repeat}", no_repeat=policy.no_repeat)
        elif c.id in last_use and ts - last_use[c.id] < policy.cooldown:
            rejected[c.id] = _("cooldown ({v1}s restantes)", v1=int(policy.cooldown - (ts - last_use[c.id])))
        else:
            pool.append(c)
    # ASN: solo se excluye si quedan alternativas verificadas (con ASN conocido y no excluido)
    if policy.exclude_asn:
        excluded = {norm_asn(x) for x in policy.exclude_asn}
        ok_asn = [c for c in pool if c.asn and norm_asn(c.asn) not in excluded]
        if ok_asn:
            for c in pool:
                if c not in ok_asn:
                    rejected[c.id] = _("ASN excluido o desconocido")
            pool = ok_asn
    if not pool:
        return None, rejected
    # LRU ponderado: los no usados nunca o hace más tiempo pesan más
    weights = [1 + min(ts - last_use[c.id], 86400) / 600 if c.id in last_use else 200 for c in pool]
    return rng.choices(pool, weights=weights, k=1)[0], rejected


# ── adaptadores ─────────────────────────────────────────────────────────────

class RotationError(Exception):
    pass


class Adapter:
    layer = "?"
    name = "?"
    supports_rotation = True
    reversible = True
    needs_killswitch = False

    def available(self) -> tuple[bool, str]:
        return True, ""

    def targets(self) -> list[Target]:
        return []

    def current(self) -> Target | None:
        return None

    def switch(self, target: Target):
        raise NotImplementedError

    def verify(self, target: Target, timeout: float = 30) -> dict:
        return {"ok": True, "observed": {"target": target.id}}

    def rollback(self, previous: Target | None):
        if previous:
            self.switch(previous)

    def endpoints(self, target: Target) -> list[str]:
        """Destinos (ip:puerto) que el kill-switch debe permitir durante el cambio."""
        return []


class SimulatedAdapter(Adapter):
    """Backend simulado para pruebas: no toca el sistema."""

    def __init__(self, layer="sim", targets=None, fail_switch=None, fail_verify=None, fail_rollback=False,
                 exits=None):
        self.layer, self.name = layer, f"sim-{layer}"
        self._targets = [t if isinstance(t, Target) else Target(t, t) for t in (targets or [])]
        self.cur: Target | None = self._targets[0] if self._targets else None
        self.fail_switch = set(fail_switch or [])
        self.fail_verify = set(fail_verify or [])
        self.fail_rollback = fail_rollback
        self.exits = exits or {}
        self.calls: list[tuple] = []

    def targets(self):
        return list(self._targets)

    def current(self):
        return self.cur

    def switch(self, target):
        self.calls.append(("switch", target.id))
        if target.id in self.fail_switch:
            raise RotationError(_("fallo simulado al cambiar a {id}", id=target.id))
        self.cur = target

    def verify(self, target, timeout=30):
        self.calls.append(("verify", target.id))
        if target.id in self.fail_verify:
            return {"ok": False, "error": _("verificación simulada fallida")}
        return {"ok": True, "observed": {"target": target.id, "exit_ip": self.exits.get(target.id),
                                         "country": target.country}}

    def rollback(self, previous):
        self.calls.append(("rollback", previous.id if previous else None))
        if self.fail_rollback:
            raise RotationError(_("fallo simulado de rollback"))
        self.cur = previous


class TorAdapter(Adapter):
    """NEWNYM. No elige exits (eso exigiría ExitNodes y empeora el anonimato); la no repetición se
    aplica al exit observado tras la rotación, reintentando dentro del rate-limit de Tor."""
    layer, name = "tor", "tor-newnym"
    reversible = False

    def __init__(self, observer):
        self.obs = observer

    def available(self):
        st = self.obs.status()
        if not st.get("available"):
            return False, st.get("error", _("Tor no disponible"))
        if st.get("observe_only"):
            return False, _("Tor Browser: solo observación (usa 'Nueva identidad' en el navegador)")
        return True, ""

    def current(self):
        st = self.obs.status()
        ex = st.get("exit") if st.get("available") else None
        return Target(ex["fp"], f"{ex.get('nick')} {ex.get('ip')}", ex.get("country"), ex.get("asn"),
                      {"ip": ex.get("ip")}) if ex else None

    def targets(self):
        return [Target("newnym", _("circuitos nuevos (Tor elige el exit)"))]

    def switch(self, target):
        res = self.obs.newnym()
        if not res.get("ok"):
            if res.get("retry_in"):
                time.sleep(res["retry_in"] + 0.5)
                res = self.obs.newnym()
            if not res.get("ok"):
                raise RotationError(res.get("error"))

    def verify(self, target, timeout=20):
        deadline = time.monotonic() + timeout
        st = {}
        while time.monotonic() < deadline:
            st = self.obs.status()
            if st.get("available") and st.get("circuit_established") and st.get("exit"):
                ex = st["exit"]
                return {"ok": True, "observed": {"exit": ex["fp"], "exit_ip": ex.get("ip"),
                                                 "country": ex.get("country"), "asn": ex.get("asn"),
                                                 "note": _("exit del circuito más reciente; el que use cada "
                                                         "aplicación lo decide Tor al abrir streams")}}
            time.sleep(1)
        return {"ok": False, "error": st.get("error") or _("sin circuito establecido tras NEWNYM")}

    def rollback(self, previous):
        return None  # NEWNYM no es reversible ni necesita serlo: no deja tráfico expuesto


class ProxyAdapter(Adapter):
    layer, name = "proxy", "local-forwarder"

    def __init__(self, forwarder, pool: list[str], geo=None):
        self.fw = forwarder
        self.pool = pool
        self.geo = geo

    def available(self):
        if not self.fw:
            return False, _("forwarder no iniciado")
        if len(self.pool) < 2:
            return False, _("hacen falta al menos 2 proxies en el pool")
        return True, ""

    def targets(self):
        out = []
        for url in self.pool:
            host = re.sub(r"^\w+://", "", url).rsplit(":", 1)[0]
            g = self.geo.lookup(host) if self.geo else {}
            out.append(Target(url, url, g.get("country"), str(g["asn"]) if g.get("asn") else None))
        return out

    def current(self):
        u = self.fw.upstream if self.fw else None
        return Target(u, u) if u else None

    def switch(self, target):
        self.fw.set_upstream(target.id)

    def verify(self, target, timeout=10):
        ok, err = self.fw.probe_upstream(target.id, timeout)
        return {"ok": ok, "error": err, "observed": {"target": target.id}}


class NetworkManagerAdapter(Adapter):
    layer, name = "vpn", "networkmanager"
    needs_killswitch = True

    def __init__(self, endpoints: dict | None = None):
        self._endpoints = endpoints or {}

    def _conns(self):
        code, out, _ign = run(["nmcli", "-t", "-f", "NAME,TYPE,ACTIVE", "connection", "show"])
        if code:
            return []
        rows = []
        for line in out.splitlines():
            f = [x.replace("\\:", ":") for x in re.split(r"(?<!\\):", line)]
            if len(f) >= 3 and f[1] in ("vpn", "wireguard"):
                rows.append({"name": f[0], "active": f[2] == "yes"})
        return rows

    def available(self):
        conns = self._conns()
        if len(conns) < 2:
            return False, _("NetworkManager tiene {n} conexiones VPN (hacen falta 2+)", n=len(conns))
        return True, ""

    def targets(self):
        return [Target(c["name"], c["name"]) for c in self._conns()]

    def current(self):
        act = [c for c in self._conns() if c["active"]]
        return Target(act[0]["name"], act[0]["name"]) if act else None

    def switch(self, target):
        cur = self.current()
        if cur:
            run(["nmcli", "connection", "down", "id", cur.id], timeout=30)
        code, _ign, err = run(["nmcli", "connection", "up", "id", target.id], timeout=90)
        if code:
            raise RotationError(_("nmcli up {id}: {v3}", id=target.id, v3=err.strip()))

    def verify(self, target, timeout=30):
        from . import network
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            snap = network.snapshot()
            if snap["via_tunnel"].get("ipv4"):
                return {"ok": True, "observed": {"target": target.id, "iface": snap["egress"]["ipv4"]["dev"]}}
            time.sleep(1)
        return {"ok": False, "error": _("la ruta por defecto no pasa por el túnel tras conectar")}

    def endpoints(self, target):
        return self._endpoints.get(target.id, [])


class WgQuickAdapter(Adapter):
    layer, name = "vpn", "wg-quick"
    needs_killswitch = True

    def __init__(self, confdir="/etc/wireguard"):
        self.confdir = confdir

    def targets(self):
        import os
        try:
            return [Target(f[:-5], f[:-5]) for f in sorted(os.listdir(self.confdir)) if f.endswith(".conf")]
        except OSError:
            return []

    def available(self):
        if len(self.targets()) < 2:
            return False, _("hacen falta 2+ configuraciones en /etc/wireguard (o permisos para leerlas)")
        code, _ign, _ign = run(["sudo", "-n", "true"])
        return (code == 0), ("" if code == 0 else _("wg-quick necesita sudo sin contraseña (sudo -n)"))

    def current(self):
        code, out, _ign = run(["sudo", "-n", "wg", "show", "interfaces"])
        names = out.split() if code == 0 else []
        return Target(names[0], names[0]) if names else None

    def switch(self, target):
        cur = self.current()
        if cur:
            run(["sudo", "-n", "wg-quick", "down", cur.id], timeout=30)
        code, _ign, err = run(["sudo", "-n", "wg-quick", "up", target.id], timeout=60)
        if code:
            raise RotationError(_("wg-quick up {id}: {v3}", id=target.id, v3=err.strip()[-300:]))

    def endpoints(self, target):
        code, out, _ign = run(["sudo", "-n", "cat", f"{self.confdir}/{target.id}.conf"])
        return re.findall(r"(?im)^\s*Endpoint\s*=\s*(\S+)", out) if code == 0 else []


class MullvadAdapter(Adapter):
    """El cliente de Mullvad tiene su propio kill-switch ('lockdown mode'), por eso no exige el nuestro."""
    layer, name = "vpn", "mullvad"

    def targets(self):
        code, out, _ign = run(["mullvad", "relay", "list"], timeout=10)
        out_t = []
        country = None
        for line in out.splitlines() if code == 0 else []:
            m = re.match(r"^\S.*\((\w{2})\)", line)
            if m:
                country = m.group(1).upper()
            m = re.match(r"^\s+(\S+-wg-\d+)\s+\(([\d.]+)", line)
            if m:
                out_t.append(Target(m.group(1), f"{m.group(1)} {m.group(2)}", country))
        return out_t

    def current(self):
        code, out, _ign = run(["mullvad", "status", "-v"], timeout=10)
        m = re.search(r"(\w{2}-\w{3}-wg-\d+)", out) if code == 0 else None
        return Target(m.group(1), m.group(1)) if m else None

    def switch(self, target):
        for cmd in (["mullvad", "relay", "set", "location", target.id], ["mullvad", "reconnect"]):
            code, _ign, err = run(cmd, timeout=30)
            if code:
                raise RotationError(f"{' '.join(cmd)}: {err.strip()}")

    def verify(self, target, timeout=40):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            code, out, _ign = run(["mullvad", "status"], timeout=10)
            if code == 0 and "Connected" in out:
                return {"ok": True, "observed": {"target": target.id, "status": out.strip().splitlines()[0]}}
            time.sleep(2)
        return {"ok": False, "error": _("mullvad no llegó a Connected")}


# ── motor ───────────────────────────────────────────────────────────────────

class RotationEngine:
    def __init__(self, store, cfg: dict, killswitch=None, emit=None):
        self.store = store
        self.cfg = cfg
        self.ks = killswitch
        self.emit = emit or (lambda *a, **k: None)
        self.adapters: dict[str, Adapter] = {}
        self.state: dict[str, dict] = {}       # layer -> {since, deadline, current}
        self.paused = False
        self.external_ks = lambda: None        # kill-switch de un cliente VPN (verificado por rutas)

    def policy(self, layer: str) -> Policy:
        return Policy.from_cfg(self.cfg["rotation"].get(layer, {}))

    def register(self, adapter: Adapter):
        self.adapters[adapter.layer] = adapter
        st = self.state.setdefault(adapter.layer, {})
        st.setdefault("since", now())
        st.setdefault("deadline", st["since"] + self.policy(adapter.layer).ttl())

    def history(self, layer: str, limit: int = 50) -> list[dict]:
        rows = self.store.rotations(limit=limit, layer=layer)
        out = []
        for r in rows:
            if r["result"] == "ok" and not r["dry_run"]:
                obs = (r["detail"] or {}).get("observed") or {}
                out.append({"target": r["to_target"], "ts": r["ts"], "exit_ip": obs.get("exit_ip"),
                            "exit": obs.get("exit"), "combination": obs.get("combination")})
        return out

    def rotations_last_hour(self, layer: str) -> int:
        return sum(1 for r in self.store.rotations(limit=100, layer=layer, since=now() - 3600)
                   if not r["dry_run"] and r["result"] in ("ok", "rolled_back", "failed_closed"))

    def status(self) -> dict:
        out = {}
        for layer, a in self.adapters.items():
            p = self.policy(layer)
            st = self.state.get(layer, {})
            ok, why = a.available()
            out[layer] = {"adapter": a.name, "enabled": p.enabled, "available": ok, "reason": why,
                          "since": st.get("since"), "deadline": st.get("deadline") if p.enabled else None,
                          "remaining": max(0, st["deadline"] - now()) if p.enabled and st.get("deadline") else None,
                          "rotations_last_hour": self.rotations_last_hour(layer), "max_per_hour": p.max_per_hour,
                          "paused": self.paused}
        return out

    def due(self) -> list[str]:
        if self.paused:
            return []
        return [l for l, st in self.state.items()
                if l in self.adapters and self.policy(l).enabled and st.get("deadline") and now() >= st["deadline"]]

    def rotate(self, layer: str, reason: str = "manual", dry_run: bool = False, force: bool = False) -> dict:
        steps: list[dict] = []

        def step(n, name, ok, detail=""):
            steps.append({"step": n, "name": name, "ok": ok, "detail": detail})
            return ok

        a = self.adapters.get(layer)
        p = self.policy(layer)
        result = {"layer": layer, "reason": reason, "dry_run": dry_run, "steps": steps, "result": "aborted"}
        if not a:
            step(0, "adaptador", False, _("no hay adaptador para '{layer}' en este sistema", layer=layer))
            return self._finish(result, None, None)
        result["adapter"] = a.name
        if self.paused and not dry_run:
            step(0, "estado", False, _("rotaciones en pausa (modo de emergencia)"))
            return self._finish(result, None, None)

        # límites de frecuencia
        st = self.state.setdefault(layer, {"since": now()})
        if not dry_run:
            if self.rotations_last_hour(layer) >= p.max_per_hour:
                step(0, "límite", False, _("máximo {max_per_hour} rotaciones/hora alcanzado", max_per_hour=p.max_per_hour))
                return self._finish(result, None, None)
            if not force and now() - st.get("since", 0) < p.min_ttl:
                step(0, "límite", False, _("tiempo mínimo de uso ({v1}s) no alcanzado", v1=int(p.min_ttl)))
                return self._finish(result, None, None)

        # 1. destino
        ok, why = a.available()
        if not step(1, "adaptador disponible", ok, why):
            return self._finish(result, None, None)
        previous = a.current()
        target, rejected = choose(a.targets(), self.history(layer), p, previous.id if previous else None)
        if layer == "tor" and target is None and a.targets():
            target = a.targets()[0]   # NEWNYM: la no repetición se aplica al exit observado (paso 7)
        if not step(1, "destino alternativo", target is not None,
                    f"→ {target.label}" if target else _("sin destinos válidos: {rejected}", rejected=rejected)):
            self.emit("rotation_no_target", "warning", {"layer": layer, "rejected": rejected})
            return self._finish(result, previous, None)
        result["from"], result["to"] = (previous.as_dict() if previous else None), target.as_dict()

        # 2. compatibilidad y consentimiento
        if not step(2, "compatibilidad", a.supports_rotation, "" if a.supports_rotation else _("solo observación")):
            return self._finish(result, previous, target)
        consent = self.cfg["consent"].get("allow_rotation_changes")
        if not dry_run and not step(2, "consentimiento", bool(consent),
                                    "" if consent else _("activa consent.allow_rotation_changes para rotar de verdad")):
            return self._finish(result, previous, target)

        # 3. protección contra fugas
        need_ks = p.require_killswitch and a.needs_killswitch
        ext = self.external_ks() or {}
        if need_ks and ext.get("verified_ipv4") and ext.get("declared_by"):
            # el cliente VPN ya bloquea el tráfico si cae el túnel: no hace falta el nuestro
            need_ks = False
            step(3, "protección contra fugas", True,
                 _("kill-switch de {v1} verificado por rutas", v1=', '.join(ext['declared_by'])))
        ks_ok, ks_why = (self.ks.can_apply() if self.ks else (False, _("kill-switch no disponible")))
        endpoints = a.endpoints(target) if need_ks else []
        if need_ks and not (ks_ok and endpoints):
            step(3, "protección contra fugas", False,
                 ks_why or _("no se conocen los endpoints del destino para permitirlos en el kill-switch"))
            self.emit("rotation_unsafe", "high", {"layer": layer, "reason": ks_why or _("endpoints desconocidos")})
            return self._finish(result, previous, target)
        if not any(x["step"] == 3 for x in steps):
            step(3, "protección contra fugas", True, _("kill-switch requerido y disponible") if need_ks else
                 (_("no requerida para esta capa") if not a.needs_killswitch else _("desactivada en la política")))

        if dry_run:
            result["result"] = "dry_run_ok"
            step(4, "simulación", True, _("pasos 4-8 no ejecutados (--dry-run)"))
            return self._finish(result, previous, target, record=True)

        # 4. bloqueo
        engaged = False
        if need_ks:
            res = self.ks.engage(endpoints=endpoints, reason=_("rotación {layer}", layer=layer))
            engaged = res.get("ok", False)
            if not step(4, "bloqueo de tráfico", engaged, res.get("error", "")):
                return self._finish(result, previous, target)
        else:
            step(4, "bloqueo de tráfico", True, _("no aplicado"))

        # 5-7 rotación, verificación y validación (con reintentos para Tor si repite exit)
        attempts = 1 + (p.retries_on_repeat if layer == "tor" else 0)
        verified, observed, error = False, {}, None
        recent_exits = {h.get("exit") or h.get("exit_ip") for h in self.history(layer)[:max(p.no_repeat, 1)]}
        for attempt in range(attempts):
            try:
                a.switch(target)
                step(5, "rotación", True, f"intento {attempt + 1}")
            except Exception as e:  # noqa: BLE001
                error = str(e)
                step(5, "rotación", False, error)
                break
            v = a.verify(target)
            if not step(6, "verificación", v.get("ok", False), v.get("error") or str(v.get("observed", ""))):
                error = v.get("error")
                break
            observed = v.get("observed", {})
            violations = []
            if observed.get("country") and observed["country"].upper() in p.exclude_countries:
                violations.append(_("país excluido {country}", country=observed['country']))
            if observed.get("asn") and norm_asn(observed["asn"]) in {norm_asn(x) for x in p.exclude_asn}:
                violations.append(_("ASN excluido {asn}", asn=observed['asn']))
            repeated = layer == "tor" and (observed.get("exit") in recent_exits)
            if repeated:
                violations.append(_("exit repetido dentro de la ventana de no repetición"))
            if not violations:
                verified = True
                step(7, "validación de política", True)
                break
            step(7, "validación de política", False, "; ".join(violations))
            error = "; ".join(violations)
            if not (repeated and attempt + 1 < attempts):
                break

        # 8. registro / rollback / liberar
        if verified:
            result["result"] = "ok"
            result["observed"] = observed
            if engaged:
                rel = self.ks.release()
                step(8, "liberar tráfico", rel.get("ok", False), rel.get("error", ""))
            else:
                step(8, "registro", True)
            st["since"] = now()
            st["deadline"] = st["since"] + p.ttl()
            return self._finish(result, previous, target, record=True)

        # fallo → rollback
        if a.reversible and previous:
            try:
                a.rollback(previous)
                rv = a.verify(previous)
                rb_ok = rv.get("ok", False)
            except Exception as e:  # noqa: BLE001
                rb_ok, rv = False, {"error": str(e)}
            step(8, "rollback", rb_ok, rv.get("error") or f"restaurado {previous.id}")
        else:
            rb_ok = layer == "tor"   # NEWNYM fallido no deja tráfico expuesto
            step(8, "rollback", rb_ok, _("no aplicable (no reversible)") if not a.reversible else _("sin destino previo"))
        if rb_ok:
            if engaged:
                self.ks.release()
            result["result"] = "rolled_back"
            self.emit("rotation_failed", "warning", {"layer": layer, "error": error})
        else:
            result["result"] = "failed_closed" if engaged else "failed"
            self.emit("rotation_failed", "critical",
                      {"layer": layer, "error": error, "traffic_blocked": engaged,
                       "action": _("el kill-switch se mantiene activo; revisa la conexión manualmente") if engaged
                       else _("sin kill-switch: verifica tu conexión")})
        result["error"] = error
        return self._finish(result, previous, target, record=True)

    def _finish(self, result, previous, target, record: bool = True) -> dict:
        if record:
            self.store.add_rotation(result["layer"], result.get("adapter", "-"), result["dry_run"],
                                    previous.id if previous else None, target.id if target else None,
                                    result["result"], {"steps": result["steps"], "observed": result.get("observed"),
                                                       "reason": result["reason"], "error": result.get("error")})
        return result
