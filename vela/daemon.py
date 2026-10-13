"""`velad`: motor de monitorización continua.

Sigue funcionando aunque la TUI o la GUI estén cerradas. Combina eventos (netlink para la red,
eventos CIRC/STREAM de Tor) con sondeos de respaldo a intervalos configurables.
"""

from __future__ import annotations

import logging
import os
import signal
import sys
import threading
import time

from . import config as config_mod
from .engine import Engine
from .ipc import IPCServer, ping, socket_path
from .network import NetlinkWatcher
from .util import now, private_dir, runtime_dir, xdg_dir

log = logging.getLogger("velad")


def pid_path():
    return runtime_dir() / "velad.pid"


def run(foreground: bool = True, log_level: str = "INFO") -> int:
    logging.basicConfig(level=log_level, format="%(asctime)s velad %(levelname)s %(message)s")
    if ping():
        print(f"velad ya está en marcha ({socket_path()})", file=sys.stderr)
        return 1
    try:                                   # red de seguridad: más margen de descriptores
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, 8192), hard), hard))
    except (ImportError, ValueError, OSError):
        pass
    cfg = config_mod.load()
    engine = Engine(cfg, actor="daemon", track=True)
    engine.tracker.recover(engine.store.get("heartbeat"))
    engine.retention()
    engine.discover()
    engine.start_forwarder()
    server = IPCServer(engine).start()
    private_dir(runtime_dir())
    pid_path().write_text(str(os.getpid()))

    watcher = NetlinkWatcher(lambda: engine.mark_dirty("network", "dns", "public", "rediscover"))
    watcher.start()
    log.info("netlink: %s", "eventos activos" if watcher.available else "no disponible, solo sondeo")
    engine.tor_obs.start_events(lambda ev: engine.mark_dirty("tor"))
    from .leakwatch import LeakWatcher
    from .util import parse_duration
    lw_cfg = cfg.get("leakwatch") or {}
    if lw_cfg.get("enabled", True):
        engine.leakwatcher = LeakWatcher(engine, interval=parse_duration(lw_cfg.get("interval", "2s")))
        engine.leakwatcher.start()
        log.info("vigilante de fugas en tiempo real: cada %s", lw_cfg.get("interval", "2s"))
    from .intel import LiveIntel
    engine.intel_live = LiveIntel(engine)
    engine.intel_live.start()
    engine.emit("daemon_start", "info", {"pid": os.getpid(), "netlink": watcher.available})
    log.info("escuchando en %s", socket_path())

    stop = threading.Event()

    def _sig(signum, _frame):
        log.info("señal %s: deteniendo", signum)
        stop.set()

    signal.signal(signal.SIGTERM, _sig)
    signal.signal(signal.SIGINT, _sig)
    last_retention = now()
    while not stop.is_set():
        t0 = time.monotonic()
        try:
            engine.tick()
        except Exception:  # noqa: BLE001 — el daemon no debe caer por un fallo puntual
            log.exception("error en el ciclo de monitorización")
        if now() - last_retention > 3600:
            engine.retention()
            last_retention = now()
        stop.wait(max(0.2, 1.0 - (time.monotonic() - t0)))

    engine.emit("daemon_stop", "info", {})
    watcher.stop()
    server.stop()
    engine.close()
    try:
        pid_path().unlink()
    except OSError:
        pass
    return 0


def start_background() -> int:
    """Lanza el daemon desacoplado de la terminal (log en ~/.local/state/vela/velad.log)."""
    if ping():
        print("velad ya está en marcha")
        return 0
    logdir = private_dir(xdg_dir("state"))
    logf = open(logdir / "velad.log", "ab")
    pid = os.fork()
    if pid:
        for _ in range(100):
            time.sleep(0.1)
            if ping():
                print(f"velad iniciado (pid {pid}), log: {logdir / 'velad.log'}")
                return 0
        print(f"velad no respondió; revisa {logdir / 'velad.log'}", file=sys.stderr)
        return 1
    os.setsid()
    os.dup2(logf.fileno(), 1)
    os.dup2(logf.fileno(), 2)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os._exit(run())


def stop_daemon() -> int:
    try:
        pid = int(pid_path().read_text())
    except (OSError, ValueError):
        print("velad no está en marcha")
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        print("velad no está en marcha (pid obsoleto)")
        return 1
    for _ in range(50):
        time.sleep(0.1)
        if not ping():
            print("velad detenido")
            return 0
    print("velad no se detuvo a tiempo", file=sys.stderr)
    return 1


def main():
    sys.exit(run())


if __name__ == "__main__":
    main()
