"""Regresión: fuga de descriptores en el IPC (Too many open files tras horas de funcionamiento)."""

import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from vela import ipc, leakwatch
from vela.engine import Engine
from vela.store import Store

from .helpers import cfg

TMP = os.environ.get("TMPDIR") or None


def nfds():
    return len(os.listdir("/proc/self/fd"))


class IPCLeakTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine(cfg(), store=Store(memory=True), track=False)
        self.srv = ipc.IPCServer(self.engine, Path(tempfile.mkdtemp(dir=TMP)) / "s" / "velad.sock").start()

    def tearDown(self):
        self.srv.stop()

    def server_conns(self):
        time.sleep(0.3)
        return sum(1 for t in threading.enumerate() if t.name.startswith("Thread") and t.is_alive())

    def test_client_never_leaks(self):
        c = ipc.Client(self.srv.path, timeout=10)
        c.call("profiles")
        base = nfds()
        for _ in range(60):
            c.call("profiles")
            with self.assertRaises(ipc.IPCError):
                c.call("no_existe")
            self.assertTrue(ipc.ping(self.srv.path))
        self.assertLessEqual(nfds() - base, 1)

    def test_timeout_does_not_leak(self):
        slow = threading.Event()
        self.engine.api_profiles = lambda: (slow.wait(2), {"active": "x"})[1]
        c = ipc.Client(self.srv.path, timeout=0.2)
        base = nfds()
        for _ in range(10):
            with self.assertRaises(OSError):
                c.call("profiles")
        slow.set()                                    # la respuesta lenta termina…
        time.sleep(0.6)
        self.assertLessEqual(nfds() - base, 1)        # …y el servidor (mismo proceso) libera todos los sockets

    def test_server_closes_idle_connections(self):
        ipc._Handler.timeout = 0.5
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(str(self.srv.path))           # conecta y no envía nada
            s.settimeout(3)
            self.assertEqual(s.recv(10), b"")        # el servidor cierra al agotar el tiempo
            s.close()
        finally:
            ipc._Handler.timeout = 60

    def test_one_request_per_connection(self):
        s = socket.socket(socket.AF_UNIX)
        s.connect(str(self.srv.path))
        s.sendall(b'{"id":1,"method":"profiles"}\n')
        s.settimeout(3)
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        self.assertIn(b'"result"', data)             # responde y cierra (no deja la conexión abierta)
        s.close()


class OwnersTests(unittest.TestCase):
    def test_owners_only_wanted_and_cached(self):
        a, b = socket.socketpair()
        ino = os.fstat(a.fileno()).st_ino
        res = leakwatch.owners({ino})
        self.assertEqual(res[ino][0], os.getpid())
        self.assertEqual(set(res), {ino})
        self.assertEqual(leakwatch.owners({ino}), res)  # desde caché
        a.close()
        b.close()


if __name__ == "__main__":
    unittest.main()
