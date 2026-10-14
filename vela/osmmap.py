"""Mapa base propio a partir de datos de OpenStreetMap, generado una vez y guardado en local.

Fuentes (© OpenStreetMap contributors, ODbL — la atribución se muestra en el mapa):
  * tierra y costa: «simplified land polygons» de osmdata.openstreetmap.de (derivado de OSM, EPSG:3857);
  * países, capitales y grandes ciudades: nodos place=* de OSM vía Overpass API.

La app trae el mapa ya generado e incorporado (vela/data/basemap-osm.bin), así que funciona
nada más instalarla y sin conexión. Regenerarlo es opcional (datos más recientes); el nuevo solo se
descarga cuando el usuario lo pide (`vela map build` o el botón de Ajustes), por Tor si está
disponible o por la VPN; nunca por la conexión directa salvo con --via direct. Después el mapa se dibuja
sin conexión: mirar el mapa no pide teselas a ningún servidor, así que no revela qué zonas consultas
(que suelen ser las de tus propias IPs).

Formato propio (basemap-osm.bin): cabecera JSON + bloques zlib por tesela. Hay varios niveles de detalle
(LOD) para zoom 2, 4, 6 y 8; cada nivel está simplificado (Douglas-Peucker) y troceado en una rejilla para
dibujar solo lo visible. Coordenadas en Mercator normalizado [0, 1] cuantizado a enteros.
"""

from __future__ import annotations

from .i18n import _

import array
import http.client
import json
import math
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import zipfile
import zlib
from pathlib import Path

from .util import xdg_dir

LAND_HOST = "osmdata.openstreetmap.de"
LAND_PATH = "/download/simplified-land-polygons-complete-3857.zip"
OVERPASS = [("overpass-api.de", "/api/interpreter"), ("overpass.private.coffee", "/api/interpreter")]
ATTRIBUTION = "© OpenStreetMap contributors"     # texto oficial de la licencia ODbL: no se traduce
USER_AGENT = "vela-command-center/1.0 (mapa base local; descarga única)"
MAGIC = b"OPSECMAP1\n"
R = 20037508.342789244          # semieje de Web Mercator (m)
Q = 1 << 26                     # cuantización de [0, 1]
LODS = [(2, 1), (4, 4), (6, 16), (8, 64)]   # (zoom de referencia, rejilla n×n)
TOL_PX = 0.6                    # error máximo de simplificación, en píxeles del zoom de referencia
MAX_LAT = 85.05112878
MIN_POP = 100_000

# Tres consultas pequeñas: la combinada suele dar 504 en los servidores públicos de Overpass
PLACES_QUERIES = [
    ("países", '[out:json][timeout:90];node["place"="country"];out body qt;'),
    ("capitales", '[out:json][timeout:90];node["place"="city"]["capital"="yes"];out body qt;'),
    ("ciudades", '[out:json][timeout:120];node["place"="city"]["population"]'
                 '(if: number(t["population"]) >= %d);out body qt;' % MIN_POP),
]


def data_dir() -> Path:
    return xdg_dir("data") / "map"


def cache_dir() -> Path:
    """Descargas originales (para reconstruir sin volver a descargar)."""
    base = Path(os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache"))
    return base / xdg_dir("data").name / "map"


def basemap_path() -> Path:
    """Mapa generado por el usuario (vela map build)."""
    return data_dir() / "basemap-osm.bin"


BUNDLED = Path(__file__).resolve().parent / "data" / "basemap-osm.bin"   # incorporado en la app


def _created(path: Path) -> int:
    try:
        with open(path, "rb") as f:
            head = f.read(len(MAGIC) + 4)
            if not head.startswith(MAGIC):
                return -1
            n = struct.unpack_from("<I", head, len(MAGIC))[0]
            return int(json.loads(f.read(n)).get("created") or 0)
    except (OSError, ValueError, struct.error):
        return -1


def active_path() -> Path | None:
    """El mapa a usar: el más reciente entre el incorporado en la app y el que haya generado el usuario."""
    cands = [(c, i, p) for i, p in enumerate((BUNDLED, basemap_path())) if (c := _created(p)) >= 0]
    return max(cands)[2] if cands else None


# ── proyección ──────────────────────────────────────────────────────────────

def lonlat_to_norm(lon: float, lat: float) -> tuple[float, float]:
    """Web Mercator normalizado: x ∈ [0, 1] de oeste a este, y ∈ [0, 1] de norte a sur."""
    lat = max(-MAX_LAT, min(MAX_LAT, lat))
    y = 0.5 - math.log(math.tan(math.pi / 4 + math.radians(lat) / 2)) / (2 * math.pi)
    return (lon + 180.0) / 360.0, y


def norm_to_lonlat(x: float, y: float) -> tuple[float, float]:
    lat = math.degrees(2 * math.atan(math.exp((0.5 - y) * 2 * math.pi)) - math.pi / 2)
    return x * 360.0 - 180.0, lat


def merc_to_norm(mx: float, my: float) -> tuple[float, float]:
    return (mx + R) / (2 * R), (R - my) / (2 * R)


def lod_for_zoom(z: float) -> int:
    """Índice del nivel de detalle para un zoom efectivo (log2 del ancho del mundo en teselas de 256 px)."""
    best = 0
    for i, (lz, _ign) in enumerate(LODS):
        if lz <= z + 0.6:
            best = i
    return best


# ── shapefile (solo polígonos, sin dependencias) ────────────────────────────

def read_shp(data: bytes):
    """Genera las anillas (listas de (x, y) en metros) de cada polígono de un .shp."""
    if struct.unpack_from(">i", data, 0)[0] != 9994:
        raise ValueError(_("no es un shapefile"))
    total = struct.unpack_from(">i", data, 24)[0] * 2
    off = 100
    while off + 8 <= min(total, len(data)):
        _num, clen = struct.unpack_from(">ii", data, off)
        off += 8
        end = off + clen * 2
        stype = struct.unpack_from("<i", data, off)[0]
        if stype in (5, 15, 25):
            nparts, npoints = struct.unpack_from("<ii", data, off + 36)
            parts = list(struct.unpack_from(f"<{nparts}i", data, off + 44)) + [npoints]
            pts = array.array("d")
            p0 = off + 44 + 4 * nparts
            pts.frombytes(data[p0:p0 + 16 * npoints])
            if sys.byteorder == "big":
                pts.byteswap()
            rings = []
            for a, b in zip(parts, parts[1:]):
                rings.append(pts[2 * a:2 * b])
            yield rings
        off = end


def read_land_zip(path: Path):
    with zipfile.ZipFile(path) as z:
        name = next(n for n in z.namelist() if n.endswith(".shp"))
        return z.read(name)


# ── geometría ───────────────────────────────────────────────────────────────

def simplify(xs: list[float], ys: list[float], tol: float) -> list[int]:
    """Douglas-Peucker iterativo; devuelve los índices conservados (anilla cerrada: primero == último)."""
    n = len(xs)
    if n <= 4:
        return list(range(n))
    keep = bytearray(n)
    keep[0] = keep[n - 1] = 1
    # una anilla cerrada tiene el mismo punto al principio y al final: partirla por el punto más lejano
    x0, y0 = xs[0], ys[0]
    far = max(range(1, n - 1), key=lambda i: (xs[i] - x0) ** 2 + (ys[i] - y0) ** 2)
    keep[far] = 1
    stack = [(0, far), (far, n - 1)]
    tol2 = tol * tol
    while stack:
        a, b = stack.pop()
        if b - a < 2:
            continue
        ax, ay, bx, by = xs[a], ys[a], xs[b], ys[b]
        dx, dy = bx - ax, by - ay
        L2 = dx * dx + dy * dy
        best, bi = -1.0, -1
        if L2 == 0:
            for i in range(a + 1, b):
                d = (xs[i] - ax) ** 2 + (ys[i] - ay) ** 2
                if d > best:
                    best, bi = d, i
        else:
            for i in range(a + 1, b):
                c = (xs[i] - ax) * dy - (ys[i] - ay) * dx
                d = c * c / L2
                if d > best:
                    best, bi = d, i
        if best > tol2:
            keep[bi] = 1
            stack.append((a, bi))
            stack.append((bi, b))
    return [i for i in range(n) if keep[i]]


def ring_area(ring: list[tuple[float, float]]) -> float:
    s = 0.0
    for (x1, y1), (x2, y2) in zip(ring, ring[1:] + ring[:1]):
        s += x1 * y2 - x2 * y1
    return s / 2


def clip_half(ring, axis: int, value: float, keep_less: bool):
    """Sutherland-Hodgman contra un semiplano (x o y ≤/≥ value). Los puntos de corte caen EXACTAMENTE
    en `value`, lo que permite reconocer después los bordes artificiales de tesela al trazar la costa."""
    out = []
    if not ring:
        return out
    inside = (lambda p: p[axis] <= value) if keep_less else (lambda p: p[axis] >= value)
    prev = ring[-1]
    pin = inside(prev)
    for cur in ring:
        cin = inside(cur)
        if cin != pin:
            t = (value - prev[axis]) / (cur[axis] - prev[axis])
            o = 1 - axis
            q = [0.0, 0.0]
            q[axis] = value
            q[o] = prev[o] + t * (cur[o] - prev[o])
            out.append((q[0], q[1]))
        if cin:
            out.append(cur)
        prev, pin = cur, cin
    return out


def split_ring(ring, grid: int, out: dict, ix0=0, ix1=None, iy0=0, iy1=None):
    """Trocea una anilla en las teselas de una rejilla grid×grid (división binaria recursiva)."""
    if len(ring) < 3:
        return
    if ix1 is None:
        xs = [p[0] for p in ring]
        ys = [p[1] for p in ring]
        ix0, ix1 = max(0, int(min(xs) * grid)), min(grid - 1, int(max(xs) * grid))
        iy0, iy1 = max(0, int(min(ys) * grid)), min(grid - 1, int(max(ys) * grid))
    if ix0 == ix1 and iy0 == iy1:
        if abs(ring_area(ring)) > 0:
            out.setdefault((ix0, iy0), []).append(ring)
        return
    if ix1 - ix0 >= iy1 - iy0:
        mid = (ix0 + ix1 + 1) // 2
        v = mid / grid
        split_ring(clip_half(ring, 0, v, True), grid, out, ix0, mid - 1, iy0, iy1)
        split_ring(clip_half(ring, 0, v, False), grid, out, mid, ix1, iy0, iy1)
    else:
        mid = (iy0 + iy1 + 1) // 2
        v = mid / grid
        split_ring(clip_half(ring, 1, v, True), grid, out, ix0, ix1, iy0, mid - 1)
        split_ring(clip_half(ring, 1, v, False), grid, out, ix0, ix1, mid, iy1)


# ── lugares (Overpass) ──────────────────────────────────────────────────────

def parse_places(doc: dict) -> list[dict]:
    out = []
    for el in doc.get("elements", []):
        t = el.get("tags") or {}
        if el.get("lat") is None:
            continue
        name = t.get("name:es") or t.get("name:en") or t.get("name")
        if not name:
            continue
        place = t.get("place")
        kind = "country" if place == "country" else "capital" if t.get("capital") == "yes" else "city"
        try:
            pop = int(float(str(t.get("population", "0")).replace(",", "").replace(" ", "").split(";")[0] or 0))
        except ValueError:
            pop = 0
        x, y = lonlat_to_norm(el["lon"], el["lat"])
        names = {lang: t[f"name:{lang}"] for lang in ("es", "en", "ca", "pt", "fr", "de") if t.get(f"name:{lang}")}
        out.append({"x": round(x, 7), "y": round(y, 7), "name": name, "names": names, "kind": kind, "pop": pop,
                    "cc": (t.get("ISO3166-1:alpha2") or t.get("country_code") or "").upper() or None})
    rank = {"country": 0, "capital": 1, "city": 2}
    out.sort(key=lambda p: (rank[p["kind"]], -p["pop"]))
    return out


# ── construcción del fichero ────────────────────────────────────────────────

def _pack_tile(rings) -> bytes:
    a = array.array("i", [len(rings)] + [len(r) for r in rings])
    for r in rings:
        px = py = 0
        for x, y in r:
            qx, qy = int(round(x * Q)), int(round(y * Q))
            a.append(qx - px)
            a.append(qy - py)
            px, py = qx, qy
    if sys.byteorder == "big":
        a.byteswap()
    return zlib.compress(a.tobytes(), 6)


def _unpack_tile(blob: bytes) -> list[array.array]:
    a = array.array("i")
    a.frombytes(zlib.decompress(blob))
    if sys.byteorder == "big":
        a.byteswap()
    n = a[0]
    lens = a[1:1 + n]
    pos = 1 + n
    rings = []
    for L in lens:
        r = array.array("i", bytes(8 * L))
        px = py = 0
        for i in range(L):
            px += a[pos]
            py += a[pos + 1]
            r[2 * i] = px
            r[2 * i + 1] = py
            pos += 2
        rings.append(r)
    return rings


def build_basemap(shp: bytes, places: list[dict] | None, out: Path, progress=lambda f, m: None,
                  source: str = LAND_HOST + LAND_PATH) -> dict:
    """Convierte los polígonos de tierra (shapefile EPSG:3857) en el mapa base de la app."""
    t0 = time.time()
    progress(0.02, _("leyendo polígonos de tierra"))
    rings = []
    npts = 0
    for poly in read_shp(shp):
        for r in poly:
            xs = [(r[i] + R) / (2 * R) for i in range(0, len(r), 2)]
            ys = [(R - r[i]) / (2 * R) for i in range(1, len(r), 2)]
            npts += len(xs)
            rings.append((xs, ys))
    progress(0.10, f"{len(rings)} anillas, {npts} puntos")
    lods = []
    blobs = []
    offset = 0
    cur = rings
    # de más fino a más grueso: cada nivel se simplifica a partir del anterior
    levels = []
    for li, (z, grid) in enumerate(reversed(LODS)):
        tol = TOL_PX / (256 * 2 ** z)
        nxt = []
        for xs, ys in cur:
            if max(xs) - min(xs) < tol * 2 and max(ys) - min(ys) < tol * 2:
                continue
            idx = simplify(xs, ys, tol)
            if len(idx) >= 4:
                nxt.append(([xs[i] for i in idx], [ys[i] for i in idx]))
        cur = nxt
        levels.append((z, grid, cur))
        progress(0.10 + 0.45 * (li + 1) / len(LODS), f"zoom {z}: {sum(len(x) for x, _ign in cur)} puntos")
    total_pts = {}
    for li, (z, grid, rs) in enumerate(sorted(levels)):
        tiles: dict = {}
        for xs, ys in rs:
            ring = list(zip(xs, ys))
            if ring[0] == ring[-1]:
                ring.pop()
            split_ring(ring, grid, tiles)
        index = {}
        for (tx, ty), trs in sorted(tiles.items()):
            blob = _pack_tile(trs)
            index[f"{tx},{ty}"] = [offset, len(blob)]
            blobs.append(blob)
            offset += len(blob)
        total_pts[z] = sum(len(r) for trs in tiles.values() for r in trs)
        lods.append({"z": z, "grid": grid, "tiles": index})
        progress(0.55 + 0.4 * (li + 1) / len(LODS), f"zoom {z}: {len(tiles)} teselas")
    head = {"version": 1, "created": int(time.time()), "attribution": ATTRIBUTION, "license": "ODbL 1.0",
            "sources": [source] + (["overpass-api.de"] if places else []), "q": Q, "lods": lods,
            "points": total_pts, "places": places or []}
    hb = json.dumps(head, ensure_ascii=False).encode()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp")
    with open(tmp, "wb") as f:
        f.write(MAGIC + struct.pack("<I", len(hb)) + hb)
        for b in blobs:
            f.write(b)
    tmp.replace(out)
    progress(1.0, _("listo en {v1:.0f} s", v1=time.time() - t0))
    return {"path": str(out), "bytes": out.stat().st_size, "points": total_pts, "places": len(places or []),
            "seconds": round(time.time() - t0, 1)}


# ── lectura ────────────────────────────────────────────────────────────────

class Basemap:
    """Mapa base cargado: teselas decodificadas bajo demanda y guardadas en memoria."""

    def __init__(self, path: Path):
        raw = Path(path).read_bytes()
        if not raw.startswith(MAGIC):
            raise ValueError(_("formato de mapa desconocido"))
        n = struct.unpack_from("<I", raw, len(MAGIC))[0]
        p = len(MAGIC) + 4
        self.head = json.loads(raw[p:p + n])
        self.body = memoryview(raw)[p + n:]
        self.places = self.head.get("places") or []
        self.lods = self.head["lods"]
        self.q = self.head.get("q", Q)
        self._cache: dict = {}
        self._lock = threading.Lock()

    def tile(self, lod: int, tx: int, ty: int) -> list[array.array]:
        key = (lod, tx, ty)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        ent = self.lods[lod]["tiles"].get(f"{tx},{ty}")
        rings = _unpack_tile(bytes(self.body[ent[0]:ent[0] + ent[1]])) if ent else []
        with self._lock:
            self._cache[key] = rings
        return rings

    def coast(self, lod: int, tx: int, ty: int) -> list[array.array]:
        """Líneas de costa de una tesela: las anillas sin los tramos que son bordes de tesela (artificiales)."""
        key = ("c", lod, tx, ty)
        with self._lock:
            hit = self._cache.get(key)
        if hit is not None:
            return hit
        g = self.lods[lod]["grid"]
        step = self.q // g
        bx = (tx * step, (tx + 1) * step)
        by = (ty * step, (ty + 1) * step)
        lines = []
        for r in self.tile(lod, tx, ty):
            n = len(r) // 2
            cur = None
            for i in range(n + 1):
                j = i % n
                x, y = r[2 * j], r[2 * j + 1]
                if cur is not None:
                    px, py = cur[-2], cur[-1]
                    seam = (x == px and x in bx) or (y == py and y in by)
                    if seam:
                        if len(cur) >= 4:
                            lines.append(cur)
                        cur = None
                    else:
                        cur.append(x)
                        cur.append(y)
                        continue
                cur = array.array("i", (x, y))
            if cur is not None and len(cur) >= 4:
                lines.append(cur)
        with self._lock:
            self._cache[key] = lines
        return lines

    def world_rings(self, lod: int = 0) -> list[list[tuple[float, float]]]:
        """Anillas del nivel `lod` en (lon, lat), para la TUI y la GUI web (proyección equirectangular)."""
        key = ("ll", lod)
        hit = self._cache.get(key)
        if hit is not None:
            return hit
        out = []
        g = self.lods[lod]["grid"]
        for ty in range(g):
            for tx in range(g):
                for r in self.tile(lod, tx, ty):
                    out.append([norm_to_lonlat(r[i] / self.q, r[i + 1] / self.q) for i in range(0, len(r), 2)])
        self._cache[key] = out
        return out

    def visible(self, lod: int, x0: float, y0: float, x1: float, y1: float):
        """Teselas (tx, ty, anillas) del nivel `lod` que tocan el rectángulo normalizado dado."""
        g = self.lods[lod]["grid"]
        for ty in range(max(0, int(y0 * g)), min(g - 1, int(y1 * g)) + 1):
            for tx in range(max(0, int(x0 * g)), min(g - 1, int(x1 * g)) + 1):
                rings = self.tile(lod, tx, ty)
                if rings:
                    yield tx, ty, rings


_LOADED: dict = {}


def load(path: Path | None = None) -> Basemap | None:
    path = path or active_path()
    if path is None:
        return None
    path = Path(path)
    try:
        st = path.stat()
    except OSError:
        return None
    key = (str(path), st.st_mtime_ns)
    if key not in _LOADED:
        _LOADED.clear()
        try:
            _LOADED[key] = Basemap(path)
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            return None
    return _LOADED[key]


def status() -> dict:
    p = active_path()
    if p is None:
        return {"installed": False, "path": str(basemap_path())}
    bm = load(p)
    if not bm:
        return {"installed": False, "path": str(p), "error": _("fichero dañado")}
    h = bm.head
    return {"installed": True, "path": str(p), "bundled": p == BUNDLED,
            "source": _("incorporado en la app") if p == BUNDLED else _("generado por ti (vela map build)"),
            "bytes": p.stat().st_size, "created": h.get("created"),
            "points": h.get("points"), "places": len(bm.places), "sources": h.get("sources"),
            "attribution": h.get("attribution")}


# ── descarga ───────────────────────────────────────────────────────────────

def choose_route(via: str, env: dict) -> tuple[str, tuple[str, int] | None]:
    """Devuelve (ruta, socks). auto = Tor si hay SocksPort, si no la VPN; nunca directo sin pedirlo."""
    socks = ((env.get("tor") or {}).get("socks") or [])
    kinds = {i["name"]: i["kind"] for i in env.get("interfaces") or []}
    egress = (env.get("egress") or {}).get("ipv4")
    tunnel = kinds.get(egress) in ("wireguard", "tun", "ppp")
    if via in ("auto", "tor") and socks:
        return "tor", ("127.0.0.1", socks[0])
    if via == "tor":
        raise OSError(_("Tor no está disponible (no hay SocksPort)"))
    if via in ("auto", "vpn"):
        if tunnel:
            return "vpn", None
        raise OSError(_("sin Tor ni VPN conectada: la descarga saldría con tu IP real. Usa --via direct si te da igual "
                      "(solo se descarga un fichero público del mundo entero; no revela qué zonas miras)"))
    if via == "direct":
        return "direct", None
    raise ValueError(via)


class _Conn(http.client.HTTPSConnection):
    def __init__(self, host, socks, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._socks = socks

    def connect(self):
        if self._socks:
            from .publicip import open_socks5
            raw = open_socks5(self._socks, self.host, 443, self.timeout)
        else:
            raw = socket.create_connection((self.host, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def fetch(host: str, path: str, socks, dest: Path, *, method="GET", body: bytes | None = None,
          timeout: float = 90, progress=lambda f, m: None, label="") -> Path:
    """Descarga a fichero (en streaming); con `socks` la conexión va por Tor y el DNS lo resuelve Tor."""
    conn = _Conn(host, socks, timeout)
    hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if body is not None:
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    try:
        conn.request(method, path, body=body, headers=hdrs)
        r = conn.getresponse()
        if r.status != 200:
            raise OSError(f"{host}: HTTP {r.status}")
        size = int(r.getheader("Content-Length") or 0)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        got = 0
        last = 0.0
        with open(tmp, "wb") as f:
            while True:
                chunk = r.read(256 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                got += len(chunk)
                if time.time() - last > 0.5:
                    last = time.time()
                    progress(got / size if size else 0.0, f"{label} {got / 1e6:.1f}"
                             + (f" / {size / 1e6:.1f}" if size else "") + " MB")
        if size and got != size:
            raise OSError(_("{host}: descarga incompleta ({got} de {size} bytes)", host=host, got=got, size=size))
        tmp.replace(dest)
        return dest
    finally:
        conn.close()


def head_size(host: str, path: str, socks, timeout: float = 60) -> int | None:
    conn = _Conn(host, socks, timeout)
    try:
        conn.request("HEAD", path, headers={"User-Agent": USER_AGENT})
        r = conn.getresponse()
        return int(r.getheader("Content-Length") or 0) or None
    finally:
        conn.close()


def fetch_places(socks, progress=lambda f, m: None, tries: int = 3, wait: float = 15) -> tuple[dict, str | None]:
    """Nombres de países, capitales y grandes ciudades desde Overpass. Devuelve (documento, error)."""
    elements, errors, failed = {}, [], []
    for qi, (label, q) in enumerate(PLACES_QUERIES):
        body = urllib.parse.urlencode({"data": q}).encode()
        done = False
        for attempt in range(tries):
            for host, path in OVERPASS:
                try:
                    progress(0.47 + 0.03 * qi / len(PLACES_QUERIES), f"lugares: {label} ({host})")
                    conn = _Conn(host, socks, 150)
                    try:
                        conn.request("POST", path, body=body, headers={
                            "User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded"})
                        r = conn.getresponse()
                        data = r.read()
                    finally:
                        conn.close()
                    if r.status != 200:
                        raise OSError(f"HTTP {r.status}")
                    doc = json.loads(data)
                    if doc.get("remark") and not doc.get("elements"):
                        raise OSError(doc["remark"][:120])
                    for el in doc.get("elements", []):
                        elements[el.get("id")] = el
                    done = True
                    break
                except (OSError, ValueError, http.client.HTTPException) as e:
                    errors.append(f"{label} · {host}: {e}")
            if done:
                break
            if attempt + 1 < tries:
                time.sleep(wait * (attempt + 1))
        if not done:
            failed.append(label)
    err = f"faltan {', '.join(failed)} ({errors[-1]})" if failed else None
    return {"elements": list(elements.values())}, err


def download_and_build(via: str, env: dict, land_file: Path | None = None, places: bool = True,
                       progress=lambda f, m: None, refresh: bool = False) -> dict:
    """Genera el mapa. Reutiliza las descargas guardadas en caché salvo con refresh=True."""
    cdir = cache_dir()
    if refresh:
        for f in ("simplified-land-polygons-complete-3857.zip", "places.json"):
            if not (f.endswith(".zip") and land_file):
                (cdir / f).unlink(missing_ok=True)
    need_land = land_file is None and not (cdir / "simplified-land-polygons-complete-3857.zip").exists()
    need_places = places and not (cdir / "places.json").exists()
    route, socks = choose_route(via, env) if (need_land or need_places) else (None, None)
    downloaded = []
    if land_file is None:
        land_file = cdir / "simplified-land-polygons-complete-3857.zip"
        if not land_file.exists():
            fetch(LAND_HOST, LAND_PATH, socks, land_file, timeout=120, label=_("tierra (OSM)"),
                  progress=lambda f, m: progress(0.02 + 0.45 * f, m))
            downloaded.append("costas")
    pl = None
    perr = None
    if places:
        pfile = cdir / "places.json"
        if not pfile.exists():
            pl_doc, perr = fetch_places(socks, progress)
            if pl_doc["elements"]:
                pfile.write_text(json.dumps(pl_doc))
                downloaded.append("lugares")
        if pfile.exists():
            try:
                pl = parse_places(json.loads(pfile.read_text()))
            except (ValueError, KeyError) as e:
                perr = f"lugares: {e}"
                pfile.unlink(missing_ok=True)
    shp = read_land_zip(land_file)
    res = build_basemap(shp, pl, basemap_path(), progress=lambda f, m: progress(0.5 + 0.5 * f, m))
    res.update(route=route if downloaded else None, downloaded=downloaded, places_error=perr, land_file=str(land_file))
    return res


def _cli_progress(f, m):
    print(f"progress {f:.3f} {m}", flush=True)

