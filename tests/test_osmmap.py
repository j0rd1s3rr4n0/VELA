"""Mapa base propio a partir de OSM: shapefile, simplificación, troceado, formato y lugares."""

import math
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from opsectools import osmmap


def shp_bytes(polys):
    """Shapefile mínimo de polígonos (coordenadas Web Mercator en metros)."""
    recs = b""
    for n, rings in enumerate(polys, 1):
        pts = [p for r in rings for p in r]
        parts, acc = [], 0
        for r in rings:
            parts.append(acc)
            acc += len(r)
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        body = struct.pack("<i4d2i", 5, min(xs), min(ys), max(xs), max(ys), len(rings), len(pts))
        body += struct.pack(f"<{len(parts)}i", *parts) + b"".join(struct.pack("<2d", *p) for p in pts)
        recs += struct.pack(">2i", n, len(body) // 2) + body
    head = struct.pack(">7i", 9994, 0, 0, 0, 0, 0, (100 + len(recs)) // 2) + struct.pack("<2i4d4d", 1000, 5, *[0.0] * 8)
    return head + recs


def merc(lon, lat):
    x, y = osmmap.lonlat_to_norm(lon, lat)
    return x * 2 * osmmap.R - osmmap.R, osmmap.R - y * 2 * osmmap.R


def circle(lon, lat, r_deg, n=400):
    pts = [merc(lon + r_deg * math.cos(2 * math.pi * i / n), lat + r_deg * math.sin(2 * math.pi * i / n)) for i in range(n)]
    return pts + [pts[0]]


class ProjectionTests(unittest.TestCase):
    def test_roundtrip(self):
        for lon, lat in ((0, 0), (-3.7, 40.4), (139.7, 35.7), (-70, -55)):
            x, y = osmmap.lonlat_to_norm(lon, lat)
            lo, la = osmmap.norm_to_lonlat(x, y)
            self.assertAlmostEqual(lo, lon, 6)
            self.assertAlmostEqual(la, lat, 6)
        self.assertEqual(osmmap.lonlat_to_norm(0, 0), (0.5, 0.5))
        self.assertLess(osmmap.lonlat_to_norm(0, 60)[1], 0.5)          # norte arriba

    def test_lod_choice(self):
        self.assertEqual(osmmap.lod_for_zoom(1), 0)
        self.assertEqual(osmmap.lod_for_zoom(4.2), 1)
        self.assertEqual(osmmap.lod_for_zoom(9), len(osmmap.LODS) - 1)


class GeometryTests(unittest.TestCase):
    def test_simplify_keeps_shape(self):
        n = 1000
        xs = [math.cos(2 * math.pi * i / n) for i in range(n)] + [1.0]
        ys = [math.sin(2 * math.pi * i / n) for i in range(n)] + [0.0]
        idx = osmmap.simplify(xs, ys, 0.01)
        self.assertLess(len(idx), 100)
        self.assertGreater(len(idx), 8)
        self.assertEqual((idx[0], idx[-1]), (0, n))

    def test_split_preserves_area(self):
        ring = [(0.1, 0.1), (0.9, 0.15), (0.8, 0.9), (0.5, 0.4), (0.2, 0.85)]   # cóncavo
        out = {}
        osmmap.split_ring(ring, 4, out)
        total = sum(abs(osmmap.ring_area(r)) for rs in out.values() for r in rs)
        self.assertAlmostEqual(total, abs(osmmap.ring_area(ring)), 9)
        for (tx, ty), rs in out.items():
            for r in rs:
                for x, y in r:
                    self.assertTrue(tx / 4 - 1e-12 <= x <= (tx + 1) / 4 + 1e-12)
                    self.assertTrue(ty / 4 - 1e-12 <= y <= (ty + 1) / 4 + 1e-12)


class BuildTests(unittest.TestCase):
    def test_build_and_load(self):
        # una isla grande con un lago (anilla interior) y un islote que desaparece en zoom bajo
        big = [circle(-3.7, 40.4, 12), circle(-3.7, 40.4, 3)]
        tiny = [circle(150, -30, 0.01, 12)]
        shp = shp_bytes([big, tiny])
        with tempfile.TemporaryDirectory() as d:
            z = Path(d) / "land.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("land-polygons/land_polygons.shp", shp)
            raw = osmmap.read_land_zip(z)
            self.assertEqual(sum(1 for _ in osmmap.read_shp(raw)), 2)
            places = osmmap.parse_places({"elements": [
                {"type": "node", "lat": 40.4, "lon": -3.7, "tags": {"name": "Madrid", "name:es": "Madrid", "place": "city",
                                                                   "capital": "yes", "population": "3,300,000"}},
                {"type": "node", "lat": 40, "lon": -4, "tags": {"name": "España", "place": "country",
                                                               "ISO3166-1:alpha2": "es"}},
                {"type": "node", "lat": 1, "lon": 1, "tags": {"place": "city"}}]})
            self.assertEqual([p["name"] for p in places], ["España", "Madrid"])
            self.assertEqual(places[0]["cc"], "ES")
            self.assertEqual(places[1]["pop"], 3_300_000)
            out = Path(d) / "map.bin"
            steps = []
            res = osmmap.build_basemap(raw, places, out, progress=lambda f, m: steps.append(f))
            self.assertEqual(steps[-1], 1.0)
            bm = osmmap.Basemap(out)
            self.assertEqual(len(bm.places), 2)
            self.assertEqual(bm.head["attribution"], osmmap.ATTRIBUTION)
            pts = res["points"]
            self.assertLess(pts[2], pts[8])                       # menos detalle a zoom bajo
            # zoom 2: una tesela, el islote desaparece; anillas = isla + lago
            rings0 = bm.tile(0, 0, 0)
            self.assertEqual(len(rings0), 2)
            # zoom 8: la isla está troceada en varias teselas y el islote sigue existiendo
            g = bm.lods[3]["grid"]
            tx, ty = (int(c * g) for c in osmmap.lonlat_to_norm(150, -30))
            self.assertTrue(bm.tile(3, tx, ty))
            vis = list(bm.visible(3, *osmmap.lonlat_to_norm(-16, 53), *osmmap.lonlat_to_norm(9, 28)))
            self.assertGreater(len(vis), 4)
            # coordenadas cuantizadas dentro de su tesela
            for tx, ty, rings in vis:
                for r in rings:
                    for i in range(0, len(r), 2):
                        self.assertTrue(tx * bm.q // g - 1 <= r[i] <= (tx + 1) * bm.q // g + 1)

    def test_load_missing_or_corrupt(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(osmmap.load(Path(d) / "no.bin"))
            p = Path(d) / "bad.bin"
            p.write_bytes(b"basura")
            self.assertIsNone(osmmap.load(p))


class RouteTests(unittest.TestCase):
    ENV_TOR = {"tor": {"socks": [9050]}, "interfaces": [{"name": "enp3s0", "kind": "ethernet"}], "egress": {"ipv4": "enp3s0"}}
    ENV_VPN = {"tor": {"socks": []}, "interfaces": [{"name": "wg0", "kind": "wireguard"}], "egress": {"ipv4": "wg0"}}
    ENV_NONE = {"tor": {"socks": []}, "interfaces": [{"name": "enp3s0", "kind": "ethernet"}], "egress": {"ipv4": "enp3s0"}}

    def test_auto_prefers_tor_then_vpn_never_direct(self):
        self.assertEqual(osmmap.choose_route("auto", self.ENV_TOR), ("tor", ("127.0.0.1", 9050)))
        self.assertEqual(osmmap.choose_route("auto", self.ENV_VPN), ("vpn", None))
        with self.assertRaises(OSError):
            osmmap.choose_route("auto", self.ENV_NONE)
        with self.assertRaises(OSError):
            osmmap.choose_route("tor", self.ENV_VPN)
        self.assertEqual(osmmap.choose_route("direct", self.ENV_NONE), ("direct", None))

    def test_offline_build_needs_no_route(self):
        shp = shp_bytes([[circle(0, 0, 5)]])
        with tempfile.TemporaryDirectory() as d:
            z = Path(d) / "land.zip"
            with zipfile.ZipFile(z, "w") as zf:
                zf.writestr("x.shp", shp)
            import os
            old = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = d
            try:
                res = osmmap.download_and_build("auto", self.ENV_NONE, land_file=z, places=False)
            finally:
                if old is None:
                    os.environ.pop("XDG_DATA_HOME")
                else:
                    os.environ["XDG_DATA_HOME"] = old
            self.assertIsNone(res["route"])
            self.assertEqual(res["downloaded"], [])
            self.assertTrue(Path(res["path"]).exists())
            self.assertTrue(res["path"].startswith(d))


if __name__ == "__main__":
    unittest.main()


class CoastTests(unittest.TestCase):
    def test_coast_skips_tile_seams(self):
        shp = shp_bytes([[circle(0, 0, 20, 200)]])
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "m.bin"
            osmmap.build_basemap(shp, None, out)
            bm = osmmap.Basemap(out)
            g = bm.lods[1]["grid"]
            step = bm.q // g
            n_lines = 0
            for tx in range(g):
                for ty in range(g):
                    for line in bm.coast(1, tx, ty):
                        n_lines += 1
                        for i in range(0, len(line) - 2, 2):
                            x0, y0, x1, y1 = line[i], line[i + 1], line[i + 2], line[i + 3]
                            on_seam = (x0 == x1 and x0 % step == 0) or (y0 == y1 and y0 % step == 0)
                            self.assertFalse(on_seam)
            self.assertGreaterEqual(n_lines, 4)          # el círculo cruza 4 teselas en el centro


class PlacesFetchTests(unittest.TestCase):
    def test_retries_and_partial_failure(self):
        import json as _json
        from unittest import mock
        calls = []

        class FakeResp:
            def __init__(self, status, body):
                self.status, self._b = status, body

            def read(self):
                return self._b

        class FakeConn:
            def __init__(self, host, socks, timeout):
                self.host = host

            def request(self, method, path, body=None, headers=None):
                self.q = body.decode()

            def getresponse(self):
                calls.append((self.host, self.q))
                if "country" in self.q:
                    return FakeResp(200, _json.dumps({"elements": [{"id": 1, "lat": 0, "lon": 0,
                                                                   "tags": {"place": "country", "name": "X"}}]}).encode())
                if "capital" in self.q and len([c for c in calls if "capital" in c[1]]) >= 2:
                    return FakeResp(200, b'{"elements": [{"id": 2, "lat": 1, "lon": 1, "tags": {"place": "city", "capital": "yes", "name": "Y"}}]}')
                return FakeResp(504, b"busy")

            def close(self):
                pass

        with mock.patch.object(osmmap, "_Conn", FakeConn):
            doc, err = osmmap.fetch_places(None, tries=2, wait=0)
        self.assertEqual(sorted(e["id"] for e in doc["elements"]), [1, 2])   # capitales: 2.º servidor
        self.assertIn("faltan ciudades", err)
        self.assertNotIn("capitales", err.split("(")[0])


class BundledTests(unittest.TestCase):
    def test_bundled_map_ships_with_app(self):
        self.assertTrue(osmmap.BUNDLED.exists())
        bm = osmmap.Basemap(osmmap.BUNDLED)
        self.assertEqual(bm.head["attribution"], osmmap.ATTRIBUTION)
        self.assertGreater(len(bm.places), 1000)
        self.assertEqual([l["z"] for l in bm.lods], [z for z, _ in osmmap.LODS])
        self.assertTrue((osmmap.BUNDLED.parent / "OSM-ATTRIBUTION.txt").exists())

    def test_newest_map_wins(self):
        import os
        with tempfile.TemporaryDirectory() as d:
            old = os.environ.get("XDG_DATA_HOME")
            os.environ["XDG_DATA_HOME"] = d
            try:
                self.assertEqual(osmmap.active_path(), osmmap.BUNDLED)      # sin mapa propio: el incorporado
                user = osmmap.basemap_path()
                osmmap.build_basemap(shp_bytes([[circle(0, 0, 5)]]), None, user)
                self.assertEqual(osmmap.active_path(), user)                # recién generado: más nuevo
                self.assertFalse(osmmap.status()["bundled"])
            finally:
                if old is None:
                    os.environ.pop("XDG_DATA_HOME")
                else:
                    os.environ["XDG_DATA_HOME"] = old


class WorldmapOSMTests(unittest.TestCase):
    def test_raster_scanline(self):
        from opsectools import worldmap
        square = [[(-10, -10), (10, -10), (10, 10), (-10, 10)]]
        hole = [[(-5, -5), (5, -5), (5, 5), (-5, 5)]]
        rows = int(worldmap.LAT_TOP - worldmap.LAT_BOTTOM)             # celdas de 1°
        g = worldmap.raster_rings(square + hole, 360, rows)
        lat_row = lambda lat: int(worldmap.LAT_TOP - lat)  # noqa: E731
        col = lambda lon: int(lon + 180)  # noqa: E731
        self.assertTrue(g[lat_row(-8)][col(-8)])          # tierra
        self.assertFalse(g[lat_row(0)][col(0)])           # lago (anilla interior)
        self.assertFalse(g[lat_row(40)][col(100)])        # mar

    def test_ascii_and_json_use_osm(self):
        from opsectools import worldmap
        j = worldmap.as_json()
        self.assertIn("rings", j)
        self.assertEqual(j["attribution"], osmmap.ATTRIBUTION)
        rows = worldmap.ascii_map(120, 40, [(40.4, -3.7, "H")])
        self.assertTrue(any("H" in r for r in rows))
        land = sum(r.count("·") for r in rows) / (120 * 40)
        self.assertTrue(0.2 < land < 0.45, land)          # ~30 % del mapa recortado es tierra
