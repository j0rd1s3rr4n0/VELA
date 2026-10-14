"""Geolocalización 100 % local. Nunca envía IPs a terceros.

Fuentes por orden de preferencia:
  1. Base .mmdb (GeoLite2/DB-IP) si existe y está instalado `geoip2` → ciudad, coordenadas, ASN.
  2. Base `geoip`/`geoip6` que distribuye Tor → solo país.
  3. Callback opcional (p. ej. `GETINFO ip-to-country` de Tor).
Las coordenadas a nivel de país salen de /usr/share/zoneinfo/zone1970.tab (ubicación de la
zona horaria principal del país): son una ESTIMACIÓN, no la ubicación física del servidor.
"""

from __future__ import annotations

import bisect
import ipaddress
import re
import threading
from pathlib import Path

ZONE_TAB = Path("/usr/share/zoneinfo/zone1970.tab")
ISO_TAB = Path("/usr/share/zoneinfo/iso3166.tab")

# Respaldo mínimo si el sistema no tiene zoneinfo.
FALLBACK_COORDS = {
    "US": (39.8, -98.6), "CA": (56.1, -106.3), "MX": (23.6, -102.5), "BR": (-14.2, -51.9),
    "AR": (-38.4, -63.6), "GB": (54.0, -2.0), "IE": (53.4, -8.2), "FR": (46.2, 2.2), "DE": (51.2, 10.4),
    "NL": (52.1, 5.3), "BE": (50.5, 4.5), "LU": (49.8, 6.1), "CH": (46.8, 8.2), "AT": (47.5, 14.6),
    "ES": (40.5, -3.7), "PT": (39.4, -8.2), "IT": (41.9, 12.6), "SE": (60.1, 18.6), "NO": (60.5, 8.5),
    "FI": (61.9, 25.7), "DK": (56.3, 9.5), "IS": (64.9, -19.0), "PL": (51.9, 19.1), "CZ": (49.8, 15.5),
    "RO": (45.9, 24.9), "BG": (42.7, 25.5), "GR": (39.1, 21.8), "UA": (48.4, 31.2), "RU": (61.5, 105.3),
    "TR": (38.9, 35.2), "IL": (31.0, 34.9), "AE": (23.4, 53.8), "IN": (20.6, 79.0), "CN": (35.9, 104.2),
    "JP": (36.2, 138.3), "KR": (35.9, 127.8), "SG": (1.35, 103.8), "HK": (22.3, 114.2), "AU": (-25.3, 133.8),
    "NZ": (-40.9, 174.9), "ZA": (-30.6, 22.9), "EG": (26.8, 30.8), "MD": (47.4, 28.4), "LV": (56.9, 24.6),
    "LT": (55.2, 23.9), "EE": (58.6, 25.0), "HU": (47.2, 19.5), "SK": (48.7, 19.7), "RS": (44.0, 21.0),
}


def _parse_iso6709(coord: str) -> tuple[float, float] | None:
    m = re.fullmatch(r"([+-])(\d{2})(\d{2})(\d{2})?([+-])(\d{3})(\d{2})(\d{2})?", coord)
    if not m:
        return None
    lat = int(m.group(2)) + int(m.group(3)) / 60 + int(m.group(4) or 0) / 3600
    lon = int(m.group(6)) + int(m.group(7)) / 60 + int(m.group(8) or 0) / 3600
    return (-lat if m.group(1) == "-" else lat, -lon if m.group(5) == "-" else lon)


ZONE_TAB_LEGACY = Path("/usr/share/zoneinfo/zone.tab")


def load_country_coords(zone_tab: Path = ZONE_TAB) -> dict[str, tuple[float, float]]:
    """zone.tab tiene una zona por país; zone1970.tab agrupa países (p. ej. 'DE,DK,NO,SE,SJ' →
    Europe/Berlin), así que de este último solo se usan las filas de un único país."""
    coords = dict(FALLBACK_COORDS)
    seen = set(FALLBACK_COORDS)        # los centroides manuales son mejores
    for path, single_only in ((ZONE_TAB_LEGACY, False), (zone_tab, True)):
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            codes = parts[0].split(",")
            if single_only and len(codes) > 1:
                continue
            pos = _parse_iso6709(parts[1])
            if pos and codes[0] not in seen:   # primera zona listada para el país
                seen.add(codes[0])
                coords[codes[0]] = pos
    return coords


def load_country_names(iso_tab: Path = ISO_TAB) -> dict[str, str]:
    names = {}
    try:
        for line in iso_tab.read_text().splitlines():
            if line and not line.startswith("#") and "\t" in line:
                cc, name = line.split("\t", 1)
                names[cc] = name.strip()
    except OSError:
        pass
    return names


_LOCAL_NAMES: dict = {}


def country_label(cc: str | None, fallback: str | None = None) -> str | None:
    """Nombre del país en el idioma de la interfaz (nombres de OpenStreetMap del mapa incorporado).
    Los países sin código ISO en OSM se emparejan por su nombre inglés con la tabla ISO del sistema."""
    if not cc:
        return fallback
    from . import i18n, osmmap
    lang = i18n.language()
    table = _LOCAL_NAMES.get(lang)
    if table is None:
        table = {}
        bm = osmmap.load()
        if bm is not None:
            en2cc = {v.lower(): k for k, v in load_country_names().items()}
            for p in bm.places:
                if p.get("kind") != "country":
                    continue
                names = p.get("names") or {}
                code = p.get("cc") or en2cc.get((names.get("en") or "").lower())
                if code and names.get(lang) and code not in table:
                    table[code] = names[lang]
        _LOCAL_NAMES[lang] = table
    return table.get(cc.upper()) or fallback or cc


class _RangeDB:
    def __init__(self):
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.ccs: list[str] = []

    def add(self, start: int, end: int, cc: str):
        self.starts.append(start)
        self.ends.append(end)
        self.ccs.append(cc)

    def finish(self):
        order = sorted(range(len(self.starts)), key=self.starts.__getitem__)
        self.starts = [self.starts[i] for i in order]
        self.ends = [self.ends[i] for i in order]
        self.ccs = [self.ccs[i] for i in order]

    def get(self, value: int) -> str | None:
        i = bisect.bisect_right(self.starts, value) - 1
        if i >= 0 and value <= self.ends[i]:
            return self.ccs[i]
        return None


class Geo:
    def __init__(self, tor_geoip: str | None = "/usr/share/tor/geoip", tor_geoip6: str | None = "/usr/share/tor/geoip6",
                 mmdb_city: str | None = None, mmdb_asn: str | None = None, fallback=None):
        self.tor_geoip, self.tor_geoip6 = tor_geoip, tor_geoip6
        self.fallback = fallback
        self.coords = load_country_coords()
        self.names = load_country_names()
        self._v4: _RangeDB | None = None
        self._v6: _RangeDB | None = None
        self._lock = threading.Lock()
        self._cache: dict[str, dict] = {}
        self._city = self._asn = None
        try:  # opcional
            import geoip2.database  # type: ignore
            if mmdb_city and Path(mmdb_city).exists():
                self._city = geoip2.database.Reader(mmdb_city)
            if mmdb_asn and Path(mmdb_asn).exists():
                self._asn = geoip2.database.Reader(mmdb_asn)
        except ImportError:
            pass

    @property
    def sources(self) -> list[str]:
        s = []
        if self._city:
            s.append("mmdb-city")
        if self._asn:
            s.append("mmdb-asn")
        if self.tor_geoip and Path(self.tor_geoip).exists():
            s.append("tor-geoip")
        return s

    def _load(self):
        with self._lock:
            if self._v4 is not None:
                return
            v4, v6 = _RangeDB(), _RangeDB()
            for path, db, is6 in ((self.tor_geoip, v4, False), (self.tor_geoip6, v6, True)):
                if not path:
                    continue
                try:
                    fh = open(path)
                except OSError:
                    continue
                with fh:
                    for line in fh:
                        if line.startswith("#"):
                            continue
                        parts = line.strip().split(",")
                        if len(parts) != 3:
                            continue
                        try:
                            if is6:
                                a, b = int(ipaddress.IPv6Address(parts[0])), int(ipaddress.IPv6Address(parts[1]))
                            else:
                                a, b = int(parts[0]), int(parts[1])
                        except ValueError:
                            continue
                        db.add(a, b, parts[2].upper())
                db.finish()
            self._v4, self._v6 = v4, v6

    def country_info(self, cc: str | None) -> dict:
        if not cc:
            return {"country": None, "country_name": None, "lat": None, "lon": None}
        lat, lon = self.coords.get(cc, (None, None))
        return {"country": cc, "country_name": country_label(cc, self.names.get(cc, cc)), "lat": lat, "lon": lon}

    def lookup(self, ip: str | None) -> dict:
        if not ip:
            return {"ip": ip, "scope": "unknown", "country": None}
        if ip in self._cache:
            return self._cache[ip]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {"ip": ip, "scope": "invalid", "country": None}
        if not addr.is_global:
            res = {"ip": ip, "scope": "local", "country": None, "source": None, "precision": None}
            self._cache[ip] = res
            return res
        res = {"ip": ip, "scope": "global", "asn": None, "org": None, "city": None}
        if self._city:
            try:
                r = self._city.city(ip)
                res.update(self.country_info(r.country.iso_code))
                if r.location.latitude is not None:
                    res.update(lat=r.location.latitude, lon=r.location.longitude, city=r.city.name)
                res.update(source="mmdb", precision="ciudad" if r.city.name else "país")
            except Exception:
                pass
        if self._asn:
            try:
                a = self._asn.asn(ip)
                res.update(asn=a.autonomous_system_number, org=a.autonomous_system_organization)
            except Exception:
                pass
        if not res.get("country"):
            self._load()
            db = self._v4 if addr.version == 4 else self._v6
            cc = db.get(int(addr)) if db else None
            if not cc and self.fallback:
                try:
                    cc = self.fallback(ip)
                except Exception:
                    cc = None
            if cc and cc not in ("??", "--"):
                res.update(self.country_info(cc))
                res.update(source="tor-geoip" if db and db.get(int(addr)) else "fallback", precision="país")
            else:
                res.update(self.country_info(None), source=None, precision=None)
        if len(self._cache) > 5000:
            self._cache.clear()
        self._cache[ip] = res
        return res
