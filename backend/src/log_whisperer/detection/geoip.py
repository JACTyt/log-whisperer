"""IP geolocation via an MMDB file (DB-IP Lite by default, MaxMind GeoLite2 compatible)."""

import ipaddress
import logging
import math
from pathlib import Path
from typing import Protocol

log = logging.getLogger(__name__)


class GeoLookup(Protocol):
    def lookup(self, ip: str) -> tuple[float, float, str] | None: ...


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def haversine_km(a: tuple[float, float], b: tuple[float, float]) -> float:
    lat1, lon1, lat2, lon2 = map(math.radians, (*a, *b))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 2 * 6371.0 * math.asin(math.sqrt(h))


class GeoIP:
    def __init__(self, reader):
        self._reader = reader

    @classmethod
    def open(cls, path: Path) -> "GeoIP | None":
        if not Path(path).is_file():
            log.warning("GeoIP database %s not found; impossible-travel detection disabled "
                        "(run scripts/fetch_geoip.py)", path)
            return None
        import maxminddb

        return cls(maxminddb.open_database(str(path)))

    def lookup(self, ip: str) -> tuple[float, float, str] | None:
        if not is_public(ip):
            return None
        rec = self._reader.get(ip)
        if not rec or "location" not in rec:
            return None
        loc = rec["location"]
        country = (rec.get("country") or {}).get("iso_code", "??")
        return loc["latitude"], loc["longitude"], country
