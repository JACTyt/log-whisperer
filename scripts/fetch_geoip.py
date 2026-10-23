"""Download the free DB-IP City Lite database (CC-BY 4.0, https://db-ip.com) for impossible-travel detection.

Usage: python scripts/fetch_geoip.py [--dest backend/data/geoip/dbip-city-lite.mmdb]
"""

import argparse
import gzip
import shutil
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

URL = "https://download.db-ip.com/free/dbip-city-lite-{y:04d}-{m:02d}.mmdb.gz"


def _months_back(today: date, n: int):
    y, m = today.year, today.month
    for _ in range(n):
        yield y, m
        y, m = (y, m - 1) if m > 1 else (y - 1, 12)


def fetch(dest: Path) -> str:
    dest.parent.mkdir(parents=True, exist_ok=True)
    for y, m in _months_back(date.today(), 3):
        url = URL.format(y=y, m=m)
        req = urllib.request.Request(url, headers={"User-Agent": "log-whisperer/0.1 (+https://github.com/JACTyt)"})
        try:
            with urllib.request.urlopen(req, timeout=120) as r, gzip.open(r) as gz, open(dest, "wb") as out:
                shutil.copyfileobj(gz, out)
            return url
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise
    raise SystemExit("no DB-IP Lite release found for the last 3 months")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dest", type=Path, default=Path(__file__).parents[1] / "backend/data/geoip/dbip-city-lite.mmdb")
    args = ap.parse_args()
    print(f"downloaded {fetch(args.dest)} -> {args.dest}")
