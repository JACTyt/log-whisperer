"""Same user, successful logons from places too far apart for the time between them."""

import logging
from collections import defaultdict
from datetime import timedelta

from log_whisperer.detection.geoip import GeoLookup, haversine_km
from log_whisperer.detection.heuristics.common import candidates, has_new, make_detection
from log_whisperer.models import Detection
from log_whisperer.store import Store

log = logging.getLogger(__name__)
MIN_KM = 500  # ignore GeoIP jitter between nearby cities


class ImpossibleTravelDetector:
    rule_id = "heuristic.impossible_travel"
    title = "Impossible travel"

    def __init__(self, geoip: GeoLookup | None, kmh: float = 900):
        self.geoip = geoip
        self.kmh = kmh

    def run(self, store: Store, since_seq: int | None = None) -> list[Detection]:
        if self.geoip is None:
            return []
        events = candidates(store, "action IN ('logon', 'ssh_auth') AND outcome = 'success' "
                            "AND \"user\" IS NOT NULL AND src_ip IS NOT NULL", [], since_seq, timedelta(days=1))
        by_user = defaultdict(list)
        for e in events:
            if (geo := self.geoip.lookup(e.src_ip)) is not None:
                by_user[e.user].append((e, geo))
        out = []
        for user, seq in by_user.items():
            for (a, ga), (b, gb) in zip(seq, seq[1:]):
                km = haversine_km(ga[:2], gb[:2])
                if km < MIN_KM:
                    continue
                hours = max((b.ts - a.ts).total_seconds() / 3600, 1 / 60)
                speed = km / hours
                if speed > self.kmh and has_new([a, b], since_seq):
                    out.append(make_detection(
                        self.rule_id,
                        f"{self.title}: {user} {ga[2]}→{gb[2]} ({km:.0f} km in {hours * 60:.0f} min)",
                        "high", ["T1078"], [a, b], key=user,
                    ))
        return out
