"""Pick the events an incident narrative may draw on: detection events plus nearby related events."""

from collections.abc import Sequence
from datetime import timedelta

from log_whisperer.incidents.grouping import NOISE_HOSTS, NOISE_IPS, NOISE_USERS
from log_whisperer.models import Detection, Incident
from log_whisperer.store import Store

MARGIN = timedelta(hours=1)
CANDIDATE_LIMIT = 50_000


def _distances(n: int, positions: list[int]) -> list[int]:
    """Distance of every index in range(n) to the nearest position."""
    inf = n + 1
    dist = [inf] * n
    for p in positions:
        dist[p] = 0
    for i in range(1, n):
        dist[i] = min(dist[i], dist[i - 1] + 1)
    for i in range(n - 2, -1, -1):
        dist[i] = min(dist[i], dist[i + 1] + 1)
    return dist


def select_context(store: Store, incident: Incident, detections: Sequence[Detection],
                   neighbors: int, max_events: int) -> list[str]:
    det_ids = {e for d in detections if d.detection_id in set(incident.detection_ids) for e in d.event_ids}
    hosts = [h.lower() for h in incident.hosts if h.lower() not in NOISE_HOSTS]
    users = [u for u in incident.users if u not in NOISE_USERS and not u.endswith("$")]
    ips = [ip for ip in incident.src_ips if ip not in NOISE_IPS]

    candidates = []
    if hosts or users or ips:
        candidates = store.query_events(
            "ts BETWEEN ? AND ? AND (lower(host) IN (SELECT unnest(?)) OR \"user\" IN (SELECT unnest(?)) "
            "OR src_ip IN (SELECT unnest(?)))",
            [incident.ts_start - MARGIN, incident.ts_end + MARGIN, hosts, users, ips],
            limit=CANDIDATE_LIMIT,
        )
    positions = [i for i, e in enumerate(candidates) if e.event_id in det_ids]
    dist = _distances(len(candidates), positions) if positions else [len(candidates) + 1] * len(candidates)
    near = sorted((dist[i], i) for i, e in enumerate(candidates)
                  if e.event_id not in det_ids and dist[i] <= neighbors)
    budget = max(0, max_events - len(det_ids))
    keep = {candidates[i].event_id for _, i in near[:budget]} | det_ids
    return [e.event_id for e in store.events_by_ids(sorted(keep))]
