"""Group detections into incidents: shared entity + time proximity, via union-find (DESIGN §8)."""

from collections import defaultdict
from collections.abc import Sequence
from datetime import datetime, timedelta

from log_whisperer.detection.base import uniq
from log_whisperer.ids import short_hash
from log_whisperer.models import Detection, Incident, severity_rank

NOISE_USERS = {"system", "local service", "network service", "anonymous logon", "-", "dwm-1", "umfd-0"}
NOISE_IPS = {"127.0.0.1", "::1", "localhost", "-", "0.0.0.0"}
NOISE_HOSTS = {"localhost", "-"}


def linking_entities(d: Detection) -> set[tuple[str, str]]:
    out = set()
    for h in d.hosts:
        if h.lower() not in NOISE_HOSTS:
            out.add(("host", h.lower()))
    for u in d.users:
        if u.lower() not in NOISE_USERS and not u.endswith("$"):
            out.add(("user", u.lower()))
    for ip in d.src_ips:
        if ip not in NOISE_IPS:
            out.add(("ip", ip))
    return out


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def group_detections(dets: Sequence[Detection], gap: timedelta) -> list[Incident]:
    dets = sorted(dets, key=lambda d: (d.ts_first, d.detection_id))
    uf = _UnionFind(len(dets))
    by_entity: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, d in enumerate(dets):
        for ent in linking_entities(d):
            by_entity[ent].append(i)
    for idxs in by_entity.values():  # already sorted by ts_first
        prev, reach = idxs[0], dets[idxs[0]].ts_last
        for i in idxs[1:]:
            if dets[i].ts_first <= reach + gap:
                uf.union(prev, i)
            reach = max(reach, dets[i].ts_last)
            prev = i
    # Detections citing the same log line describe the same activity: always one incident.
    first_with_event: dict[str, int] = {}
    for i, d in enumerate(dets):
        for event_id in d.event_ids:
            if event_id in first_with_event:
                uf.union(first_with_event[event_id], i)
            else:
                first_with_event[event_id] = i

    groups: dict[int, list[Detection]] = defaultdict(list)
    for i, d in enumerate(dets):
        groups[uf.find(i)].append(d)
    incidents = [_build(members) for members in groups.values()]
    return sorted(incidents, key=lambda inc: (inc.ts_start, inc.incident_id))


def _build(members: list[Detection]) -> Incident:
    top = max(members, key=lambda d: (severity_rank(d.severity), -d.ts_first.timestamp()))
    extra = len({d.rule_title for d in members}) - 1
    return Incident(
        incident_id=short_hash("incident", members[0].detection_id),
        title=top.rule_title + (f" (+{extra} more)" if extra else ""),
        ts_start=min(d.ts_first for d in members),
        ts_end=max(d.ts_last for d in members),
        severity=top.severity,
        hosts=uniq(h for d in members for h in d.hosts),
        users=uniq(u for d in members for u in d.users),
        src_ips=uniq(ip for d in members for ip in d.src_ips),
        techniques=uniq(t for d in members for t in d.techniques),
        detection_ids=[d.detection_id for d in members],
        updated_at=datetime.now().replace(microsecond=0),
    )
