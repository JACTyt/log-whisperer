"""Human-readable names for where log lines came from."""

from collections.abc import Iterable

from pydantic import BaseModel

from log_whisperer.models import Event

KINDS = {
    "evtx": "Windows event log (EVTX)",
    "winjson": "Windows events (JSON export)",
    "authlog": "Linux auth log",
    "web": "Web server access log",
    "syslog": "Syslog (live)",
}


class SourceSummary(BaseModel):
    name: str  # file name as a person knows it, e.g. "auth.log"
    source_file: str  # full stored path or live source URI
    source_type: str
    kind: str
    events: int
    event_ids: list[str]


def display_name(source_file: str) -> str:
    """`/data/uploads/ab12/auth.log` -> `auth.log`; live sources keep their URI (`syslog://10.0.0.5`)."""
    if "://" in source_file:
        scheme, rest = source_file.split("://", 1)
        return source_file if scheme == "syslog" else rest.replace("\\", "/").rsplit("/", 1)[-1]
    return source_file.replace("\\", "/").rsplit("/", 1)[-1]


def summarize_sources(events: Iterable[Event]) -> list[SourceSummary]:
    """One entry per source file, most lines first."""
    groups: dict[str, list[Event]] = {}
    for e in events:
        groups.setdefault(e.source_file, []).append(e)
    out = [
        SourceSummary(name=display_name(path), source_file=path, source_type=evs[0].source_type,
                      kind=KINDS.get(evs[0].source_type, evs[0].source_type), events=len(evs),
                      event_ids=[e.event_id for e in evs])
        for path, evs in groups.items()
    ]
    return sorted(out, key=lambda s: (-s.events, s.name))
