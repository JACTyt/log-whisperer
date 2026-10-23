"""Core domain models shared by parsers, store, detection and narrative layers."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, model_validator

from log_whisperer.ids import make_event_id, short_hash

SEVERITIES = ["informational", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 2


class Event(BaseModel):
    """One normalized log record (DESIGN §5.1)."""

    event_id: str = ""
    seq: int | None = None
    ts: datetime
    source_type: str
    channel: str | None = None
    host: str | None = None
    user: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    process: str | None = None
    command_line: str | None = None
    action: str | None = None
    outcome: str | None = None
    event_code: str | None = None
    source_file: str
    record_ref: str
    raw: str
    fields: dict[str, Any] = {}

    @model_validator(mode="after")
    def _normalize(self) -> "Event":
        if not self.event_id:
            self.event_id = make_event_id(self.source_file, self.record_ref)
        if self.ts.tzinfo is not None:
            self.ts = self.ts.astimezone(timezone.utc).replace(tzinfo=None)
        return self


class Detection(BaseModel):
    """A rule or heuristic match over one or more events (DESIGN §5.2)."""

    detection_id: str = ""
    rule_id: str
    rule_title: str
    rule_source: str  # sigma | heuristic
    severity: str = "medium"
    techniques: list[str] = []
    event_ids: list[str]
    ts_first: datetime
    ts_last: datetime
    hosts: list[str] = []
    users: list[str] = []
    src_ips: list[str] = []

    @model_validator(mode="after")
    def _fill_id(self) -> "Detection":
        if not self.detection_id:
            self.detection_id = short_hash(self.rule_id, ",".join(sorted(self.event_ids)))
        return self


class Incident(BaseModel):
    """Detections linked by shared entities and time (DESIGN §5.3)."""

    incident_id: str
    title: str
    ts_start: datetime
    ts_end: datetime
    severity: str
    hosts: list[str] = []
    users: list[str] = []
    src_ips: list[str] = []
    techniques: list[str] = []
    detection_ids: list[str] = []
    context_event_ids: list[str] = []
    updated_at: datetime
