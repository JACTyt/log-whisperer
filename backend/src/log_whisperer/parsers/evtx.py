"""Windows EVTX parser built on pyevtx-rs (`evtx` package)."""

import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from evtx import PyEvtxParser

from log_whisperer.models import Event
from log_whisperer.parsers.windows_fields import add_sigma_aliases, derive

EVTX_MAGIC = b"ElfFile\x00"
_FRACTION = re.compile(r"(\.\d{6})\d+")


def parse_windows_ts(value: str) -> datetime:
    """Parse `2020-09-09T13:18:23.6279520Z` (any fraction length, optional ` UTC`)."""
    v = _FRACTION.sub(r"\1", value.removesuffix(" UTC").strip())
    return datetime.fromisoformat(v)


def _attr(node: Any, name: str) -> Any:
    return node.get("#attributes", {}).get(name) if isinstance(node, dict) else None


def _flatten_data(data: dict[str, Any], out: dict[str, Any]) -> None:
    for key, value in data.items():
        if key == "#attributes":
            continue
        if key == "Data":
            items = value.get("#text") if isinstance(value, dict) else value
            if not isinstance(items, list):
                items = [items]
            for i, item in enumerate(items):
                out[f"Data_{i}"] = item
        else:
            out[key] = value


def flatten_record(event: dict[str, Any]) -> dict[str, Any]:
    """Map a pyevtx-rs `Event` object to a flat dict of native Windows field names."""
    system = event.get("System") or {}
    eid = system.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    out: dict[str, Any] = {
        "EventID": None if eid is None else str(eid),
        "Channel": system.get("Channel"),
        "Computer": system.get("Computer"),
        "Provider_Name": _attr(system.get("Provider"), "Name"),
        "TimeCreated": _attr(system.get("TimeCreated"), "SystemTime"),
        "EventRecordID": system.get("EventRecordID"),
        "Level": system.get("Level"),
        "Task": system.get("Task"),
        "Opcode": system.get("Opcode"),
        "Keywords": system.get("Keywords"),
        "Security_UserID": _attr(system.get("Security"), "UserID"),
    }
    if isinstance(event.get("EventData"), dict):
        _flatten_data(event["EventData"], out)
    user_data = event.get("UserData")
    if isinstance(user_data, dict):
        for inner in user_data.values():
            if isinstance(inner, dict):
                _flatten_data(inner, out)
    return out


def parse_record(record: dict[str, Any], source_file: str) -> Event:
    """Convert one item of `PyEvtxParser.records_json()` into an Event."""
    event = json.loads(record["data"])["Event"]
    fields = add_sigma_aliases(flatten_record(event))
    ts_raw = fields["TimeCreated"] or record["timestamp"]
    return Event(
        ts=parse_windows_ts(ts_raw),
        source_type="evtx",
        source_file=source_file,
        record_ref=f"record:{record['event_record_id']}",
        raw=record["data"],
        fields=fields,
        **derive(fields),
    )


class EvtxParser:
    source_type = "evtx"

    def can_parse(self, path: Path) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(len(EVTX_MAGIC)) == EVTX_MAGIC
        except OSError:
            return False

    def parse(self, path: Path) -> Iterator[Event]:
        source = str(Path(path).resolve())
        for record in PyEvtxParser(str(path)).records_json():
            yield parse_record(record, source)
