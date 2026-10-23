"""Windows events exported as JSON lines (Security-Datasets / Mordor NXLog or Winlogbeat shape)."""

import json
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from itertools import islice
from pathlib import Path
from typing import Any

from log_whisperer.models import Event
from log_whisperer.parsers.textio import TextLineParser, open_text
from log_whisperer.parsers.windows_fields import add_sigma_aliases, derive

# Collector metadata that duplicates the event or bloats storage.
_DROP = {"Message", "tags", "@version", "port", "host", "EventReceivedTime", "SourceModuleName",
         "SourceModuleType", "message", "agent", "ecs", "log", "event"}
# Collector-side timestamps, in order of preference, used when Sysmon's UtcTime is absent.
_COLLECTOR_TS = ("@timestamp", "TimeCreated", "EventTime")
CALIBRATION_SAMPLE = 5000
OFFSET_STEP = timedelta(minutes=15)


def _parse_ts(value: str) -> datetime:
    """-> naive UTC. Values without a zone are taken as UTC."""
    v = value.strip().replace(" ", "T", 1)
    dt = datetime.fromisoformat(v.replace("Z", "+00:00") if v.endswith("Z") else v)
    return dt.astimezone(timezone.utc).replace(tzinfo=None) if dt.tzinfo else dt


def _collector_ts(obj: dict[str, Any]) -> datetime | None:
    for key in _COLLECTOR_TS:
        if obj.get(key):
            try:
                return _parse_ts(str(obj[key]))
            except ValueError:
                return None
    return None


def normalize_record(obj: dict[str, Any]) -> dict[str, Any]:
    """Return native Windows field names for either export shape."""
    if isinstance(obj.get("winlog"), dict):
        w = obj["winlog"]
        out = {k: v for k, v in (w.get("event_data") or {}).items()}
        out.update(w.get("user_data") or {})
        out["EventID"] = w.get("event_id")
        out["Channel"] = w.get("channel")
        out["Computer"] = w.get("computer_name")
        out["Provider_Name"] = w.get("provider_name")
        out["EventRecordID"] = w.get("record_id")
        out["@timestamp"] = obj.get("@timestamp")
    else:
        out = {k: v for k, v in obj.items() if k not in _DROP}
        out["Computer"] = obj.get("Computer") or obj.get("Hostname")
        if "SourceName" in obj:
            out["Provider_Name"] = obj["SourceName"]
        if "RecordNumber" in obj:
            out["EventRecordID"] = obj["RecordNumber"]
    if out.get("EventID") is not None:
        out["EventID"] = str(out["EventID"])
    return out


def parse_line(line: str, line_no: int, source_file: str, clock_offset: timedelta | None = None) -> Event | None:
    """`clock_offset` corrects collector timestamps (UtcTime - collector time) measured for the file."""
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict) or ("EventID" not in obj and "winlog" not in obj):
        return None
    fields = add_sigma_aliases(normalize_record(obj))
    try:
        ts = _parse_ts(str(fields["UtcTime"])) if fields.get("UtcTime") else None
    except ValueError:
        ts = None
    if ts is None:
        ts = _collector_ts(obj)
        if ts is None:
            return None
        if clock_offset:
            ts += clock_offset
    return Event(
        ts=ts,
        source_type="winjson",
        source_file=source_file,
        record_ref=f"line:{line_no}",
        raw=line.rstrip("\n"),
        fields=fields,
        **derive(fields),
    )


def measure_clock_offset(path: Path, sample: int = CALIBRATION_SAMPLE) -> timedelta | None:
    """Most common (UtcTime - collector time) over records carrying both, rounded to 15 min.

    Exports often stamp local time (sometimes with a misleading 'Z'); Sysmon's UtcTime is authoritative.
    """
    diffs: Counter[int] = Counter()
    with open_text(path) as f:
        for line in islice(f, sample):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if not isinstance(obj, dict) or not obj.get("UtcTime"):
                continue
            collected = _collector_ts(obj)
            try:
                utc = _parse_ts(str(obj["UtcTime"]))
            except ValueError:
                continue
            if collected is not None:
                diffs[round((utc - collected) / OFFSET_STEP)] += 1
    if not diffs:
        return None
    steps = diffs.most_common(1)[0][0]
    return steps * OFFSET_STEP if steps else None


class WinJsonParser(TextLineParser):
    source_type = "winjson"

    def __init__(self) -> None:
        super().__init__()
        self.clock_offset: timedelta | None = None

    def parse_line(self, line: str, line_no: int, source_file: str) -> Event | None:
        return parse_line(line, line_no, source_file, self.clock_offset)

    def parse(self, path: Path) -> Iterator[Event]:
        self.clock_offset = measure_clock_offset(path)
        try:
            yield from super().parse(path)
        finally:
            self.clock_offset = None
