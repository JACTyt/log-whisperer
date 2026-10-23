"""DuckDB-backed store. One process owns the database file (DESIGN §15)."""

import json
import threading
from collections.abc import Iterable, Sequence
from datetime import datetime
from importlib.resources import files
from itertools import islice
from pathlib import Path
from typing import TYPE_CHECKING, Any, Self

import duckdb
import pyarrow as pa

from log_whisperer.models import Detection, Event, Incident

if TYPE_CHECKING:
    from log_whisperer.narrative.schema import StoredNarrative, ValidatedNarrative

BATCH_SIZE = 5000

# Insert order of columns; `seq` is assigned by the database.
EVENT_COLUMNS = [
    "event_id", "ts", "source_type", "channel", "host", "user", "src_ip", "dst_ip",
    "process", "command_line", "action", "outcome", "event_code",
    "source_file", "record_ref", "raw", "fields",
]
EVENT_SELECT = ", ".join(f'"{c}"' for c in ["seq", *EVENT_COLUMNS])

_EVENT_SCHEMA = pa.schema(
    [pa.field("ts", pa.timestamp("us"))]
    + [pa.field(c, pa.string()) for c in EVENT_COLUMNS if c != "ts"]
)

_LIST_COLUMNS = {"techniques", "event_ids", "hosts", "users", "src_ips", "detection_ids", "context_event_ids"}
_TS_COLUMNS = {"ts_first", "ts_last", "ts_start", "ts_end", "updated_at"}


def _schema(columns: list[str]) -> pa.Schema:
    return pa.schema([
        pa.field(c, pa.list_(pa.string()) if c in _LIST_COLUMNS
                 else pa.timestamp("us") if c in _TS_COLUMNS else pa.string())
        for c in columns
    ])


DETECTION_COLUMNS = list(Detection.model_fields)
_DETECTION_SCHEMA = _schema(DETECTION_COLUMNS)
INCIDENT_COLUMNS = list(Incident.model_fields)
_INCIDENT_SCHEMA = _schema(INCIDENT_COLUMNS)


def _cols(names: Sequence[str]) -> str:
    return ", ".join(f'"{c}"' for c in names)


class Store:
    def __init__(self, db_path: str | Path):
        if str(db_path) != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.con = duckdb.connect(str(db_path))
        self.lock = threading.RLock()
        self._q("SET enable_progress_bar = false")
        for stmt in files("log_whisperer.store").joinpath("schema.sql").read_text().split(";"):
            if stmt.strip():
                self._q(stmt)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.con.close()

    # -- low level -------------------------------------------------------------

    def _q(self, sql: str, params: list | None = None) -> list[tuple]:
        """Execute and fully consume the result (DuckDB 2 requires it before the next statement)."""
        with self.lock:
            return self.con.execute(sql, params or []).fetchall()

    def sql(self, sql: str, params: list | None = None) -> list[tuple]:
        return self._q(sql, params)

    def sql_dicts(self, sql: str, params: list | None = None) -> list[dict[str, Any]]:
        with self.lock:
            cur = self.con.execute(sql, params or [])
            names = [d[0] for d in cur.description]
            return [dict(zip(names, row)) for row in cur.fetchall()]

    def _insert_arrow(self, table: str, columns: list[str], rows: dict[str, list], schema: pa.Schema,
                      key: str, replace: bool = False) -> None:
        verb = "INSERT OR REPLACE INTO" if replace else "INSERT INTO"
        conflict = "" if replace else f"ON CONFLICT ({key}) DO NOTHING"
        with self.lock:
            self.con.register("_batch", pa.table(rows, schema=schema))
            try:
                self._q(f"{verb} {table} ({_cols(columns)}) SELECT {_cols(columns)} FROM _batch {conflict}")
            finally:
                self.con.unregister("_batch")

    def _count(self, table: str) -> int:
        return self._q(f"SELECT count(*) FROM {table}")[0][0]

    # -- events ----------------------------------------------------------------

    def insert_events(self, events: Iterable[Event]) -> int:
        """Insert events, skipping ids already stored. Returns rows actually inserted."""
        with self.lock:
            before = self._count("events")
            it = iter(events)
            while batch := list(islice(it, BATCH_SIZE)):
                unique = {e.event_id: e for e in batch}.values()
                rows: dict[str, list] = {c: [] for c in EVENT_COLUMNS}
                for e in unique:
                    for c in EVENT_COLUMNS:
                        v = getattr(e, c)
                        rows[c].append(json.dumps(v, default=str) if c == "fields" else v)
                self._insert_arrow("events", EVENT_COLUMNS, rows, _EVENT_SCHEMA, "event_id")
            return self._count("events") - before

    def count_events(self) -> int:
        return self._count("events")

    def max_seq(self) -> int:
        return self._q("SELECT coalesce(max(seq), 0) FROM events")[0][0]

    def get_event(self, event_id: str) -> Event | None:
        rows = self._q(f"SELECT {EVENT_SELECT} FROM events WHERE event_id = ?", [event_id])
        return row_to_event(rows[0]) if rows else None

    def events_by_ids(self, ids: Sequence[str]) -> list[Event]:
        if not ids:
            return []
        rows = self._q(
            f"SELECT {EVENT_SELECT} FROM events WHERE event_id IN (SELECT unnest(?)) ORDER BY ts, seq",
            [list(ids)],
        )
        return [row_to_event(r) for r in rows]

    def query_events(self, where: str = "TRUE", params: list | None = None, order: str = "ts, seq",
                     limit: int | None = None, offset: int = 0) -> list[Event]:
        """`where` must be built from trusted fragments; values go through `params`."""
        sql = f"SELECT {EVENT_SELECT} FROM events WHERE {where} ORDER BY {order}"
        if limit is not None:
            sql += f" LIMIT {int(limit)} OFFSET {int(offset)}"
        return [row_to_event(r) for r in self._q(sql, params)]

    # -- detections ------------------------------------------------------------

    def insert_detections(self, detections: Iterable[Detection], replace: bool = False) -> int:
        """Insert detections; `replace` overwrites same-id rows (growing heuristic bursts).
        Returns the number of new detection ids."""
        with self.lock:
            before = self._count("detections")
            it = iter(detections)
            while batch := list(islice(it, BATCH_SIZE)):
                unique = {d.detection_id: d for d in batch}.values()
                rows: dict[str, list] = {c: [getattr(d, c) for d in unique] for c in DETECTION_COLUMNS}
                self._insert_arrow("detections", DETECTION_COLUMNS, rows, _DETECTION_SCHEMA,
                                   "detection_id", replace=replace)
            return self._count("detections") - before

    def list_detections(self, since: datetime | None = None, ids: Sequence[str] | None = None) -> list[Detection]:
        where, params = ["TRUE"], []
        if since is not None:
            where.append("ts_last >= ?")
            params.append(since)
        if ids is not None:
            where.append("detection_id IN (SELECT unnest(?))")
            params.append(list(ids))
        rows = self._q(
            f"SELECT {_cols(DETECTION_COLUMNS)} FROM detections WHERE {' AND '.join(where)} "
            "ORDER BY ts_first, detection_id",
            params,
        )
        return [Detection(**dict(zip(DETECTION_COLUMNS, r))) for r in rows]

    # -- incidents ---------------------------------------------------------------

    def replace_incidents(self, incidents: Sequence[Incident]) -> None:
        rows: dict[str, list] = {c: [getattr(i, c) for i in incidents] for c in INCIDENT_COLUMNS}
        with self.lock:
            self._q("BEGIN TRANSACTION")
            try:
                self._q("DELETE FROM incidents")
                if incidents:
                    self._insert_arrow("incidents", INCIDENT_COLUMNS, rows, _INCIDENT_SCHEMA, "incident_id")
                self._q("COMMIT")
            except Exception:
                self._q("ROLLBACK")
                raise

    def list_incidents(self, where: str = "TRUE", params: list | None = None) -> list[Incident]:
        rows = self._q(f"SELECT {_cols(INCIDENT_COLUMNS)} FROM incidents WHERE {where} "
                       "ORDER BY ts_start, incident_id", params)
        return [Incident(**dict(zip(INCIDENT_COLUMNS, r))) for r in rows]

    def get_incident(self, incident_id: str) -> Incident | None:
        found = self.list_incidents("incident_id = ?", [incident_id])
        return found[0] if found else None

    # -- narratives --------------------------------------------------------------

    def save_narrative(self, incident_id: str, model: str, narrative: "ValidatedNarrative") -> None:
        body = narrative.model_dump_json(exclude={"rejected"})
        rejected = json.dumps([r.model_dump() for r in narrative.rejected])
        self._q("INSERT INTO narratives VALUES (?, ?, ?, ?, ?)",
                [incident_id, model, datetime.now().replace(microsecond=0), body, rejected])

    def latest_narrative(self, incident_id: str) -> "StoredNarrative | None":
        from log_whisperer.narrative.schema import StoredNarrative, ValidatedNarrative

        rows = self._q("SELECT model, created_at, body, rejected FROM narratives WHERE incident_id = ? "
                       "ORDER BY created_at DESC, rowid DESC LIMIT 1", [incident_id])
        if not rows:
            return None
        model, created_at, body, rejected = rows[0]
        nv = ValidatedNarrative.model_validate(json.loads(body) | {"rejected": json.loads(rejected)})
        return StoredNarrative(incident_id=incident_id, model=model, created_at=created_at, narrative=nv)


def row_to_event(row: tuple) -> Event:
    data = dict(zip(["seq", *EVENT_COLUMNS], row))
    data["fields"] = json.loads(data["fields"]) if data["fields"] else {}
    return Event(**data)
