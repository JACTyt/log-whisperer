"""Read endpoints: events, detections, incidents, health."""

import os
from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

import ollama
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from log_whisperer.api.deps import get_settings, get_store, require_incident
from log_whisperer.attack import default_catalog
from log_whisperer.attack.table import AttackRow, attack_table
from log_whisperer.config import Settings
from log_whisperer.llm.factory import PROVIDERS
from log_whisperer.models import Detection, Event, Incident
from log_whisperer.narrative.schema import StoredNarrative
from log_whisperer.sources import KINDS, SourceSummary, display_name, summarize_sources
from log_whisperer.store import Store

router = APIRouter()
T = TypeVar("T")
StoreDep = Annotated[Store, Depends(get_store)]
Limit = Annotated[int, Query(ge=1, le=500)]


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int


class IncidentSummary(Incident):
    has_narrative: bool = False
    detection_count: int = 0
    event_count: int = 0
    source_files: list[str] = []  # stored paths of the log files this incident uses, most lines first


class IncidentDetail(BaseModel):
    incident: Incident
    detections: list[Detection]
    events: list[Event]
    sources: list[SourceSummary]
    attack: list[AttackRow]
    narrative: StoredNarrative | None
    shared: dict[str, list[str]] = {}  # event_id -> OTHER incidents that also use this log line


@router.get("/health")
def health(store: StoreDep) -> dict:
    return {"status": "ok", "events": store.count_events()}


def installed_ollama_models() -> list[str] | None:
    """Model names installed in Ollama, or None if Ollama can't be reached."""
    try:
        client = ollama.Client(host=os.environ.get("OLLAMA_HOST", "http://localhost:11434"), timeout=3)
        return [m.model for m in client.list().models if m.model]
    except Exception:
        return None


def _chat_capable(name: str) -> bool:
    return "embed" not in name.lower()


@router.get("/providers")
def providers(settings: Annotated[Settings, Depends(get_settings)]) -> dict:
    """Models the UI can offer: configured defaults first, then everything installed in Ollama."""
    llm = settings.llm
    installed = installed_ollama_models()
    have = set(installed or [])
    ollama_default = llm.model or llm.ollama_model
    names = list(dict.fromkeys([ollama_default, *llm.ollama_extra_models,
                                *(m for m in (installed or []) if _chat_capable(m))]))
    models = [{"provider": "ollama", "model": m, "installed": m in have} for m in names]
    models.append({"provider": "anthropic", "model": llm.anthropic_model, "installed": True})
    if llm.openai_model:
        models.append({"provider": "openai", "model": llm.openai_model, "installed": True})
    default_model = {"ollama": ollama_default, "anthropic": llm.anthropic_model}.get(llm.provider, llm.openai_model)
    return {"default": llm.provider, "default_model": default_model, "models": models,
            "ollama_reachable": installed is not None, "available": list(PROVIDERS)}


_EVENT_FILTERS = {"host": "lower(host) = lower(?)", "user": '"user" = lower(?)', "src_ip": "src_ip = ?",
                  "source_type": "source_type = ?", "action": "action = ?", "outcome": "outcome = ?",
                  "source_file": "source_file = ?"}
# "file": the order lines have in their file (line / record number), file by file; "time": chronological.
_ORDERS = {
    "time": "ts, seq",
    "file": "source_file, try_cast(split_part(record_ref, ':', 2) AS BIGINT), seq",
}


class EventPage(BaseModel):
    items: list[Event]
    total: int
    offset: int
    incidents: dict[str, list[str]] = {}  # event_id -> incident ids that use this line


class SourceFile(BaseModel):
    name: str
    source_file: str
    source_type: str
    kind: str
    events: int
    first_ts: datetime
    last_ts: datetime
    incidents: int


@router.get("/sources")
def list_sources(store: StoreDep) -> list[SourceFile]:
    """Every log file / live source that has been ingested, with line and incident counts."""
    rows = store.sql_dicts(
        """WITH used AS (SELECT DISTINCT e.source_file, i.incident_id
                         FROM incidents i, unnest(i.context_event_ids) AS u(event_id) JOIN events e USING (event_id))
           SELECT e.source_file, any_value(e.source_type) AS source_type, count(*) AS events,
                  min(e.ts) AS first_ts, max(e.ts) AS last_ts,
                  (SELECT count(*) FROM used WHERE used.source_file = e.source_file) AS incidents
           FROM events e GROUP BY e.source_file ORDER BY e.source_file"""
    )
    return sorted((SourceFile(name=display_name(r["source_file"]), kind=KINDS.get(r["source_type"], r["source_type"]), **r)
                   for r in rows), key=lambda s: (s.name, s.source_file))


def _incidents_for(store: Store, event_ids: list[str]) -> dict[str, list[str]]:
    if not event_ids:
        return {}
    out: dict[str, list[str]] = {}
    for event_id, incident_id in store.sql(
        """SELECT u.event_id, i.incident_id FROM incidents i, unnest(i.context_event_ids) AS u(event_id)
           WHERE u.event_id IN (SELECT unnest(?)) ORDER BY i.ts_start""", [event_ids]
    ):
        out.setdefault(event_id, []).append(incident_id)
    return out


@router.get("/events")
def list_events(
    store: StoreDep,
    request: Request,
    ts_from: datetime | None = None,
    ts_to: datetime | None = None,
    q: str | None = None,
    incident_id: str | None = None,
    order: Literal["time", "file"] = "time",
    focus: Annotated[str | None, Query(description="Return the page that contains this event id.")] = None,
    limit: Limit = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> EventPage:
    where, params = ["TRUE"], []
    if ts_from:
        where.append("ts >= ?")
        params.append(ts_from)
    if ts_to:
        where.append("ts <= ?")
        params.append(ts_to)
    for name, clause in _EVENT_FILTERS.items():
        if value := request.query_params.get(name):
            where.append(clause)
            params.append(value)
    if q:
        where.append("raw ILIKE ? ESCAPE '\\'")
        params.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if incident_id:
        inc = require_incident(store, incident_id)
        where.append("event_id IN (SELECT unnest(?))")
        params.append(inc.context_event_ids)
    clause = " AND ".join(where)
    order_sql = _ORDERS[order]
    total = store.sql(f"SELECT count(*) FROM events WHERE {clause}", params)[0][0]
    if focus:
        pos = store.sql(f"""SELECT pos FROM (SELECT event_id, row_number() OVER (ORDER BY {order_sql}) - 1 AS pos
                                             FROM events WHERE {clause}) WHERE event_id = ?""", [*params, focus])
        if pos:
            offset = pos[0][0] // limit * limit
    items = store.query_events(clause, params, order=order_sql, limit=limit, offset=offset)
    return EventPage(items=items, total=total, offset=offset,
                     incidents=_incidents_for(store, [e.event_id for e in items]))


@router.get("/events/{event_id}")
def get_event(event_id: str, store: StoreDep) -> Event:
    event = store.get_event(event_id)
    if event is None:
        raise HTTPException(404, f"event {event_id} not found")
    return event


@router.get("/detections")
def list_detections(store: StoreDep, incident_id: str | None = None, limit: Limit = 100,
                    offset: Annotated[int, Query(ge=0)] = 0) -> Page[Detection]:
    ids = require_incident(store, incident_id).detection_ids if incident_id else None
    dets = store.list_detections(ids=ids)
    return Page(items=dets[offset:offset + limit], total=len(dets))


@router.get("/incidents")
def list_incidents(store: StoreDep, min_severity: str = "informational") -> list[IncidentSummary]:
    from log_whisperer.models import severity_rank

    narrated = {r[0] for r in store.sql("SELECT DISTINCT incident_id FROM narratives")}
    incidents = [i for i in reversed(store.list_incidents()) if severity_rank(i.severity) >= severity_rank(min_severity)]
    # source files per incident in one query (most lines first)
    files: dict[str, list[str]] = {}
    for incident_id, source_file in store.sql(
        """SELECT i.incident_id, e.source_file FROM incidents i, unnest(i.context_event_ids) AS u(event_id)
           JOIN events e USING (event_id) GROUP BY ALL ORDER BY count(*) DESC, e.source_file"""
    ):
        files.setdefault(incident_id, []).append(source_file)
    return [IncidentSummary(**i.model_dump(), has_narrative=i.incident_id in narrated,
                            detection_count=len(i.detection_ids), event_count=len(i.context_event_ids),
                            source_files=files.get(i.incident_id, []))
            for i in incidents]


@router.get("/incidents/{incident_id}")
def get_incident(incident_id: str, store: StoreDep) -> IncidentDetail:
    inc = require_incident(store, incident_id)
    dets = store.list_detections(ids=inc.detection_ids)
    stored = store.latest_narrative(incident_id)
    events = store.events_by_ids(inc.context_event_ids)
    shared = {eid: others for eid, ids in _incidents_for(store, inc.context_event_ids).items()
              if (others := [i for i in ids if i != incident_id])}
    return IncidentDetail(
        incident=inc, detections=dets, events=events, sources=summarize_sources(events),
        attack=attack_table(stored.narrative if stored else None, dets, default_catalog()),
        narrative=stored, shared=shared,
    )


@router.get("/incidents/{incident_id}/narrative")
def get_narrative(incident_id: str, store: StoreDep) -> StoredNarrative:
    require_incident(store, incident_id)
    stored = store.latest_narrative(incident_id)
    if stored is None:
        raise HTTPException(404, "no narrative generated yet")
    return stored
