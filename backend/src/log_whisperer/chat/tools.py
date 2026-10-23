"""Safe, parameterized query tools the chat model may call. No raw SQL ever comes from the model."""

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Literal

from log_whisperer.llm.base import ToolSpec
from log_whisperer.models import Event, Incident
from log_whisperer.store import Store

ENTITY_COLUMNS = ("host", "user", "src_ip", "dst_ip", "process")
GROUP_COLUMNS = (*ENTITY_COLUMNS, "action", "outcome", "event_code", "source_type", "channel")
MAX_ROWS = 50
SAMPLES = 5
SCOPE_MARGIN = timedelta(hours=1)


@dataclass
class ChatScope:
    kind: Literal["incident", "global"]
    incident: Incident | None = None


@dataclass
class ToolResult:
    events: list[Event] = field(default_factory=list)  # rendered with aliases by the chat service
    rows: list[dict[str, Any]] = field(default_factory=list)  # aggregate rows; may hold "sample_event_ids"
    error: str | None = None


def _col(name: str) -> str:
    return f'"{name}"'


def _scope(scope: ChatScope) -> tuple[str, list]:
    if scope.kind == "incident" and scope.incident is not None:
        return "ts BETWEEN ? AND ?", [scope.incident.ts_start - SCOPE_MARGIN, scope.incident.ts_end + SCOPE_MARGIN]
    return "TRUE", []


def _limit(value: Any, default: int = 20) -> int:
    try:
        return max(1, min(int(value or default), MAX_ROWS))
    except (TypeError, ValueError):
        return default


def events_by_entity(store: Store, scope: ChatScope, args: dict) -> ToolResult:
    col = args.get("entity_type")
    if col not in ENTITY_COLUMNS:
        return ToolResult(error=f"entity_type must be one of {ENTITY_COLUMNS}")
    where, params = _scope(scope)
    events = store.query_events(f"{where} AND lower({_col(col)}) = lower(?)", [*params, str(args.get("value", ""))],
                                limit=_limit(args.get("limit")))
    return ToolResult(events=events)


def entity_summary(store: Store, scope: ChatScope, args: dict) -> ToolResult:
    col = args.get("entity_type")
    if col not in ENTITY_COLUMNS:
        return ToolResult(error=f"entity_type must be one of {ENTITY_COLUMNS}")
    where, params = _scope(scope)
    rows = store.sql_dicts(
        f"""SELECT action, outcome, count(*) AS n, min(ts) AS first_seen, max(ts) AS last_seen,
                   list(DISTINCT host) FILTER (WHERE host IS NOT NULL) AS hosts,
                   list(DISTINCT "user") FILTER (WHERE "user" IS NOT NULL) AS users,
                   list(DISTINCT src_ip) FILTER (WHERE src_ip IS NOT NULL) AS src_ips,
                   list(event_id ORDER BY ts)[1:{SAMPLES}] AS sample_event_ids
            FROM events WHERE {where} AND lower({_col(col)}) = lower(?)
            GROUP BY ALL ORDER BY n DESC LIMIT {MAX_ROWS}""",
        [*params, str(args.get("value", ""))],
    )
    return ToolResult(rows=rows)


def count_by(store: Store, scope: ChatScope, args: dict) -> ToolResult:
    field_ = args.get("field")
    if field_ not in GROUP_COLUMNS:
        return ToolResult(error=f"field must be one of {GROUP_COLUMNS}")
    where, params = _scope(scope)
    ff, fv = args.get("filter_field"), args.get("filter_value")
    if ff:
        if ff not in GROUP_COLUMNS:
            return ToolResult(error=f"filter_field must be one of {GROUP_COLUMNS}")
        where += f" AND lower({_col(ff)}) = lower(?)"
        params.append(str(fv))
    rows = store.sql_dicts(
        f"""SELECT {_col(field_)} AS value, count(*) AS n,
                   list(event_id ORDER BY ts)[1:{SAMPLES}] AS sample_event_ids
            FROM events WHERE {where} GROUP BY 1 ORDER BY n DESC LIMIT {MAX_ROWS}""",
        params,
    )
    return ToolResult(rows=rows)


def incident_events(store: Store, scope: ChatScope, args: dict) -> ToolResult:
    if scope.incident is None:
        return ToolResult(error="no incident selected; use events_by_entity or search_events")
    events = store.events_by_ids(scope.incident.context_event_ids)
    if action := args.get("action"):
        events = [e for e in events if e.action == action]
    return ToolResult(events=events[:_limit(args.get("limit"), MAX_ROWS)])


def search_events(store: Store, scope: ChatScope, args: dict) -> ToolResult:
    text = str(args.get("text") or "").strip()
    if len(text) < 2:
        return ToolResult(error="text must be at least 2 characters")
    where, params = _scope(scope)
    pattern = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    events = store.query_events(f"{where} AND raw ILIKE ? ESCAPE '\\'", [*params, pattern],
                                limit=_limit(args.get("limit")))
    return ToolResult(events=events)


@dataclass
class Tool:
    spec: ToolSpec
    fn: Callable[[Store, ChatScope, dict], ToolResult]


def _params(props: dict[str, dict]) -> dict:
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


_ENTITY = {"type": "string", "enum": list(ENTITY_COLUMNS)}
_GROUP = {"type": "string", "enum": list(GROUP_COLUMNS)}
_LIMIT = {"type": ["integer", "null"], "description": f"max rows (<= {MAX_ROWS})"}

TOOLS: dict[str, Tool] = {t.spec.name: t for t in [
    Tool(ToolSpec("events_by_entity", "List events where a host/user/IP/process equals a value.",
                  _params({"entity_type": _ENTITY, "value": {"type": "string"}, "limit": _LIMIT})), events_by_entity),
    Tool(ToolSpec("entity_summary", "Summarize activity of one entity: actions, outcomes, related hosts/users/IPs.",
                  _params({"entity_type": _ENTITY, "value": {"type": "string"}})), entity_summary),
    Tool(ToolSpec("count_by", "Count events grouped by a field, optionally filtered by another field's value. "
                  "E.g. which hosts an IP touched: field=host, filter_field=src_ip, filter_value=<ip>.",
                  _params({"field": _GROUP, "filter_field": {"type": ["string", "null"], "enum": [*GROUP_COLUMNS, None]},
                           "filter_value": {"type": ["string", "null"]}})), count_by),
    Tool(ToolSpec("incident_events", "List the events of the current incident, optionally only one action "
                  "(logon, ssh_auth, process_start, sudo, user_created, group_member_added, http_request, ...).",
                  _params({"action": {"type": ["string", "null"]}, "limit": _LIMIT})), incident_events),
    Tool(ToolSpec("search_events", "Case-insensitive substring search over raw log lines.",
                  _params({"text": {"type": "string"}, "limit": _LIMIT})), search_events),
]}
