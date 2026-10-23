"""Generate -> validate -> persist incident narratives."""

import logging
from dataclasses import dataclass, field

from pydantic import BaseModel, ValidationError

from log_whisperer.attack import default_catalog
from log_whisperer.config import Settings
from log_whisperer.llm.base import LLMError, LLMProvider
from log_whisperer.models import Detection, Event, Incident
from log_whisperer.narrative.prompt import SYSTEM_PROMPT, build_user_prompt, render_context
from log_whisperer.narrative.schema import NARRATIVE_SCHEMA, CitedText, ValidatedNarrative
from log_whisperer.narrative.validator import validate
from log_whisperer.store import Store

log = logging.getLogger(__name__)


class NarrativeError(Exception):
    def __init__(self, message: str, raw: str = ""):
        super().__init__(message)
        self.raw = raw


class _Shape(BaseModel):
    """Minimal structural check before the semantic validator runs."""

    summary: dict
    steps: list[dict]


@dataclass
class IncidentBundle:
    incident: Incident
    detections: list[Detection]
    events: list[Event]
    events_by_id: dict[str, Event] = field(default_factory=dict)
    known_entities: set[str] = field(default_factory=set)


def load_incident_bundle(store: Store, incident_id: str) -> IncidentBundle:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise KeyError(f"incident {incident_id} not found")
    detections = store.list_detections(ids=incident.detection_ids)
    events = store.events_by_ids(incident.context_event_ids)
    entities = set(incident.hosts) | set(incident.users) | set(incident.src_ips)
    for e in events:
        entities.update(v for v in (e.host, e.user, e.src_ip, e.dst_ip) if v)
    entities |= {h.split(".")[0] for h in list(entities) if "." in h and not h[0].isdigit()}
    return IncidentBundle(incident, detections, events, {e.event_id: e for e in events}, entities)


def template_summary(bundle: IncidentBundle) -> CitedText:
    inc = bundle.incident
    cites = list(dict.fromkeys(d.event_ids[0] for d in bundle.detections if d.event_ids))
    titles = ", ".join(dict.fromkeys(d.rule_title for d in bundle.detections))
    return CitedText(
        text=(f"{len(bundle.detections)} detections ({titles}) between {inc.ts_start:%Y-%m-%d %H:%M} and "
              f"{inc.ts_end:%H:%M} UTC involving hosts {', '.join(inc.hosts) or '-'}."),
        event_ids=cites,
    )


def generate_narrative(store: Store, incident_id: str, provider: LLMProvider, settings: Settings,
                       attempts: int = 2) -> ValidatedNarrative:
    bundle = load_incident_bundle(store, incident_id)
    rc = render_context(bundle.incident, bundle.events, bundle.detections)
    user = build_user_prompt(rc)
    raw, last_error = None, ""
    for attempt in range(attempts):
        try:
            candidate = provider.generate_json(SYSTEM_PROMPT, user, NARRATIVE_SCHEMA)
            _Shape.model_validate(candidate)
            raw = candidate
            break
        except (LLMError, ValidationError) as exc:
            last_error = str(exc)
            log.warning("narrative attempt %d failed: %s", attempt + 1, last_error)
    if raw is None:
        raise NarrativeError(f"model output unusable after {attempts} attempts: {last_error}", last_error)

    nv = validate(raw, rc, bundle.events_by_id, default_catalog(), bundle.known_entities)
    if nv.summary is None:
        nv.summary = template_summary(bundle)
        nv.summary_is_template = True
    store.save_narrative(incident_id, f"{provider.name}:{provider.model}", nv)
    return nv
