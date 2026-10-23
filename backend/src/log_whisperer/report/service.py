from log_whisperer.attack import default_catalog
from log_whisperer.attack.table import attack_table
from log_whisperer.report.markdown import render_markdown
from log_whisperer.response.actions import SuggestedAction
from log_whisperer.store import Store


def build_report(store: Store, incident_id: str, actions: list[SuggestedAction] | None = None) -> str:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise KeyError(f"incident {incident_id} not found")
    detections = store.list_detections(ids=incident.detection_ids)
    stored = store.latest_narrative(incident_id)
    rows = attack_table(stored.narrative if stored else None, detections, default_catalog())
    events = {e.event_id: e for e in store.events_by_ids(incident.context_event_ids)}
    return render_markdown(incident, detections, stored, rows, actions, events)
