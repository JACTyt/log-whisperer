from datetime import timedelta

from log_whisperer.config import Settings
from log_whisperer.incidents.context import select_context
from log_whisperer.incidents.grouping import group_detections
from log_whisperer.models import Incident
from log_whisperer.store import Store


def rebuild_incidents(store: Store, settings: Settings) -> list[Incident]:
    """Regroup all detections and persist incidents. IDs stay stable while incidents grow."""
    cfg = settings.incidents
    detections = store.list_detections()
    incidents = group_detections(detections, timedelta(minutes=cfg.group_gap_minutes))
    for inc in incidents:
        inc.context_event_ids = select_context(store, inc, detections, cfg.context_neighbors, cfg.context_max)
    store.replace_incidents(incidents)
    return incidents
