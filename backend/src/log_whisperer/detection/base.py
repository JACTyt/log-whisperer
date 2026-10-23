from typing import Protocol

from log_whisperer.models import Detection
from log_whisperer.store import Store


class Detector(Protocol):
    """Heuristic detector producing the same Detection records as Sigma rules."""

    rule_id: str
    title: str

    def run(self, store: Store, since_seq: int | None = None) -> list[Detection]: ...


def uniq(values) -> list[str]:
    """Distinct non-empty values, first-seen order."""
    return list(dict.fromkeys(v for v in values if v))
