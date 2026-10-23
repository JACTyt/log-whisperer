"""Narrative output contract: the JSON schema the model must follow and the validated result models."""

from datetime import datetime

from pydantic import BaseModel


def _cited(extra: dict | None = None) -> dict:
    props = {"text": {"type": "string"}, "event_ids": {"type": "array", "items": {"type": "string"}}}
    props |= extra or {}
    return {"type": "object", "additionalProperties": False, "required": list(props), "properties": props}


NARRATIVE_SCHEMA: dict = {
    "type": "object",
    "additionalProperties": False,
    "required": ["summary", "steps"],
    "properties": {
        "summary": _cited(),
        "steps": {"type": "array", "items": _cited({
            "ts": {"type": "string", "description": "ISO-8601 UTC time of the step, e.g. 2026-03-14T14:02:01Z"},
            "techniques": {"type": "array", "items": {"type": "string"}},
        })},
    },
}


class CitedText(BaseModel):
    text: str
    event_ids: list[str]


class NarrativeStep(BaseModel):
    ts: datetime
    text: str
    event_ids: list[str]
    techniques: list[str] = []


class Rejection(BaseModel):
    index: int  # step index; -1 for the summary
    text: str
    reason: str


class ValidatedNarrative(BaseModel):
    summary: CitedText | None = None
    summary_is_template: bool = False
    steps: list[NarrativeStep] = []
    rejected: list[Rejection] = []


class StoredNarrative(BaseModel):
    incident_id: str
    model: str
    created_at: datetime
    narrative: ValidatedNarrative
