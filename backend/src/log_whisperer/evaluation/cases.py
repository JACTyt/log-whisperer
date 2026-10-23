"""Eval case files: eval/cases/*.yaml (DESIGN §19)."""

from datetime import datetime
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator


class KeyFact(BaseModel):
    entity: str
    action: str | None = None
    outcome: str | None = None
    approx_ts: datetime | None = None

    @field_validator("approx_ts")
    @classmethod
    def _utc_naive(cls, v: datetime | None) -> datetime | None:
        from datetime import timezone

        return v.astimezone(timezone.utc).replace(tzinfo=None) if v and v.tzinfo else v


class EvalCase(BaseModel):
    name: str
    description: str = ""
    files: list[Path]
    parser: str | None = None  # force a parser type
    authlog_year: int | None = None
    expected_techniques: list[str] = []
    key_facts: list[KeyFact] = []

    @field_validator("files", mode="before")
    @classmethod
    def _posix(cls, v: list) -> list:
        return [Path(str(p).replace("\\", "/")) for p in v]


def load_cases(directory: Path) -> list[EvalCase]:
    return [EvalCase.model_validate(yaml.safe_load(p.read_text(encoding="utf-8")))
            for p in sorted([*directory.glob("*.yaml"), *directory.glob("*.yml")])]
