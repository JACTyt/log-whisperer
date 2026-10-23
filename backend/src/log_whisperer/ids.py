"""Deterministic identifiers and entity normalization."""

import hashlib


def short_hash(*parts: str) -> str:
    return hashlib.sha1("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


def make_event_id(source_file: str, record_ref: str) -> str:
    return short_hash(source_file, record_ref)


def normalize_user(value: str | None) -> str | None:
    """`CORP\\Bob` / `bob@corp.local` / `Bob` -> `bob`; `-` and blanks -> None."""
    if value is None:
        return None
    v = value.strip()
    if "\\" in v:
        v = v.rsplit("\\", 1)[1]
    if "@" in v:
        v = v.split("@", 1)[0]
    v = v.strip().lower()
    return None if v in ("", "-") else v
