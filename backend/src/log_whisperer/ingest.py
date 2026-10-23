"""File ingestion: pick a parser per file, stream events into the store."""

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from log_whisperer.models import Event
from log_whisperer.parsers import Parser, pick_parser
from log_whisperer.store import Store


@dataclass
class IngestResult:
    files: int = 0
    parsed: int = 0
    inserted: int = 0
    skipped_lines: int = 0
    errors: list[str] = field(default_factory=list)

    def add(self, other: "IngestResult") -> None:
        self.files += other.files
        self.parsed += other.parsed
        self.inserted += other.inserted
        self.skipped_lines += other.skipped_lines
        self.errors += other.errors


def ingest_events(store: Store, events: Iterable[Event]) -> int:
    return store.insert_events(events)


def _counted(events: Iterable[Event], result: IngestResult) -> Iterable[Event]:
    for e in events:
        result.parsed += 1
        yield e


def ingest_path(
    store: Store,
    path: Path,
    parsers: Sequence[Parser],
    force: Parser | None = None,
    progress: Callable[[dict], None] | None = None,
) -> IngestResult:
    """Ingest a file or every file under a directory. Per-file failures go to `errors`.

    `force` skips format detection and uses that parser for every file.
    """
    result = IngestResult()
    if not path.exists():
        result.errors.append(f"{path}: not found")
        return result
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    for i, f in enumerate(files, 1):
        parser = force or pick_parser(f, parsers)
        if parser is None:
            result.errors.append(f"{f}: no parser")
            continue
        try:
            result.inserted += ingest_events(store, _counted(parser.parse(f), result))
            result.files += 1
            result.skipped_lines += getattr(parser, "skipped", 0)
        except Exception as exc:  # one bad file must not abort a bulk ingest
            result.errors.append(f"{f}: {type(exc).__name__}: {exc}")
        if progress:
            progress({"file": str(f), "done": i, "total": len(files),
                      "parsed": result.parsed, "inserted": result.inserted})
    return result
