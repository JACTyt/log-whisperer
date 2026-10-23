"""Shared machinery for line-oriented text log parsers."""

import gzip
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import TextIO

from log_whisperer.models import Event

SNIFF_LINES = 20


def open_text(path: Path) -> TextIO:
    with open(path, "rb") as f:
        gz = f.read(2) == b"\x1f\x8b"
    if gz:
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


class TextLineParser:
    """Subclasses implement `parse_line`; this provides file iteration and sniffing."""

    source_type = "text"

    def __init__(self) -> None:
        self.skipped = 0

    def parse_line(self, line: str, line_no: int, source_file: str) -> Event | None:
        raise NotImplementedError

    def can_parse(self, path: Path) -> bool:
        """True when at least half of the first non-empty lines parse."""
        try:
            with open_text(path) as f:
                lines = list(islice((ln for ln in f if ln.strip()), SNIFF_LINES))
        except (OSError, UnicodeError, EOFError):
            return False
        if not lines or any("\x00" in ln for ln in lines):
            return False
        ok = sum(1 for i, ln in enumerate(lines, 1) if self.parse_line(ln, i, str(path)))
        return ok * 2 >= len(lines)

    def parse(self, path: Path) -> Iterator[Event]:
        self.skipped = 0
        source = str(Path(path).resolve())
        with open_text(path) as f:
            for line_no, line in enumerate(f, 1):
                if not line.strip():
                    continue
                event = self.parse_line(line, line_no, source)
                if event is None:
                    self.skipped += 1
                else:
                    yield event
