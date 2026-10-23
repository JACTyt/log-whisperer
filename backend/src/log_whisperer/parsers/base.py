from collections.abc import Iterator
from pathlib import Path
from typing import Protocol

from log_whisperer.models import Event


class Parser(Protocol):
    source_type: str

    def can_parse(self, path: Path) -> bool: ...

    def parse(self, path: Path) -> Iterator[Event]: ...
