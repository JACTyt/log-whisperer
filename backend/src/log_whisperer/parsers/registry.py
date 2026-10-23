"""Choose a parser for a file."""

from collections.abc import Sequence
from pathlib import Path

from log_whisperer.parsers.authlog import AuthLogParser
from log_whisperer.parsers.base import Parser
from log_whisperer.parsers.evtx import EvtxParser
from log_whisperer.parsers.webaccess import WebAccessParser
from log_whisperer.parsers.winjson import WinJsonParser

PARSER_TYPES = {
    "evtx": EvtxParser,
    "winjson": WinJsonParser,
    "web": WebAccessParser,
    "authlog": AuthLogParser,
}


def default_parsers() -> list[Parser]:
    """Order matters: most specific formats first."""
    return [cls() for cls in PARSER_TYPES.values()]


def parser_by_type(source_type: str) -> Parser:
    try:
        return PARSER_TYPES[source_type]()
    except KeyError:
        raise ValueError(f"unknown parser type {source_type!r}; choose from {sorted(PARSER_TYPES)}") from None


def pick_parser(path: Path, parsers: Sequence[Parser]) -> Parser | None:
    return next((p for p in parsers if p.can_parse(path)), None)
