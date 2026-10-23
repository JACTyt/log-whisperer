import gzip
import json
from pathlib import Path

from log_whisperer.parsers.registry import default_parsers, parser_by_type, pick_parser

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _pick(path):
    p = pick_parser(path, default_parsers())
    return p.source_type if p else None


def test_fixtures_resolve():
    assert _pick(FIXTURES / "auth.log") == "authlog"
    assert _pick(FIXTURES / "access.log") == "web"
    assert _pick(FIXTURES / "winjson_flat.jsonl") == "winjson"


def test_gzip(tmp_path):
    gz = tmp_path / "auth.log.1.gz"
    gz.write_bytes(gzip.compress((FIXTURES / "auth.log").read_bytes()))
    assert _pick(gz) == "authlog"
    parser = pick_parser(gz, default_parsers())
    assert len(list(parser.parse(gz))) == 31


def test_binary_junk(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(bytes(range(256)) * 4)
    assert _pick(f) is None


def test_evtx_magic(tmp_path):
    f = tmp_path / "x.evtx"
    f.write_bytes(b"ElfFile\x00" + b"\x00" * 64)
    assert _pick(f) == "evtx"


def test_json_without_events(tmp_path):
    f = tmp_path / "x.json"
    f.write_text(json.dumps({"a": 1}))
    assert _pick(f) is None


def test_parser_by_type():
    assert parser_by_type("authlog").source_type == "authlog"
    assert parser_by_type("web").source_type == "web"
