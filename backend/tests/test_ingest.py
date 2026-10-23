from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from log_whisperer.ingest import ingest_path
from log_whisperer.models import Event
from log_whisperer.store import Store


class FakeParser:
    """Claims `*.fake` files and yields 3 events per file."""

    source_type = "fake"

    def can_parse(self, path: Path) -> bool:
        return path.suffix == ".fake"

    def parse(self, path: Path) -> Iterator[Event]:
        if "boom" in path.name:
            raise ValueError("corrupt file")
        for i in range(3):
            yield Event(
                ts=datetime(2026, 1, 1, 0, 0, i),
                source_type="fake",
                source_file=str(path),
                record_ref=f"line:{i}",
                raw=f"{path.name}:{i}",
            )


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "a.fake").write_text("x")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.fake").write_text("x")
    return tmp_path


def test_ingest_dir_recursive_and_idempotent(tmp_path):
    root = _tree(tmp_path)
    with Store(":memory:") as s:
        r = ingest_path(s, root, [FakeParser()])
        assert (r.files, r.parsed, r.inserted, r.errors) == (2, 6, 6, [])
        r2 = ingest_path(s, root, [FakeParser()])
        assert (r2.parsed, r2.inserted) == (6, 0)


def test_ingest_single_file(tmp_path):
    _tree(tmp_path)
    with Store(":memory:") as s:
        r = ingest_path(s, tmp_path / "a.fake", [FakeParser()])
        assert (r.files, r.inserted) == (1, 3)


def test_unknown_file_reported(tmp_path):
    (tmp_path / "notes.txt").write_text("hello")
    with Store(":memory:") as s:
        r = ingest_path(s, tmp_path, [FakeParser()])
        assert r.files == 0
        assert len(r.errors) == 1 and "no parser" in r.errors[0]


def test_parser_exception_is_caught(tmp_path):
    _tree(tmp_path)
    (tmp_path / "boom.fake").write_text("x")
    with Store(":memory:") as s:
        r = ingest_path(s, tmp_path, [FakeParser()])
        assert r.inserted == 6
        assert len(r.errors) == 1 and "corrupt file" in r.errors[0]


def test_missing_path_reported(tmp_path):
    with Store(":memory:") as s:
        r = ingest_path(s, tmp_path / "nope", [FakeParser()])
        assert r.files == 0 and "not found" in r.errors[0]
