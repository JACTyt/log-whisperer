from typer.testing import CliRunner

from log_whisperer import cli
from log_whisperer.store import Store
from tests.test_ingest import FakeParser, _tree

runner = CliRunner()


def test_cli_ingest_reports_counts(tmp_path, monkeypatch):
    (tmp_path / "logs").mkdir()
    root = _tree(tmp_path / "logs")
    db = tmp_path / "x.duckdb"
    monkeypatch.setattr(cli, "default_parsers", lambda: [FakeParser()])
    result = runner.invoke(cli.app, ["ingest", str(root), "--db", str(db)])
    assert result.exit_code == 0, result.output
    assert "files=2 parsed=6 inserted=6 skipped_lines=0 errors=0" in result.output
    with Store(db) as s:
        assert s.count_events() == 6


def test_cli_bad_file_exit_1(tmp_path, monkeypatch):
    bad = tmp_path / "junk.bin"
    bad.write_bytes(b"\x00\x01")
    monkeypatch.setattr(cli, "default_parsers", lambda: [FakeParser()])
    result = runner.invoke(cli.app, ["ingest", str(bad), "--db", str(tmp_path / "x.duckdb")])
    assert result.exit_code == 1
    assert "no parser" in result.output
    assert "Traceback" not in result.output
