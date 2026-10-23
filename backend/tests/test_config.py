from pathlib import Path

from log_whisperer.config import load_settings


def test_defaults_when_no_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOGW_CONFIG", raising=False)
    s = load_settings()
    assert s.incidents.group_gap_minutes == 30
    assert s.incidents.context_neighbors == 20
    assert s.incidents.context_max == 300
    assert s.llm.provider == "ollama"
    assert s.llm.ollama_model == "gemma4:26b-a4b" and s.llm.model is None
    assert s.llm.anthropic_model == "claude-opus-5-5"
    assert s.detection.brute_force_threshold == 10
    assert s.live.syslog_port == 5514
    assert s.storage.db_path == Path("data/logw.duckdb")


def test_toml_overrides(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[incidents]\ngroup_gap_minutes = 5\n")
    s = load_settings(p)
    assert s.incidents.group_gap_minutes == 5
    assert s.incidents.context_max == 300


def test_env_var_path(tmp_path, monkeypatch):
    p = tmp_path / "c.toml"
    p.write_text('[llm]\nmodel = "x"\n')
    monkeypatch.setenv("LOGW_CONFIG", str(p))
    assert load_settings().llm.model == "x"


def test_env_overrides(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOGW_CONFIG", raising=False)
    monkeypatch.setenv("LOGW_OLLAMA_MODEL", "gemma4:e4b")
    monkeypatch.setenv("LOGW_LLM_PROVIDER", "anthropic")
    s = load_settings()
    assert (s.llm.ollama_model, s.llm.provider) == ("gemma4:e4b", "anthropic")


def test_cwd_config_used(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("LOGW_CONFIG", raising=False)
    (tmp_path / "config.toml").write_text("[live]\nsyslog_port = 6000\n")
    assert load_settings().live.syslog_port == 6000
