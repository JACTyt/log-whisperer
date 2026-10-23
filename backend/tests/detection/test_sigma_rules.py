from pathlib import Path

from sigma.rule import SigmaLogSource

from log_whisperer.detection.logsources import logsource_sql
from log_whisperer.detection.sigma_rules import load_rules, techniques_from_tags

RULES = Path(__file__).parents[1] / "fixtures" / "rules"


def test_logsource_mapping():
    assert "channel = 'Security'" in logsource_sql(SigmaLogSource(product="windows", service="security"))
    pc = logsource_sql(SigmaLogSource(product="windows", category="process_creation"))
    assert "'1'" in pc and "'4688'" in pc
    assert logsource_sql(SigmaLogSource(product="linux", service="sshd")) == "source_type IN ('authlog', 'syslog')"
    assert logsource_sql(SigmaLogSource(product="linux")) == "source_type IN ('authlog', 'syslog')"
    assert logsource_sql(SigmaLogSource(product="linux", category="process_creation")) is None
    assert logsource_sql(SigmaLogSource(category="webserver")) == "source_type = 'web'"
    assert logsource_sql(SigmaLogSource(product="apache", category="webserver")) == "source_type = 'web'"
    assert logsource_sql(SigmaLogSource(product="macos", category="process_creation")) is None
    assert logsource_sql(SigmaLogSource(product="windows", category="no_such_thing")) is None


def test_load_rules_and_report():
    rules, report = load_rules([RULES])
    assert sorted(r.title for r in rules) == ["Encoded PowerShell", "SQL Injection Strings In URI", "SSH Failed Password"]
    assert report.loaded == 3
    reasons = dict(report.unsupported)
    assert any("logsource" in v for k, v in reasons.items() if k.startswith("macOS Thing"))
    assert any("correlation" in v for k, v in reasons.items() if k.startswith("Many Failed Logons"))
    assert any("malformed.yml" in k for k in reasons)
    assert any("experimental" in v for k, v in reasons.items() if k.startswith("Experimental Whoami"))


def test_status_filter_override():
    rules, _ = load_rules([RULES], statuses={"experimental"})
    assert [r.title for r in rules] == ["Experimental Whoami"]


def test_compiled_rule_metadata():
    rules, _ = load_rules([RULES])
    ps = next(r for r in rules if r.title == "Encoded PowerShell")
    assert ps.rule_id == "6f7b9a50-0000-4000-8000-000000000002"
    assert ps.level == "high" and ps.techniques == ["T1059.001", "T1027"]
    assert ps.path.name == "encoded_ps.yml"


def test_techniques_from_tags():
    assert techniques_from_tags(["attack.t1059.001", "attack.execution", "cve.2021-1", "attack.T1110"]) == ["T1059.001", "T1110"]


def test_missing_dir_is_reported(tmp_path):
    rules, report = load_rules([tmp_path / "nope"])
    assert rules == [] and "not found" in report.unsupported[0][1]
