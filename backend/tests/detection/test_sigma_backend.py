"""Each test compiles a Sigma rule and EXECUTES it against real stored events."""

from datetime import datetime

import pytest
from sigma.collection import SigmaCollection

from log_whisperer.detection.sigma_backend import compile_rule
from log_whisperer.models import Event
from log_whisperer.store import Store

EVENTS = {
    "enc": {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -NoP -enc SQBFAFgA", "EventID": "1", "LogonType": 3},
    "whoami": {"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /all",
               "EventID": "1", "ParentImage": "C:\\Windows\\System32\\cmd.exe"},
    "quote": {"Image": "C:\\x\\it's.exe", "CommandLine": "100% done_ok", "EventID": "1"},
    "web": {"cs-uri-query": "id=1' OR 1=1--", "sc-status": 500, "EventID": None},
    "flag": {"Enabled": True, "EventID": "4"},
}


@pytest.fixture
def store():
    s = Store(":memory:")
    s.insert_events(
        Event(ts=datetime(2026, 1, 1), source_type="evtx", source_file="f", record_ref=k,
              raw=f"raw text for {k} mimikatz" if k == "whoami" else f"raw {k}", fields=v, event_id=k)
        for k, v in EVENTS.items()
    )
    yield s
    s.close()


def match(store: Store, detection_yaml: str) -> set[str]:
    rule = SigmaCollection.from_yaml(
        "title: t\nid: 11111111-1111-1111-1111-111111111111\nstatus: test\n"
        "logsource: {product: windows, category: process_creation}\n" + detection_yaml
    ).rules[0]
    sql = compile_rule(rule)
    return {r[0] for r in store._q(f"SELECT event_id FROM events WHERE {sql}")}


def test_equals_case_insensitive(store):
    assert match(store, "detection:\n  sel:\n    Image: 'c:\\windows\\system32\\WHOAMI.exe'\n  condition: sel") == {"whoami"}


def test_endswith_startswith_contains(store):
    assert match(store, "detection:\n  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel") == {"enc"}
    assert match(store, "detection:\n  sel:\n    CommandLine|startswith: 'WHOAMI'\n  condition: sel") == {"whoami"}
    assert match(store, "detection:\n  sel:\n    CommandLine|contains: ' -enc '\n  condition: sel") == {"enc"}


def test_contains_all(store):
    y = "detection:\n  sel:\n    CommandLine|contains|all: ['-nop', '-enc']\n  condition: sel"
    assert match(store, y) == {"enc"}


def test_windash(store):
    y = "detection:\n  sel:\n    CommandLine|windash|contains: ' -enc '\n  condition: sel"
    assert match(store, y) == {"enc"}


def test_wildcards_inside(store):
    assert match(store, "detection:\n  sel:\n    CommandLine: 'who*all'\n  condition: sel") == {"whoami"}
    assert match(store, "detection:\n  sel:\n    CommandLine: 'whoam? /all'\n  condition: sel") == {"whoami"}


def test_sql_specials_are_literal(store):
    assert match(store, "detection:\n  sel:\n    CommandLine: '100% done_ok'\n  condition: sel") == {"quote"}
    assert match(store, "detection:\n  sel:\n    CommandLine: '100x done_ok'\n  condition: sel") == set()
    assert match(store, "detection:\n  sel:\n    CommandLine: '100% doneXok'\n  condition: sel") == set()
    assert match(store, "detection:\n  sel:\n    Image|contains: \"it's\"\n  condition: sel") == {"quote"}


def test_regex(store):
    assert match(store, "detection:\n  sel:\n    CommandLine|re: '-enc [A-Za-z0-9]+$'\n  condition: sel") == {"enc"}
    assert match(store, "detection:\n  sel:\n    CommandLine|re: '-ENC'\n  condition: sel") == set()
    assert match(store, "detection:\n  sel:\n    CommandLine|re|i: '-ENC'\n  condition: sel") == {"enc"}


def test_quote_in_field_name_and_hyphen(store):
    assert match(store, "detection:\n  sel:\n    cs-uri-query|contains: \"' OR 1=1\"\n  condition: sel") == {"web"}


def test_number_and_bool(store):
    assert match(store, "detection:\n  sel:\n    LogonType: 3\n  condition: sel") == {"enc"}
    assert match(store, "detection:\n  sel:\n    sc-status: 500\n  condition: sel") == {"web"}
    assert match(store, "detection:\n  sel:\n    Enabled: true\n  condition: sel") == {"flag"}


def test_null_value(store):
    assert match(store, "detection:\n  sel:\n    ParentImage: null\n  condition: sel") == {"enc", "quote", "web", "flag"}


def test_one_of_and_not(store):
    y = ("detection:\n  selection_a:\n    Image|endswith: '\\whoami.exe'\n"
         "  selection_b:\n    Image|endswith: '\\powershell.exe'\n"
         "  filter:\n    CommandLine|contains: '-enc'\n"
         "  condition: 1 of selection_* and not filter")
    assert match(store, y) == {"whoami"}


def test_all_of_them(store):
    y = ("detection:\n  a:\n    Image|endswith: 'whoami.exe'\n  b:\n    CommandLine|contains: '/all'\n"
         "  condition: all of them")
    assert match(store, y) == {"whoami"}


def test_keywords_match_raw(store):
    assert match(store, "detection:\n  keywords:\n    - 'MIMIKATZ'\n  condition: keywords") == {"whoami"}


def test_missing_field_no_match(store):
    assert match(store, "detection:\n  sel:\n    NoSuchField: 'x'\n  condition: sel") == set()


def test_cidr(store):
    store.insert_events([Event(ts=datetime(2026, 1, 1), source_type="evtx", source_file="f",
                               record_ref="ip", raw="r", fields={"SourceIp": "10.1.2.3"}, event_id="ip")])
    assert match(store, "detection:\n  sel:\n    SourceIp|cidr: '10.0.0.0/8'\n  condition: sel") == {"ip"}
