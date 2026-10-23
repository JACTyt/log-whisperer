from datetime import timedelta

from log_whisperer.incidents.grouping import group_detections
from log_whisperer.models import Detection
from tests.helpers import T0

GAP = timedelta(minutes=30)


def det(rule: str, minute: float, end: float | None = None, severity="medium", techniques=(), **ent) -> Detection:
    return Detection(
        rule_id=rule, rule_title=rule, rule_source="sigma", severity=severity, techniques=list(techniques),
        event_ids=[f"{rule}-{minute}"], ts_first=T0 + timedelta(minutes=minute),
        ts_last=T0 + timedelta(minutes=end if end is not None else minute),
        hosts=ent.get("hosts", []), users=ent.get("users", []), src_ips=ent.get("src_ips", []),
    )


def test_shared_host_within_gap_merges():
    [inc] = group_detections([det("a", 0, hosts=["web01"]), det("b", 20, hosts=["web01"])], GAP)
    assert len(inc.detection_ids) == 2


def test_gap_splits():
    incs = group_detections([det("a", 0, hosts=["web01"]), det("b", 45, hosts=["web01"])], GAP)
    assert len(incs) == 2


def test_long_detection_extends_window():
    incs = group_detections([det("a", 0, end=40, hosts=["h"]), det("b", 60, hosts=["h"])], GAP)
    assert len(incs) == 1


def test_noise_entities_do_not_link():
    incs = group_detections([det("a", 0, users=["system"], hosts=["a"]), det("b", 1, users=["SYSTEM"], hosts=["b"]),
                             det("c", 2, users=["ws01$"], hosts=["c"]), det("d", 3, users=["ws01$"], hosts=["d"]),
                             det("e", 4, src_ips=["127.0.0.1"]), det("f", 5, src_ips=["127.0.0.1"])], GAP)
    assert len(incs) == 6


def test_chain_linking():
    incs = group_detections([det("a", 0, hosts=["h1"]), det("b", 5, hosts=["h1"], src_ips=["1.2.3.4"]),
                             det("c", 10, src_ips=["1.2.3.4"], hosts=["h2"])], GAP)
    assert len(incs) == 1 and incs[0].hosts == ["h1", "h2"]


def test_same_log_line_is_one_incident_even_without_entities():
    # two rules matched the same line; the line has no host/user/IP to link them
    a, b = det("rule-a", 0), det("rule-b", 0)
    b.event_ids = a.event_ids
    [inc] = group_detections([a, b], GAP)
    assert len(inc.detection_ids) == 2


def test_no_entities_own_incident():
    assert len(group_detections([det("a", 0), det("b", 1)], GAP)) == 2


def test_aggregates():
    [inc] = group_detections([
        det("low", 0, severity="low", techniques=["T1110.001"], hosts=["web01"], users=["root"]),
        det("high", 5, end=9, severity="high", techniques=["T1136.001", "T1110.001"], hosts=["web01"], src_ips=["1.2.3.4"]),
    ], GAP)
    assert inc.severity == "high"
    assert inc.techniques == ["T1110.001", "T1136.001"]
    assert (inc.ts_start, inc.ts_end) == (T0, T0 + timedelta(minutes=9))
    assert inc.users == ["root"] and inc.src_ips == ["1.2.3.4"]
    assert inc.title == "high (+1 more)"


def test_incident_id_stable_when_later_detection_added():
    a, b = det("a", 0, hosts=["h"]), det("b", 5, hosts=["h"])
    [first] = group_detections([a, b], GAP)
    [second] = group_detections([a, b, det("c", 10, hosts=["h"])], GAP)
    assert first.incident_id == second.incident_id


def test_sorted_by_start():
    incs = group_detections([det("b", 100, hosts=["x"]), det("a", 0, hosts=["y"])], GAP)
    assert [i.ts_start for i in incs] == sorted(i.ts_start for i in incs)
