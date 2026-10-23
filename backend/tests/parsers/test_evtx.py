import json
from datetime import datetime
from pathlib import Path

import pytest

from log_whisperer.parsers.evtx import EvtxParser, parse_record

FIXTURES = Path(__file__).parents[1] / "fixtures"
SAMPLES = Path(__file__).parents[3] / "datasets" / "evtx-attack-samples"


@pytest.fixture(scope="module")
def records() -> dict[str, dict]:
    raw = json.loads((FIXTURES / "evtx_records.json").read_text())
    return {k: v | {"data": json.dumps(v["data"])} for k, v in raw.items()}


def test_logon_failure(records):
    e = parse_record(records["4625"], "x.evtx")
    assert (e.action, e.outcome, e.event_code) == ("logon", "failure", "4625")
    assert e.user == "administrator" and e.src_ip == "10.0.0.5"
    assert e.channel == "Security" and e.host == "WS01.corp.local"
    assert e.process == "C:\\Windows\\System32\\svchost.exe"
    assert e.record_ref == "record:2" and e.source_type == "evtx"
    assert e.fields["EventID"] == "4625"
    assert e.fields["LogonType"] == 3
    assert e.fields["Provider_Name"] == "Microsoft-Windows-Security-Auditing"
    assert json.loads(e.raw)["Event"]["System"]["EventID"] == 4625


def test_eventid_as_text_dict(records):
    e = parse_record(records["4624_textid"], "x.evtx")
    assert (e.event_code, e.action, e.outcome) == ("4624", "logon", "success")


def test_dash_ip_is_none(records):
    assert parse_record(records["4624_textid"], "x.evtx").src_ip is None


def test_seven_digit_fraction_timestamp(records):
    assert parse_record(records["4624_textid"], "x.evtx").ts == datetime(2020, 9, 9, 13, 19)


def test_timestamp_is_utc_naive(records):
    e = parse_record(records["4625"], "x.evtx")
    assert e.ts == datetime(2020, 9, 9, 13, 18, 23, 627952) and e.ts.tzinfo is None


def test_process_creation_4688(records):
    e = parse_record(records["4688"], "x.evtx")
    assert e.action == "process_start"
    assert e.process == "C:\\Windows\\System32\\cmd.exe"
    assert e.command_line == "cmd.exe /c whoami" and e.user == "bob"


def test_4688_gets_sysmon_aliases_for_sigma(records):
    e = parse_record(records["4688"], "x.evtx")
    assert e.fields["Image"] == "C:\\Windows\\System32\\cmd.exe"
    assert e.fields["ParentImage"] == "C:\\Windows\\explorer.exe"
    assert e.fields["User"] == "EXAMPLE\\bob"


def test_user_created(records):
    e = parse_record(records["4720"], "x.evtx")
    assert (e.action, e.user) == ("user_created", "backdoor")


def test_group_member_added_from_cn(records):
    e = parse_record(records["4732"], "x.evtx")
    assert (e.action, e.user) == ("group_member_added", "backdoor")
    assert e.fields["TargetUserName"] == "Administrators"


def test_group_member_added_dash_member(records):
    e = parse_record(records["4732_dash"], "x.evtx")
    assert e.action == "group_member_added" and e.user is None
    assert e.fields["MemberSid"] == "S-1-5-21-1-2-3-501"


def test_script_block(records):
    e = parse_record(records["4104"], "x.evtx")
    assert e.action == "script_block" and "DownloadString" in e.command_line


def test_sysmon_process(records):
    e = parse_record(records["sysmon1"], "x.evtx")
    assert e.action == "process_start"
    assert e.process.endswith("powershell.exe")
    assert e.command_line == "powershell -nop -enc SQBFAFgA" and e.user == "bouss"


def test_sysmon_network(records):
    e = parse_record(records["sysmon3"], "x.evtx")
    assert e.action == "network_connection"
    assert (e.src_ip, e.dst_ip) == ("192.168.1.20", "198.51.100.9")


def test_ipv4_mapped_address_stripped(records):
    e = parse_record(records["4771_mapped"], "x.evtx")
    assert e.src_ip == "10.0.0.7" and e.outcome == "failure" and e.user == "alice"


def test_share_access_5145():
    from log_whisperer.parsers.windows_fields import derive

    out = derive({"EventID": "5145", "Channel": "Security", "SubjectUserName": "bob",
                  "IpAddress": "10.0.0.9", "ShareName": "\\\\*\\ADMIN$"})
    assert (out["action"], out["user"], out["src_ip"]) == ("share_access", "bob", "10.0.0.9")


def test_null_eventdata_does_not_crash(records):
    e = parse_record(records["null_eventdata"], "x.evtx")
    assert e.event_code == "306" and e.action is None


def test_unnamed_data_list(records):
    e = parse_record(records["unnamed"], "x.evtx")
    assert e.fields["Data_0"] == "foo" and e.fields["Data_1"] == "3392"
    assert e.event_code == "326"


def test_userdata_flattened(records):
    e = parse_record(records["userdata"], "x.evtx")
    assert e.fields["Param1"] == "admin" and e.fields["Param3"] == "10.0.0.9"
    assert "#attributes" not in e.fields


def test_null_channel(records):
    e = parse_record(records["no_channel"], "x.evtx")
    assert e.channel is None and e.event_code == "0"


def test_can_parse_magic(tmp_path):
    good = tmp_path / "a.evtx"
    good.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
    bad = tmp_path / "b.log"
    bad.write_text("Mar 14 14:02:01 web01 sshd[1]: hello")
    assert EvtxParser().can_parse(good)
    assert not EvtxParser().can_parse(bad)
    assert not EvtxParser().can_parse(tmp_path / "missing.evtx")


@pytest.mark.skipif(not SAMPLES.exists(), reason="datasets not downloaded")
def test_real_samples_parse():
    files = sorted(SAMPLES.rglob("*.evtx"))[:20]
    total = sum(1 for f in files for _ in EvtxParser().parse(f))
    assert total > 0
