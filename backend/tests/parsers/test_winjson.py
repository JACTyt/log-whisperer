from datetime import datetime
from pathlib import Path

from log_whisperer.parsers.winjson import WinJsonParser, parse_line

FIXTURES = Path(__file__).parents[1] / "fixtures"


def _lines(name):
    return (FIXTURES / name).read_text().splitlines()


def test_flat_logon_failure_matches_evtx_semantics():
    e = parse_line(_lines("winjson_flat.jsonl")[0], 1, "f.jsonl")
    assert (e.action, e.outcome, e.event_code) == ("logon", "failure", "4625")
    assert e.user == "administrator" and e.src_ip == "10.0.0.5"
    assert e.host == "WORKSTATION5.theshire.local" and e.channel == "Security"
    assert e.source_type == "winjson" and e.record_ref == "line:1"
    assert "Message" not in e.fields and e.fields["EventID"] == "4625"
    assert e.ts == datetime(2020, 8, 7, 14, 32, 25, 358000)


def test_winlogbeat_shape():
    e = parse_line(_lines("winjson_winlogbeat.jsonl")[0], 1, "f.jsonl")
    assert (e.action, e.outcome, e.user, e.src_ip) == ("logon", "failure", "administrator", "10.0.0.5")
    assert e.host == "WORKSTATION5.theshire.local"
    assert e.fields["TargetDomainName"] == "THESHIRE"


def test_sysmon_uses_utctime():
    e = parse_line(_lines("winjson_flat.jsonl")[1], 2, "f.jsonl")
    assert e.action == "process_start" and e.process.endswith("powershell.exe")
    assert e.command_line.startswith("powershell.exe -nop") and e.user == "pgustavo"
    assert e.ts == datetime(2020, 8, 7, 14, 32, 22, 692000)


def test_offset_timestamp_to_utc():
    e = parse_line(_lines("winjson_flat.jsonl")[3], 4, "f.jsonl")
    assert e.ts == datetime(2020, 8, 7, 14, 32, 25, 358000)
    assert e.outcome == "success" and e.src_ip is None


def test_bad_lines_return_none():
    lines = _lines("winjson_flat.jsonl")
    assert parse_line(lines[2], 3, "f") is None
    assert parse_line(lines[4], 5, "f") is None


def test_timecreated_only_record_parses():
    line = '{"TimeCreated":"2020-10-19 12:28:44.333","EventID":5156,"Channel":"Security","Hostname":"WS5"}'
    assert parse_line(line, 1, "f").ts == datetime(2020, 10, 19, 12, 28, 44, 333000)


def _write(tmp_path, lines):
    import json

    f = tmp_path / "x.json"
    f.write_text("\n".join(json.dumps(o) for o in lines) + "\n")
    return f


def test_file_clock_offset_calibrated_from_sysmon_utctime(tmp_path):
    # collector stamped local time with a bogus Z; Sysmon UtcTime is 4h later and authoritative
    sysmon = [{"@timestamp": f"2020-10-23T02:3{i}:40.000Z", "UtcTime": f"2020-10-23 06:3{i}:40.000",
               "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS5",
               "Image": "C:\\x\\bitsadmin.exe"} for i in range(5)]
    security = {"@timestamp": "2020-10-23T02:37:00.000Z", "EventID": 4624, "Channel": "Security",
                "Hostname": "WS5", "TargetUserName": "wardog"}
    events = list(WinJsonParser().parse(_write(tmp_path, [*sysmon, security])))
    assert events[-1].ts == datetime(2020, 10, 23, 6, 37)
    assert events[0].ts == datetime(2020, 10, 23, 6, 30, 40)


def test_local_timecreated_calibrated(tmp_path):
    sysmon = [{"TimeCreated": "2020-10-19 12:29:00.013", "UtcTime": "2020-10-19 04:29:00.004", "EventID": 10,
               "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS5"}] * 3
    sec = {"TimeCreated": "2020-10-19 12:30:00.000", "EventID": 4688, "Channel": "Security", "Hostname": "WS5"}
    events = list(WinJsonParser().parse(_write(tmp_path, [*sysmon, sec])))
    assert events[-1].ts == datetime(2020, 10, 19, 4, 30)


def test_no_offset_when_clocks_agree(tmp_path):
    rec = {"@timestamp": "2020-08-07T14:32:25.358Z", "UtcTime": "2020-08-07 14:32:22.692", "EventID": 1,
           "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS5"}
    sec = {"@timestamp": "2020-08-07T14:40:00.000Z", "EventID": 4624, "Channel": "Security", "Hostname": "WS5"}
    events = list(WinJsonParser().parse(_write(tmp_path, [rec, rec, sec])))
    assert events[-1].ts == datetime(2020, 8, 7, 14, 40)


def test_parse_file_counts_skipped():
    p = WinJsonParser()
    assert p.can_parse(FIXTURES / "winjson_flat.jsonl")
    assert len(list(p.parse(FIXTURES / "winjson_flat.jsonl"))) == 3
    assert p.skipped == 2
    assert not p.can_parse(FIXTURES / "auth.log")
