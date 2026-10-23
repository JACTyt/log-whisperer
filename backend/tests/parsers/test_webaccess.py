from datetime import datetime
from pathlib import Path

from log_whisperer.parsers.webaccess import WebAccessParser, parse_line

FIXTURES = Path(__file__).parents[1] / "fixtures"
LINES = (FIXTURES / "access.log").read_text().splitlines()


def test_normal_request():
    e = parse_line(LINES[0], 1, "access.log")
    assert (e.action, e.outcome, e.event_code, e.src_ip) == ("http_request", "success", "200", "192.168.10.5")
    assert (e.source_type, e.channel) == ("web", "access")
    assert e.fields["cs-method"] == "GET" and e.fields["cs-uri-stem"] == "/"
    assert e.fields["cs-user-agent"].startswith("Mozilla/5.0")
    assert e.ts == datetime(2026, 3, 14, 13, 50)


def test_query_split_and_sqli():
    e = parse_line(LINES[5], 6, "access.log")
    assert e.fields["cs-uri-stem"] == "/products.php"
    assert e.fields["cs-uri-query"] == "id=1'%20OR%201=1--%20-"
    assert e.fields["cs-uri"] == "/products.php?id=1'%20OR%201=1--%20-"
    assert e.outcome == "failure" and e.fields["sc-status"] == 500
    assert "sqlmap" in e.fields["cs-user-agent"]
    assert e.command_line == "GET /products.php?id=1'%20OR%201=1--%20-"


def test_ipv6_user_dash_size():
    e = parse_line(LINES[8], 9, "access.log")
    assert e.src_ip == "2001:db8::1" and e.user == "alice"
    assert e.fields["sc-bytes"] is None and e.fields["cs-version"] == "HTTP/2.0"


def test_dash_request():
    e = parse_line(LINES[9], 10, "access.log")
    assert e.fields["cs-method"] is None and e.event_code == "400"


def test_common_log_format():
    e = parse_line(LINES[10], 11, "access.log")
    assert e.fields["cs-user-agent"] is None and e.event_code == "200"


def test_host_argument():
    assert parse_line(LINES[0], 1, "a", host="web01").host == "web01"


def test_garbage():
    assert parse_line("Mar 14 14:02:01 web01 sshd[1]: hi", 1, "a") is None


def test_parse_file_and_sniff():
    p = WebAccessParser()
    assert p.can_parse(FIXTURES / "access.log")
    assert not p.can_parse(FIXTURES / "auth.log")
    assert len(list(p.parse(FIXTURES / "access.log"))) == 11
