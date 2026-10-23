import os
from datetime import datetime
from pathlib import Path

import pytest

from log_whisperer.parsers.authlog import AuthLogParser, parse_line

FIXTURES = Path(__file__).parents[1] / "fixtures"


def p(line: str, year: int = 2026):
    return parse_line(line, 1, "auth.log", year)


def test_failed_password():
    e = p("Mar 14 14:02:01 web01 sshd[2201]: Failed password for root from 203.0.113.7 port 40001 ssh2")
    assert (e.action, e.outcome, e.user, e.src_ip) == ("ssh_auth", "failure", "root", "203.0.113.7")
    assert (e.host, e.process, e.channel, e.source_type) == ("web01", "sshd", "auth", "authlog")
    assert e.fields["method"] == "password" and e.fields["pid"] == "2201" and e.fields["port"] == "40001"
    assert e.ts == datetime(2026, 3, 14, 14, 2, 1)


def test_failed_invalid_user():
    e = p("Mar 14 14:02:26 web01 sshd[2207]: Failed password for invalid user admin from 203.0.113.7 port 40007 ssh2")
    assert (e.outcome, e.user) == ("failure", "admin")
    assert e.fields["invalid_user"] is True


def test_invalid_user_line():
    e = p("Mar 14 14:02:25 web01 sshd[2207]: Invalid user admin from 203.0.113.7 port 40007")
    assert (e.action, e.outcome, e.user, e.src_ip) == ("ssh_auth", "failure", "admin", "203.0.113.7")


@pytest.mark.parametrize("method", ["password", "publickey"])
def test_accepted(method):
    e = p(f"Mar 14 14:09:12 web01 sshd[2301]: Accepted {method} for root from 203.0.113.7 port 40101 ssh2")
    assert (e.action, e.outcome, e.fields["method"]) == ("ssh_auth", "success", method)


def test_sudo_command():
    e = p("Mar 14 14:14:02 web01 sudo:  backdoor : TTY=pts/1 ; PWD=/home/backdoor ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    assert (e.action, e.outcome, e.user) == ("sudo", "success", "backdoor")
    assert e.command_line == "/usr/bin/cat /etc/shadow" and e.fields["target_user"] == "root"


def test_sudo_not_in_sudoers():
    e = p("Mar 14 14:20:00 web01 sudo:     www : user NOT in sudoers ; TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash")
    assert (e.action, e.outcome, e.user) == ("sudo", "failure", "www")


def test_useradd():
    e = p("Mar 14 14:11:03 web01 useradd[2350]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash")
    assert (e.action, e.user) == ("user_created", "backdoor")


@pytest.mark.parametrize("line", [
    "Mar 14 14:11:31 web01 usermod[2360]: add 'backdoor' to group 'sudo'",
    "Mar 14 14:11:31 web01 usermod[2360]: add 'backdoor' to shadow group 'sudo'",
    "Mar 14 14:11:31 web01 gpasswd[2360]: user backdoor added by root to group sudo",
])
def test_group_add(line):
    e = p(line)
    assert (e.action, e.user, e.fields["group"]) == ("group_member_added", "backdoor", "sudo")


def test_su_session():
    e = p("Mar 14 14:15:10 web01 su: pam_unix(su:session): session opened for user root(uid=0) by backdoor(uid=1002)")
    assert (e.action, e.user, e.fields["target_user"]) == ("su", "backdoor", "root")


def test_password_changed():
    e = p("Mar 14 14:11:20 web01 passwd[2355]: pam_unix(passwd:chauthtok): password changed for backdoor")
    assert (e.action, e.user) == ("password_changed", "backdoor")


def test_other_lines_kept_without_action():
    e = p("Mar 14 13:55:01 web01 CRON[2101]: pam_unix(cron:session): session closed for user root")
    assert e.action is None and e.process == "CRON"


def test_rfc3339_header():
    e = p("2026-03-14T14:02:01.123456+01:00 web01 sshd[2201]: Failed password for root from 203.0.113.7 port 40001 ssh2")
    assert e.ts == datetime(2026, 3, 14, 13, 2, 1, 123456) and e.outcome == "failure"


def test_garbage_is_none():
    assert p("this line is garbage") is None


def test_parse_fixture_file():
    parser = AuthLogParser(year=2026)
    events = list(parser.parse(FIXTURES / "auth.log"))
    assert parser.skipped == 1 and len(events) == 31
    assert sum(1 for e in events if e.action == "ssh_auth" and e.outcome == "failure") == 13


def test_year_rollover_with_explicit_year(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Dec 31 23:59:00 h sshd[1]: Invalid user a from 1.2.3.4\n"
                 "Jan  1 00:01:00 h sshd[2]: Invalid user b from 1.2.3.4\n")
    ts = [e.ts for e in AuthLogParser(year=2025).parse(f)]
    assert ts == [datetime(2025, 12, 31, 23, 59), datetime(2026, 1, 1, 0, 1)]


def test_year_from_mtime_applies_to_last_lines(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Dec 31 23:59:00 h sshd[1]: Invalid user a from 1.2.3.4\n"
                 "Jan  1 00:01:00 h sshd[2]: Invalid user b from 1.2.3.4\n")
    mtime = datetime(2026, 1, 2).timestamp()
    os.utime(f, (mtime, mtime))
    ts = [e.ts for e in AuthLogParser().parse(f)]
    assert ts == [datetime(2025, 12, 31, 23, 59), datetime(2026, 1, 1, 0, 1)]


def test_can_parse():
    assert AuthLogParser().can_parse(FIXTURES / "auth.log")
    assert not AuthLogParser().can_parse(FIXTURES / "access.log")
