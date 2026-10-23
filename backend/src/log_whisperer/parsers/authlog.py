"""Linux auth.log / secure (BSD syslog or RFC 3339 timestamps)."""

import re
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from log_whisperer.ids import normalize_user
from log_whisperer.models import Event
from log_whisperer.parsers.textio import TextLineParser, open_text

_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

_BSD = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)

_FAILED = re.compile(r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.*)$")
_USERADD = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_GROUPADD = re.compile(r"new group: name=(?P<group>[^,\s]+)")
_USERMOD = re.compile(r"add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")
_GPASSWD = re.compile(r"user (?P<user>\S+) added by \S+ to group (?P<group>\S+)")
_USERDEL = re.compile(r"delete user '(?P<user>[^']+)'")
_PASSWD = re.compile(r"password changed for (?P<user>\S+)")
_SU = re.compile(r"session opened for user (?P<target>[^\s(]+)(?:\(uid=\d+\))? by (?P<user>[^\s(]*)")
_SU_LEGACY = re.compile(r"^\(to (?P<target>\S+)\) (?P<user>\S+) on")


def _classify(prog: str, msg: str) -> dict[str, Any]:
    """Return column/field overrides for a syslog message body."""
    p = prog.lower()
    if p == "sshd":
        if m := _FAILED.match(msg):
            return {"action": "ssh_auth", "outcome": "failure", "user": m["user"], "src_ip": m["ip"],
                    "fields": {"method": m["method"], "port": m["port"], "invalid_user": bool(m["invalid"])}}
        if m := _ACCEPTED.match(msg):
            return {"action": "ssh_auth", "outcome": "success", "user": m["user"], "src_ip": m["ip"],
                    "fields": {"method": m["method"], "port": m["port"]}}
        if m := _INVALID.match(msg):
            return {"action": "ssh_auth", "outcome": "failure", "user": m["user"], "src_ip": m["ip"],
                    "fields": {"method": "none", "port": m["port"], "invalid_user": True}}
    elif p == "sudo" and (m := _SUDO.match(msg)):
        rest = m["rest"]
        parts = dict(kv.split("=", 1) for kv in (s.strip() for s in rest.split(" ; ")) if "=" in kv)
        failed = "NOT in sudoers" in rest or "incorrect password" in rest
        return {"action": "sudo", "outcome": "failure" if failed else "success", "user": m["user"],
                "command_line": parts.get("COMMAND"), "fields": {"target_user": parts.get("USER")}}
    elif p in ("useradd", "adduser"):
        if m := _USERADD.search(msg):
            return {"action": "user_created", "outcome": "success", "user": m["user"]}
        if m := _GROUPADD.search(msg):
            return {"action": "group_created", "outcome": "success", "fields": {"group": m["group"]}}
    elif p == "groupadd" and (m := _GROUPADD.search(msg)):
        return {"action": "group_created", "outcome": "success", "fields": {"group": m["group"]}}
    elif p in ("usermod", "gpasswd"):
        if m := (_USERMOD.search(msg) or _GPASSWD.search(msg)):
            return {"action": "group_member_added", "outcome": "success", "user": m["user"],
                    "fields": {"group": m["group"]}}
    elif p == "userdel" and (m := _USERDEL.search(msg)):
        return {"action": "user_deleted", "outcome": "success", "user": m["user"]}
    elif p in ("passwd", "chpasswd") and (m := _PASSWD.search(msg)):
        return {"action": "password_changed", "outcome": "success", "user": m["user"]}
    elif p == "su":
        if "su:session" in msg and (m := _SU.search(msg)):
            return {"action": "su", "outcome": "success", "user": m["user"] or None,
                    "fields": {"target_user": m["target"]}}
        if m := _SU_LEGACY.match(msg):
            return {"action": "su", "outcome": "success", "user": m["user"],
                    "fields": {"target_user": m["target"]}}
    return {}


def _header(line: str, year: int) -> tuple[datetime, re.Match] | None:
    if m := _BSD.match(line):
        mon = _MONTHS.get(m["mon"])
        if mon is None:
            return None
        try:
            ts = datetime.strptime(f"{year}-{mon:02d}-{int(m['day']):02d} {m['time']}", "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
        return ts, m
    if m := _ISO.match(line):
        try:
            ts = datetime.fromisoformat(m["iso"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return ts, m
    return None


def parse_line(line: str, line_no: int, source_file: str, year: int) -> Event | None:
    line = line.rstrip("\r\n")
    head = _header(line, year)
    if head is None:
        return None
    ts, m = head
    info = _classify(m["prog"], m["msg"])
    fields = {"program": m["prog"], "pid": m["pid"], "message": m["msg"], **info.pop("fields", {})}
    user = info.pop("user", None)
    return Event(
        ts=ts,
        source_type="authlog",
        channel="auth",
        host=m["host"],
        process=m["prog"],
        user=normalize_user(user),
        source_file=source_file,
        record_ref=f"line:{line_no}",
        raw=line,
        fields=fields,
        **info,
    )


def _month(line: str) -> int | None:
    m = _BSD.match(line)
    return _MONTHS.get(m["mon"]) if m else None


def _rollovers(path: Path) -> int:
    count, prev = 0, None
    with open_text(path) as f:
        for line in f:
            mon = _month(line)
            if mon is None:
                continue
            if prev is not None and mon < prev - 6:
                count += 1
            prev = mon
    return count


class AuthLogParser(TextLineParser):
    source_type = "authlog"

    def __init__(self, year: int | None = None) -> None:
        super().__init__()
        self.year = year
        self._year = year or datetime.now().year
        self._prev_month: int | None = None

    def parse_line(self, line: str, line_no: int, source_file: str) -> Event | None:
        mon = _month(line)
        if mon is not None:
            if self._prev_month is not None and mon < self._prev_month - 6:
                self._year += 1
            self._prev_month = mon
        return parse_line(line, line_no, source_file, self._year)

    def parse(self, path: Path) -> Iterator[Event]:
        """Without an explicit year, the file's mtime year is assigned to its *last* lines."""
        if self.year is not None:
            self._year = self.year
        else:
            mtime_year = datetime.fromtimestamp(Path(path).stat().st_mtime).year
            self._year = mtime_year - _rollovers(path)
        self._prev_month = None
        yield from super().parse(path)

    def can_parse(self, path: Path) -> bool:
        self._prev_month = None
        return super().can_parse(path)
