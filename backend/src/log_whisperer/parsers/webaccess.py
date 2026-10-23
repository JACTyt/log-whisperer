"""Apache / Nginx access logs (combined or common log format)."""

import re
from datetime import datetime

from log_whisperer.models import Event
from log_whisperer.parsers.textio import TextLineParser

_LINE = re.compile(
    r'^(?P<ip>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] '
    r'"(?P<req>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>(?:[^"\\]|\\.)*)" "(?P<ua>(?:[^"\\]|\\.)*)")?'
)


def _dash(v: str | None) -> str | None:
    return None if v in (None, "", "-") else v


def parse_line(line: str, line_no: int, source_file: str, host: str | None = None) -> Event | None:
    line = line.rstrip("\r\n")
    m = _LINE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    method = uri = version = None
    parts = m["req"].split(" ")
    if len(parts) >= 2:
        method, uri = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else None
    stem, _, query = (uri or "").partition("?")
    status = int(m["status"])
    size = _dash(m["size"])
    fields = {
        "c-ip": m["ip"],
        "cs-username": _dash(m["user"]),
        "cs-method": method,
        "cs-uri": uri,
        "cs-uri-stem": stem or None,
        "cs-uri-query": query or None,
        "cs-version": version,
        "sc-status": status,
        "sc-bytes": int(size) if size and size.isdigit() else None,
        "cs-referer": _dash(m["ref"]),
        "cs-user-agent": _dash(m["ua"]),
    }
    return Event(
        ts=ts,
        source_type="web",
        channel="access",
        host=host,
        src_ip=m["ip"],
        user=_dash(m["user"]),
        command_line=f"{method} {uri}" if method else None,
        action="http_request",
        outcome="success" if status < 400 else "failure",
        event_code=str(status),
        source_file=source_file,
        record_ref=f"line:{line_no}",
        raw=line,
        fields=fields,
    )


class WebAccessParser(TextLineParser):
    source_type = "web"

    def __init__(self, host: str | None = None) -> None:
        super().__init__()
        self.host = host

    def parse_line(self, line: str, line_no: int, source_file: str) -> Event | None:
        return parse_line(line, line_no, source_file, self.host)
