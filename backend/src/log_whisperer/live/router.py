"""Route a live line to the right line parser (reuses the file parsers from Phase 2)."""

from datetime import datetime, timezone

from log_whisperer.live.syslog import LiveLine
from log_whisperer.models import Event
from log_whisperer.parsers import authlog, webaccess, winjson

AUTH_PROGRAMS = {"sshd", "sudo", "su", "useradd", "adduser", "usermod", "userdel", "groupadd", "gpasswd",
                 "passwd", "chpasswd", "login", "systemd-logind", "cron", "crond"}


def route_line(item: LiveLine, counter: int) -> Event | None:
    """Return a normalized event or None. `counter` keeps record refs unique per source."""
    year = datetime.now(timezone.utc).year
    payload = item.syslog.message if item.syslog else item.line
    if payload.lstrip().startswith("{") and (e := winjson.parse_line(payload, counter, item.source)):
        return e
    if e := webaccess.parse_line(payload, counter, item.source, host=item.syslog.host if item.syslog else None):
        return e
    if e := authlog.parse_line(item.line, counter, item.source, year):
        if (e.process or "").lower() not in AUTH_PROGRAMS:
            e = e.model_copy(update={"source_type": "syslog", "channel": "syslog"})
        return e
    return None
