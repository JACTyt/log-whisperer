import asyncio
import socket
from datetime import datetime
from pathlib import Path

import pytest

from log_whisperer.config import Settings
from log_whisperer.live.pipeline import LivePipeline
from log_whisperer.live.router import route_line
from log_whisperer.live.syslog import LiveLine, SyslogServer, parse_syslog
from log_whisperer.live.tailer import FileTailer
from log_whisperer.store import Store

FIX = Path(__file__).parents[1] / "fixtures"
NOW = datetime(2026, 3, 14, 15, 0, 0)


# -- parsing ----------------------------------------------------------------------

def test_rfc3164():
    m = parse_syslog(b"<38>Mar 14 14:02:01 web01 sshd[2201]: Failed password for root from 1.2.3.4 port 1 ssh2", NOW)
    assert (m.ts, m.host, m.program, m.pid) == (datetime(2026, 3, 14, 14, 2, 1), "web01", "sshd", "2201")
    assert m.message.startswith("Failed password")


def test_rfc3164_december_in_january():
    m = parse_syslog(b"<38>Dec 31 23:59:59 h sshd[1]: x", datetime(2026, 1, 1, 0, 5))
    assert m.ts.year == 2025


def test_rfc5424_with_sd_and_bom():
    data = ('<34>1 2026-03-14T14:02:01.5+01:00 web01 sshd 2201 ID47 [exampleSDID@32473 iut="3" '
            'eventSource="App\\]x"] ﻿Failed password for root from 1.2.3.4 port 1 ssh2').encode()
    m = parse_syslog(data, NOW)
    assert m.ts == datetime(2026, 3, 14, 13, 2, 1, 500000) and m.program == "sshd" and m.pid == "2201"
    assert m.message.startswith("Failed password")


def test_rfc5424_nil_fields():
    m = parse_syslog(b"<13>1 2026-03-14T14:02:01Z - - - - - hello", NOW, peer="10.0.0.9")
    assert (m.host, m.program, m.pid, m.message) == ("10.0.0.9", "-", None, "hello")


def test_garbage_none():
    assert parse_syslog(b"\x00\x01 nothing", NOW) is None


def test_route_auth_and_generic_and_web():
    auth = parse_syslog(b"<38>Mar 14 14:02:01 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", NOW)
    e = route_line(LiveLine("syslog://1.1.1.1", auth.to_line(), auth), 7)
    assert (e.source_type, e.action, e.outcome, e.src_ip, e.record_ref) == ("authlog", "ssh_auth", "failure",
                                                                            "1.2.3.4", "line:7")
    kern = parse_syslog(b"<6>Mar 14 14:02:01 web01 kernel: eth0 link up", NOW)
    assert route_line(LiveLine("s", kern.to_line(), kern), 1).source_type == "syslog"
    web_line = (FIX / "access.log").read_text().splitlines()[5]
    nginx = parse_syslog(f"<190>Mar 14 13:59:30 web01 nginx: {web_line}".encode(), NOW)
    e = route_line(LiveLine("s", nginx.to_line(), nginx), 2)
    assert e.source_type == "web" and e.host == "web01"
    assert route_line(LiveLine("tail://x", "random words"), 1) is None


# -- network ----------------------------------------------------------------------

async def _server():
    q: asyncio.Queue = asyncio.Queue(maxsize=10)
    srv = SyslogServer(q, "127.0.0.1", 0)
    await srv.start()
    return q, srv


async def test_udp_and_tcp_roundtrip():
    q, srv = await _server()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<38>Mar 14 14:02:01 web01 sshd[1]: udp msg", ("127.0.0.1", srv.port))
        reader, writer = await asyncio.open_connection("127.0.0.1", srv.port)
        msg = b"<38>Mar 14 14:02:02 web01 sshd[1]: framed msg"
        writer.write(str(len(msg)).encode() + b" " + msg + b"<38>Mar 14 14:02:03 web01 sshd[1]: newline msg\n")
        await writer.drain()
        got = [await asyncio.wait_for(q.get(), 3) for _ in range(3)]
        writer.close()
        assert sorted(i.syslog.message for i in got) == ["framed msg", "newline msg", "udp msg"]
    finally:
        await srv.stop()


async def test_udp_overflow_counted():
    q, srv = await _server()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for i in range(30):
                s.sendto(f"<38>Mar 14 14:02:01 h sshd[1]: m{i}".encode(), ("127.0.0.1", srv.port))
        await asyncio.sleep(0.5)
        assert q.qsize() == 10 and srv.dropped >= 1
    finally:
        await srv.stop()


async def test_stop_start_releases_port():
    q, srv = await _server()
    port = srv.port
    await srv.stop()
    again = SyslogServer(q, "127.0.0.1", port)
    await again.start()
    await again.stop()


# -- tailer ----------------------------------------------------------------------------

async def test_tailer_append_truncate_rotate_and_late_creation(tmp_path):
    q: asyncio.Queue = asyncio.Queue()
    f = tmp_path / "auth.log"
    t = FileTailer(q, f, start_at_end=False)
    assert await t.poll_once() == 0  # file does not exist yet
    f.write_text("one\ntwo\npart")
    assert await t.poll_once() == 2
    with f.open("a") as fh:
        fh.write("ial\nthree\n")
    assert await t.poll_once() == 2
    assert [q.get_nowait().line for _ in range(4)] == ["one", "two", "partial", "three"]
    f.write_text("new\n")  # truncated
    assert await t.poll_once() == 1 and q.get_nowait().line == "new"
    f.rename(tmp_path / "auth.log.1")  # rotated
    f.write_text("rotated-1\nrotated-2\n")
    assert await t.poll_once() == 2


async def test_tailer_start_at_end_skips_existing(tmp_path):
    q: asyncio.Queue = asyncio.Queue()
    f = tmp_path / "x.log"
    f.write_text("old\n")
    t = FileTailer(q, f)
    assert await t.poll_once() == 0
    with f.open("a") as fh:
        fh.write("new\n")
    assert await t.poll_once() == 1


# -- pipeline ----------------------------------------------------------------------------

@pytest.fixture
def settings(tmp_path):
    s = Settings()
    s.detection.sigma_dirs = [FIX / "rules"]
    s.geoip.path = tmp_path / "none.mmdb"
    s.live.syslog_port = 0
    s.live.flush_seconds = 0.2
    return s


async def test_live_bruteforce_becomes_incident(settings):
    store = Store(":memory:")
    p = LivePipeline(store, settings)
    await p.start()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for i in range(12):
                s.sendto(f"<38>Mar 14 14:02:{i:02d} web01 sshd[{i}]: Failed password for root from 203.0.113.7 "
                         f"port {40000 + i} ssh2".encode(), ("127.0.0.1", p.status.syslog_port))
            s.sendto(b"<38>Mar 14 14:09:12 web01 sshd[99]: Accepted password for root from 203.0.113.7 port 1 ssh2",
                     ("127.0.0.1", p.status.syslog_port))
        for _ in range(50):
            await asyncio.sleep(0.1)
            if store.list_incidents():
                break
        [inc] = store.list_incidents()
        assert inc.severity == "high" and "203.0.113.7" in inc.src_ips
        assert p.status.events_total == 13 and p.status.detections_total >= 1
    finally:
        await p.stop()
    assert p.status.running is False
    assert store.sql("SELECT counter FROM live_offsets")[0][0] == 13
    store.close()


async def test_counters_persist_across_restart(settings):
    store = Store(":memory:")
    for round_ in range(2):
        p = LivePipeline(store, settings)
        await p.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<38>Mar 14 14:02:01 web01 sshd[1]: same text", ("127.0.0.1", p.status.syslog_port))
        await asyncio.sleep(0.6)
        await p.stop()
    assert store.count_events() == 2  # identical text, different record refs
    store.close()
