"""RFC 3164 / RFC 5424 syslog parsing and an asyncio UDP+TCP listener."""

import asyncio
import logging
import random
import re
from dataclasses import dataclass
from datetime import datetime, timezone

log = logging.getLogger(__name__)

_PRI = re.compile(rb"^<(\d{1,3})>")
_5424 = re.compile(
    r"^1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$", re.S)
_3164 = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?P<prog>[^\s\[:]+)(?:\[(?P<pid>[^\]]+)\])?: ?(?P<msg>.*)$", re.S)


@dataclass
class SyslogMessage:
    ts: datetime  # naive UTC
    host: str
    program: str
    pid: str | None
    message: str
    raw: str

    def to_line(self) -> str:
        """Classic syslog line with an RFC 3339 timestamp, readable by the auth.log parser."""
        pid = f"[{self.pid}]" if self.pid else ""
        return f"{self.ts:%Y-%m-%dT%H:%M:%S}+00:00 {self.host} {self.program}{pid}: {self.message}"


def parse_syslog(data: bytes, now: datetime, peer: str = "unknown") -> SyslogMessage | None:
    """Parse one syslog message. `now` (naive UTC) supplies the year for RFC 3164."""
    raw = data.rstrip(b"\r\n\x00")
    body = _PRI.sub(b"", raw, count=1)
    text = body.decode("utf-8", errors="replace")
    if m := _5424.match(text):
        try:
            ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None) if ts.tzinfo else ts
        except ValueError:
            ts = now
        msg = (m["msg"] or "").lstrip("﻿")
        host = peer if m["host"] == "-" else m["host"]
        return SyslogMessage(ts, host, "-" if m["app"] == "-" else m["app"],
                             None if m["pid"] == "-" else m["pid"], msg, raw.decode("utf-8", "replace"))
    if m := _3164.match(text):
        try:
            ts = datetime.strptime(f"{now.year} {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None
        if ts > now.replace(microsecond=0) and (ts - now).days > 1:  # December message received in January
            ts = ts.replace(year=now.year - 1)
        return SyslogMessage(ts, m["host"], m["prog"], m["pid"], m["msg"], raw.decode("utf-8", "replace"))
    return None


@dataclass
class LiveLine:
    source: str
    line: str
    syslog: SyslogMessage | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class _UDP(asyncio.DatagramProtocol):
    def __init__(self, server: "SyslogServer"):
        self.server = server

    def datagram_received(self, data: bytes, addr) -> None:
        self.server._accept(data, addr[0], block=False)


class SyslogServer:
    def __init__(self, queue: asyncio.Queue, host: str = "127.0.0.1", port: int = 5514):
        self.queue = queue
        self.host = host
        self.port = port
        self.received = 0
        self.dropped = 0
        self._udp: asyncio.DatagramTransport | None = None
        self._tcp: asyncio.base_events.Server | None = None

    def _accept(self, data: bytes, peer: str, block: bool) -> asyncio.Future | None:
        msg = parse_syslog(data, _utcnow(), peer)
        if msg is None:
            self.dropped += 1
            return None
        self.received += 1
        item = LiveLine(source=f"syslog://{peer}", line=msg.to_line(), syslog=msg)
        if block:
            return asyncio.ensure_future(self.queue.put(item))
        try:
            self.queue.put_nowait(item)
        except asyncio.QueueFull:
            self.dropped += 1
        return None

    async def _tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = (writer.get_extra_info("peername") or ("unknown",))[0]
        try:
            while True:
                first = await reader.read(1)
                if not first:
                    break
                if first.isdigit():  # octet-counted framing (RFC 6587)
                    count = first + await reader.readuntil(b" ")
                    data = await reader.readexactly(int(count.strip()))
                else:
                    data = first + await reader.readline()
                if data.strip():
                    fut = self._accept(data, peer, block=True)
                    if fut is not None:
                        await fut  # backpressure: wait while the queue is full
        except (asyncio.IncompleteReadError, ConnectionResetError, ValueError):
            pass
        finally:
            writer.close()

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        requested = self.port
        # Port 0: try random high ports until UDP and TCP both bind (Windows reserves ranges per protocol).
        candidates = [requested] if requested else random.sample(range(20000, 60000), 50)
        last: OSError | None = None
        for port in candidates:
            try:
                self._udp, _ = await loop.create_datagram_endpoint(lambda: _UDP(self),
                                                                   local_addr=(self.host, port))
            except OSError as exc:
                last = exc
                continue
            try:
                self._tcp = await asyncio.start_server(self._tcp_client, self.host, port)
            except OSError as exc:
                last = exc
                self._udp.close()
                await asyncio.sleep(0)
                continue
            self.port = port
            break
        else:
            raise OSError(f"could not bind syslog UDP+TCP on {self.host}:{requested or 'any'}: {last}")
        log.info("syslog listening on %s:%d (udp+tcp)", self.host, self.port)

    async def stop(self) -> None:
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()
            await self._tcp.wait_closed()
        self._udp = self._tcp = None
        for _ in range(3):  # transport.close() frees the socket in a later loop callback
            await asyncio.sleep(0)
