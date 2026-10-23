"""Live pipeline: sources -> queue -> batched insert -> incremental detection -> regroup."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime

from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.detection.sigma_rules import load_rules
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.live.router import route_line
from log_whisperer.live.syslog import LiveLine, SyslogServer
from log_whisperer.live.tailer import FileTailer
from log_whisperer.models import Event
from log_whisperer.store import Store

log = logging.getLogger(__name__)


@dataclass
class LiveStatus:
    running: bool = False
    sources: list[str] = field(default_factory=list)
    events_total: int = 0
    unparsed_total: int = 0
    detections_total: int = 0
    flushes: int = 0
    last_flush: datetime | None = None
    last_error: str | None = None
    syslog_port: int | None = None


class LivePipeline:
    def __init__(self, store: Store, settings: Settings):
        self.store = store
        self.settings = settings
        self.status = LiveStatus()
        self.queue: asyncio.Queue[LiveLine] = asyncio.Queue(maxsize=settings.live.queue_max)
        self.syslog: SyslogServer | None = None
        self.tailers: list[FileTailer] = []
        self._task: asyncio.Task | None = None
        self._rules = None
        self._counters: dict[str, int] = {}

    def _load_counters(self) -> None:
        self._counters = dict(self.store.sql("SELECT source, counter FROM live_offsets"))

    def _save_counters(self, sources: set[str]) -> None:
        for s in sources:
            self.store.sql("INSERT OR REPLACE INTO live_offsets VALUES (?, ?)", [s, self._counters[s]])

    async def start(self, syslog: bool = True) -> None:
        if self.status.running:
            return
        cfg = self.settings.live
        self._rules, _ = await asyncio.to_thread(load_rules, self.settings.detection.sigma_dirs)
        await asyncio.to_thread(self._load_counters)
        if syslog:
            self.syslog = SyslogServer(self.queue, cfg.bind, cfg.syslog_port)
            await self.syslog.start()
            self.status.syslog_port = self.syslog.port
            self.status.sources.append(f"syslog://{cfg.bind}:{self.syslog.port}")
        for path in cfg.tail_paths:
            t = FileTailer(self.queue, path)
            t.start()
            self.tailers.append(t)
            self.status.sources.append(t.source)
        self._task = asyncio.create_task(self._loop())
        self.status.running = True

    async def stop(self) -> None:
        if not self.status.running:
            return
        if self.syslog:
            await self.syslog.stop()
        for t in self.tailers:
            await t.stop()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._flush(self._drain())
        self.syslog, self.tailers, self._task = None, [], None
        self.status.running = False
        self.status.sources = []

    def _drain(self, limit: int | None = None) -> list[LiveLine]:
        items = []
        while not self.queue.empty() and (limit is None or len(items) < limit):
            items.append(self.queue.get_nowait())
        return items

    async def _loop(self) -> None:
        cfg = self.settings.live
        while True:
            batch = [await self.queue.get()]
            deadline = asyncio.get_running_loop().time() + cfg.flush_seconds
            while len(batch) < cfg.flush_events:
                timeout = deadline - asyncio.get_running_loop().time()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(self.queue.get(), timeout))
                except TimeoutError:
                    break
            await self._flush(batch)

    async def _flush(self, batch: list[LiveLine]) -> None:
        if not batch:
            return
        events: list[Event] = []
        touched = set()
        for item in batch:
            n = self._counters.get(item.source, 0) + 1
            self._counters[item.source] = n
            touched.add(item.source)
            if (e := route_line(item, n)) is not None:
                events.append(e)
            else:
                self.status.unparsed_total += 1
        try:
            await asyncio.to_thread(self._process, events, touched)
        except Exception as exc:  # keep ingesting even if detection fails once
            log.exception("live flush failed")
            self.status.last_error = f"{type(exc).__name__}: {exc}"

    def _process(self, events: list[Event], touched: set[str]) -> None:
        since = self.store.max_seq()
        inserted = self.store.insert_events(events)
        self._save_counters(touched)
        self.status.events_total += inserted
        self.status.flushes += 1
        self.status.last_flush = datetime.now()
        if inserted:
            r = run_all(self.store, self.settings, since_seq=since, rules=self._rules)
            self.status.detections_total += r.detections_new
            if r.detections_new or r.by_rule:
                rebuild_incidents(self.store, self.settings)
