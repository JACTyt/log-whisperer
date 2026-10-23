"""Polling `tail -F` that survives truncation, rotation and late file creation."""

import asyncio
import logging
import os
from pathlib import Path

from log_whisperer.live.syslog import LiveLine

log = logging.getLogger(__name__)


class FileTailer:
    def __init__(self, queue: asyncio.Queue, path: Path, poll_interval: float = 0.5, start_at_end: bool = True):
        self.queue = queue
        self.path = Path(path)
        self.poll_interval = poll_interval
        self.start_at_end = start_at_end
        self.lines = 0
        self._pos = 0
        self._ino: int | None = None
        self._partial = b""
        self._task: asyncio.Task | None = None

    @property
    def source(self) -> str:
        return f"tail://{self.path}"

    def _read_new(self) -> list[str]:
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return []
        if self._ino is None:
            self._ino = st.st_ino
            self._pos = st.st_size if self.start_at_end else 0
        elif st.st_ino != self._ino or st.st_size < self._pos:
            log.info("%s rotated or truncated; restarting from the beginning", self.path)
            self._ino, self._pos, self._partial = st.st_ino, 0, b""
        if st.st_size == self._pos:
            return []
        with open(self.path, "rb") as f:
            f.seek(self._pos)
            data = f.read()
        self._pos += len(data)
        chunks = (self._partial + data).split(b"\n")
        self._partial = chunks.pop()
        return [c.decode("utf-8", "replace").rstrip("\r") for c in chunks if c.strip()]

    async def poll_once(self) -> int:
        lines = self._read_new()
        for line in lines:
            await self.queue.put(LiveLine(source=self.source, line=line))
        self.lines += len(lines)
        return len(lines)

    async def run(self) -> None:
        while True:
            try:
                await self.poll_once()
            except OSError as exc:
                log.warning("tail %s: %s", self.path, exc)
            await asyncio.sleep(self.poll_interval)

    def start(self) -> None:
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
