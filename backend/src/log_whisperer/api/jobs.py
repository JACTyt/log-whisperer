"""Background jobs (ingest, detect, narrative) with progress streamed over SSE."""

import asyncio
import logging
import threading
import uuid
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

log = logging.getLogger(__name__)
Progress = Callable[[dict[str, Any]], None]


@dataclass
class Job:
    id: str
    kind: str
    status: Literal["queued", "running", "done", "error"] = "queued"
    progress: dict[str, Any] = field(default_factory=dict)
    result: Any = None
    error: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    events: list[dict[str, Any]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "status": self.status, "progress": self.progress,
                "result": self.result, "error": self.error, "created_at": self.created_at.isoformat()}


class JobManager:
    def __init__(self, workers: int = 2):
        self.pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="logw-job")
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(self, kind: str, fn: Callable[[Progress], Any]) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], kind=kind)
        with self._lock:
            self.jobs[job.id] = job

        def progress(update: dict[str, Any]) -> None:
            job.progress = update
            job.events.append({"event": "progress", "data": update})

        def run() -> None:
            job.status = "running"
            job.events.append({"event": "status", "data": {"status": "running"}})
            try:
                job.result = fn(progress)
                job.status = "done"
            except Exception as exc:  # surfaced to the client, never raised in the pool
                log.exception("job %s (%s) failed", job.id, kind)
                job.error = f"{type(exc).__name__}: {exc}"
                job.status = "error"
            job.events.append({"event": job.status, "data": job.public()})

        self.pool.submit(run)
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    async def subscribe(self, job_id: str, poll: float = 0.2) -> AsyncIterator[dict[str, Any]]:
        job = self.jobs[job_id]
        sent = 0
        while True:
            while sent < len(job.events):
                yield job.events[sent]
                sent += 1
            if job.status in ("done", "error") and sent >= len(job.events):
                return
            await asyncio.sleep(poll)

    def shutdown(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)
