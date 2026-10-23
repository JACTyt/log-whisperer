"""Write/long-running endpoints: ingest, detect, narrative, chat, jobs."""

import json
import re
import shutil
import threading
import uuid
from pathlib import Path
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from log_whisperer.api.deps import get_jobs, get_settings, get_store, make_provider, require_incident
from log_whisperer.api.jobs import JobManager
from log_whisperer.chat.service import ChatAnswer, ChatService
from log_whisperer.chat.tools import ChatScope
from log_whisperer.config import Settings
from log_whisperer.detection.runner import run_all
from log_whisperer.detection.sigma_rules import load_rules
from log_whisperer.incidents.service import rebuild_incidents
from log_whisperer.ingest import IngestResult, ingest_path
from log_whisperer.llm import LLMError
from log_whisperer.narrative.service import generate_narrative
from log_whisperer.parsers import default_parsers
from log_whisperer.store import Store

router = APIRouter()
StoreDep = Annotated[Store, Depends(get_store)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
JobsDep = Annotated[JobManager, Depends(get_jobs)]
CHUNK = 1 << 20


def safe_filename(name: str | None) -> str:
    base = Path((name or "upload").replace("\\", "/")).name
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).lstrip(".")
    return base or "upload"


_rules_lock = threading.Lock()


def _rules(app_state, settings: Settings):
    """Compile Sigma rules once per process; `logw rules sync` + restart picks up changes."""
    with _rules_lock:
        if getattr(app_state, "rules", None) is None:
            app_state.rules, app_state.rule_report = load_rules(settings.detection.sigma_dirs)
        return app_state.rules


def _detect(store: Store, settings: Settings, progress, rules=None, since_seq: int | None = None) -> dict:
    progress({"stage": "detect"})
    r = run_all(store, settings, since_seq=since_seq, rules=rules)
    progress({"stage": "incidents", "new_detections": r.detections_new})
    incidents = rebuild_incidents(store, settings)
    return {"new_detections": r.detections_new, "incidents": len(incidents),
            "rules_loaded": len(rules) if rules is not None else r.rule_report.loaded, "query_errors": len(r.errors)}


@router.post("/ingest", status_code=202)
def ingest(files: list[UploadFile], request: Request, store: StoreDep, settings: SettingsDep, jobs: JobsDep,
           detect: bool = True) -> dict:
    job_dir = settings.storage.upload_dir / uuid.uuid4().hex[:12]
    job_dir.mkdir(parents=True, exist_ok=True)
    limit = settings.api.max_upload_mb * 1024 * 1024
    saved = []
    for f in files:
        target = job_dir / safe_filename(f.filename)
        size = 0
        with target.open("wb") as out:
            while chunk := f.file.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    out.close()
                    shutil.rmtree(job_dir, ignore_errors=True)
                    raise HTTPException(413, f"{f.filename} exceeds {settings.api.max_upload_mb} MB")
                out.write(chunk)
        saved.append(target)

    state = request.app.state

    def work(progress) -> dict:
        since = store.max_seq()
        total = IngestResult()
        for path in saved:
            total.add(ingest_path(store, path, default_parsers(), progress=progress))
        result = {"files": total.files, "parsed": total.parsed, "inserted": total.inserted,
                  "skipped_lines": total.skipped_lines, "errors": total.errors}
        if detect and total.inserted:
            result |= _detect(store, settings, progress, _rules(state, settings), since_seq=since)
        return result

    return jobs.submit("ingest", work).public()


@router.post("/detect", status_code=202)
def detect(request: Request, store: StoreDep, settings: SettingsDep, jobs: JobsDep) -> dict:
    state = request.app.state
    return jobs.submit("detect", lambda progress: _detect(store, settings, progress, _rules(state, settings))).public()


@router.get("/jobs/{job_id}")
def get_job(job_id: str, jobs: JobsDep) -> dict:
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(404, f"job {job_id} not found")
    return job.public()


@router.get("/jobs/{job_id}/stream")
async def stream_job(job_id: str, jobs: JobsDep) -> EventSourceResponse:
    if jobs.get(job_id) is None:
        raise HTTPException(404, f"job {job_id} not found")

    async def events():
        async for e in jobs.subscribe(job_id):
            yield {"event": e["event"], "data": json.dumps(e["data"], default=str)}

    return EventSourceResponse(events())


@router.post("/incidents/{incident_id}/narrative", status_code=202)
def create_narrative(incident_id: str, request: Request, store: StoreDep, settings: SettingsDep, jobs: JobsDep,
                     provider: str | None = None, model: str | None = None) -> dict:
    require_incident(store, incident_id)
    llm = make_provider(request, provider, model)

    def work(progress) -> dict:
        progress({"stage": "generating", "provider": llm.name, "model": llm.model})
        nv = generate_narrative(store, incident_id, llm, settings)
        return {"steps": len(nv.steps), "rejected": len(nv.rejected)}

    return jobs.submit("narrative", work).public()


class ChatIn(BaseModel):
    message: str
    session_id: str | None = None
    scope: Literal["incident", "global"] = "incident"
    incident_id: str | None = None
    provider: str | None = None
    model: str | None = None


class ChatOut(ChatAnswer):
    session_id: str


@router.post("/chat")
def chat(body: ChatIn, request: Request, store: StoreDep, settings: SettingsDep) -> ChatOut:
    sessions: dict = request.app.state.chat_sessions
    entry = sessions.get(body.session_id) if body.session_id else None
    if entry is None:
        incident = require_incident(store, body.incident_id or "") if body.scope == "incident" else None
        llm = make_provider(request, body.provider, body.model)
        svc = ChatService(store, llm, settings)
        session = svc.new_session(ChatScope(body.scope, incident))
        entry = sessions[session.id] = (svc, session)
    svc, session = entry
    try:
        answer = svc.ask(session, body.message)
    except LLMError as exc:
        raise HTTPException(502, f"model error: {exc}") from exc
    return ChatOut(session_id=session.id, **answer.model_dump())
