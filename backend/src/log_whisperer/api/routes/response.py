"""Suggested actions, Sigma rule drafts and report export."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse, Response

from log_whisperer.api.deps import get_jobs, get_settings, get_store, make_provider, require_incident
from log_whisperer.api.jobs import JobManager
from log_whisperer.config import Settings
from log_whisperer.report.pdf import PdfUnavailable, render_pdf
from log_whisperer.report.service import build_report
from log_whisperer.response.actions import suggest_actions
from log_whisperer.rulegen.draft import draft_rule
from log_whisperer.store import Store

router = APIRouter(prefix="/incidents/{incident_id}")
StoreDep = Annotated[Store, Depends(get_store)]
SettingsDep = Annotated[Settings, Depends(get_settings)]
JobsDep = Annotated[JobManager, Depends(get_jobs)]


@router.post("/actions", status_code=202)
def create_actions(incident_id: str, request: Request, store: StoreDep, settings: SettingsDep, jobs: JobsDep,
                   provider: str | None = None, model: str | None = None) -> dict:
    require_incident(store, incident_id)
    llm = make_provider(request, provider, model)
    cache: dict = request.app.state.actions

    def work(progress) -> dict:
        progress({"stage": "generating", "provider": llm.name, "model": llm.model})
        actions, rejected = suggest_actions(store, incident_id, llm, settings)
        cache[incident_id] = actions
        return {"actions": [a.model_dump() for a in actions], "rejected": [r.model_dump() for r in rejected]}

    return jobs.submit("actions", work).public()


@router.get("/actions")
def get_actions(incident_id: str, request: Request, store: StoreDep) -> list[dict]:
    require_incident(store, incident_id)
    return [a.model_dump() for a in request.app.state.actions.get(incident_id, [])]


@router.post("/rule-drafts", status_code=202)
def create_rule_draft(incident_id: str, request: Request, store: StoreDep, settings: SettingsDep, jobs: JobsDep,
                      provider: str | None = None, model: str | None = None) -> dict:
    require_incident(store, incident_id)
    llm = make_provider(request, provider, model)

    def work(progress) -> dict:
        progress({"stage": "drafting", "provider": llm.name, "model": llm.model})
        return draft_rule(store, incident_id, llm, settings, settings.detection.drafts_dir).model_dump(mode="json")

    return jobs.submit("rule_draft", work).public()


@router.get("/report")
def report(incident_id: str, request: Request, store: StoreDep, format: Literal["md", "pdf"] = "md") -> Response:
    require_incident(store, incident_id)
    markdown = build_report(store, incident_id, request.app.state.actions.get(incident_id))
    filename = f"incident-{incident_id}"
    if format == "md":
        return PlainTextResponse(markdown, media_type="text/markdown",
                                 headers={"Content-Disposition": f'attachment; filename="{filename}.md"'})
    try:
        pdf = render_pdf(markdown, f"Incident {incident_id}")
    except PdfUnavailable as exc:
        raise HTTPException(501, str(exc)) from exc
    return Response(pdf, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{filename}.pdf"'})
