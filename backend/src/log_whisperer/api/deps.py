from collections.abc import Callable

from fastapi import HTTPException, Request

from log_whisperer.api.jobs import JobManager
from log_whisperer.config import Settings
from log_whisperer.llm import LLMProvider, ProviderUnavailable
from log_whisperer.models import Incident
from log_whisperer.store import Store

ProviderFactory = Callable[[Settings, str | None, str | None], LLMProvider]


def get_store(request: Request) -> Store:
    return request.app.state.store


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_jobs(request: Request) -> JobManager:
    return request.app.state.jobs


def make_provider(request: Request, provider: str | None, model: str | None) -> LLMProvider:
    try:
        return request.app.state.provider_factory(request.app.state.settings, provider, model)
    except ProviderUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc


def require_incident(store: Store, incident_id: str) -> Incident:
    incident = store.get_incident(incident_id)
    if incident is None:
        raise HTTPException(404, f"incident {incident_id} not found")
    return incident
