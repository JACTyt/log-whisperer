"""FastAPI application (DESIGN §16). One process owns the DuckDB file."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from log_whisperer.api.deps import ProviderFactory
from log_whisperer.api.jobs import JobManager
from log_whisperer.api.routes import actions, data, live, response
from log_whisperer.config import Settings, load_settings
from log_whisperer.live.pipeline import LivePipeline
from log_whisperer.llm import get_provider
from log_whisperer.store import Store


def create_app(settings: Settings | None = None, store: Store | None = None,
               provider_factory: ProviderFactory | None = None) -> FastAPI:
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        owns_store = store is None
        app.state.store = store or Store(settings.storage.db_path)
        app.state.settings = settings
        app.state.jobs = JobManager()
        app.state.chat_sessions = {}
        app.state.actions = {}
        app.state.provider_factory = provider_factory or get_provider
        app.state.live = None
        if settings.live.autostart:
            app.state.live = LivePipeline(app.state.store, settings)
            await app.state.live.start()
        yield
        if app.state.live is not None:
            await app.state.live.stop()
        app.state.jobs.shutdown()
        if owns_store:
            app.state.store.close()

    app = FastAPI(title="Log Whisperer", version="0.1.0", lifespan=lifespan,
                  docs_url="/api/docs", openapi_url="/api/openapi.json")
    app.add_middleware(CORSMiddleware, allow_origins=settings.api.cors_origins, allow_methods=["*"],
                       allow_headers=["*"])
    app.include_router(data.router, prefix="/api")
    app.include_router(actions.router, prefix="/api")
    app.include_router(live.router, prefix="/api")
    app.include_router(response.router, prefix="/api")
    return app
