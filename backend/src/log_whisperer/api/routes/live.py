"""Live ingestion control."""

from dataclasses import asdict

from fastapi import APIRouter, HTTPException, Request

from log_whisperer.live.pipeline import LivePipeline, LiveStatus

router = APIRouter(prefix="/live")


def _status(request: Request) -> dict:
    live: LivePipeline | None = request.app.state.live
    return asdict(live.status if live else LiveStatus())


@router.get("/status")
def status(request: Request) -> dict:
    return _status(request)


@router.post("/start")
async def start(request: Request) -> dict:
    state = request.app.state
    if state.live is None or not state.live.status.running:
        state.live = LivePipeline(state.store, state.settings)
        try:
            await state.live.start()
        except OSError as exc:
            state.live = None
            raise HTTPException(409, f"cannot start live ingestion: {exc}") from exc
    return _status(request)


@router.post("/stop")
async def stop(request: Request) -> dict:
    if request.app.state.live is not None:
        await request.app.state.live.stop()
    return _status(request)
