"""Settings loaded from config.toml; secrets come only from environment variables."""

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel


class StorageSettings(BaseModel):
    db_path: Path = Path("data/logw.duckdb")
    upload_dir: Path = Path("data/uploads")


class ApiSettings(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8000
    max_upload_mb: int = 512
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


class DetectionSettings(BaseModel):
    sigma_dirs: list[Path] = [Path("../rules/sigma"), Path("../rules/custom")]
    sigma_min_level: str = "low"
    drafts_dir: Path = Path("../rules/drafts")
    brute_force_threshold: int = 10
    brute_force_window_min: int = 5
    brute_force_success_window_min: int = 30
    impossible_travel_kmh: float = 900
    new_admin_window_min: int = 60
    admin_groups: list[str] = [
        "administrators",
        "domain admins",
        "enterprise admins",
        "sudo",
        "wheel",
        "admin",
    ]


class GeoIPSettings(BaseModel):
    path: Path = Path("data/geoip/dbip-city-lite.mmdb")


class IncidentSettings(BaseModel):
    group_gap_minutes: int = 30
    context_neighbors: int = 20
    context_max: int = 300


class LLMSettings(BaseModel):
    provider: str = "ollama"  # ollama | anthropic | openai
    model: str | None = None  # overrides the selected provider's model
    ollama_model: str = "gemma4:26b-a4b"
    # Extra Ollama models always offered in the UI picker (installed ones are listed automatically).
    ollama_extra_models: list[str] = ["gemma4:e4b"]
    anthropic_model: str = "claude-opus-5-5"
    anthropic_effort: str = "medium"
    openai_model: str | None = None


class LiveSettings(BaseModel):
    autostart: bool = False
    bind: str = "127.0.0.1"
    syslog_port: int = 5514
    tail_paths: list[Path] = []
    flush_seconds: float = 1.0
    flush_events: int = 500
    queue_max: int = 10_000


class Settings(BaseModel):
    storage: StorageSettings = StorageSettings()
    api: ApiSettings = ApiSettings()
    detection: DetectionSettings = DetectionSettings()
    geoip: GeoIPSettings = GeoIPSettings()
    incidents: IncidentSettings = IncidentSettings()
    llm: LLMSettings = LLMSettings()
    live: LiveSettings = LiveSettings()


def load_settings(path: Path | None = None) -> Settings:
    """Load settings from `path`, else $LOGW_CONFIG, else ./config.toml, else defaults."""
    if path is None:
        env = os.environ.get("LOGW_CONFIG")
        if env:
            path = Path(env)
        elif Path("config.toml").is_file():
            path = Path("config.toml")
    if path is None:
        settings = Settings()
    else:
        with open(path, "rb") as f:
            settings = Settings.model_validate(tomllib.load(f))
    # Environment overrides (handy for Docker / launch scripts).
    if provider := os.environ.get("LOGW_LLM_PROVIDER"):
        settings.llm.provider = provider
    if model := os.environ.get("LOGW_OLLAMA_MODEL"):
        settings.llm.ollama_model = model
    return settings
