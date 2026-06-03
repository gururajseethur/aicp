"""
core/config.py

All configuration in one place.
Every module imports from here — no hardcoded values anywhere else.
Override any setting via environment variable or .env file.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Server ──────────────────────────────────────────────────
    host: str = "0.0.0.0"
    port: int = 8000
    debug: bool = False

    # ── Database ────────────────────────────────────────────────
    db_path: str = "aicp.db"

    # ── Wazuh ───────────────────────────────────────────────────
    wazuh_alerts_path: str = "/var/ossec/logs/alerts/alerts.json"
    # For development, point this at the sample fixture:
    # wazuh_alerts_path: str = "tests/fixtures/sample_alerts.json"

    # ── Ollama ──────────────────────────────────────────────────
    ollama_url:             str = "http://localhost:11434"
    ollama_model:           str = "qwen2.5:7b"
    ollama_fallback_model:  str = "llama3.1:8b"
    ollama_temperature:     float = 0.1      # low = deterministic security analysis
    ollama_timeout:         int = 120        # seconds

    # ── AI Queue ────────────────────────────────────────────────
    max_ai_queue:           int = 50
    job_stale_after:        int = 300        # seconds — skip if queued this long

    # ── Docker ──────────────────────────────────────────────────
    docker_socket:          str = "unix:///var/run/docker.sock"

    # ── Snapshot worker ─────────────────────────────────────────
    snapshot_interval:      int = 60         # seconds

    # ── Alert filtering thresholds ───────────────────────────────
    # Wazuh rule levels: 1-15
    always_analyze_level:   int = 10        # HIGH and above
    conditional_level:      int = 7         # MEDIUM — only if correlated

    # ── Incident correlation window ──────────────────────────────
    incident_window:        int = 1800      # 30 minutes

    # ── Context builder ──────────────────────────────────────────
    context_max_tokens:     int = 3000
    context_related_events: int = 30        # max related events to include
    context_lookback_hours: int = 24


settings = Settings()
