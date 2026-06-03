"""
main.py — AI SOC Control Plane

Entry point. Wires everything together:
  - FastAPI app
  - Database initialization
  - Background tasks (ingestion pipeline, snapshot worker, AI analyst)
  - API routes
  - Static file serving (frontend)

Access at: http://localhost:8000
"""

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from core.config import settings
from core.database import db
from core.event_bus import bus
from core.onboarding import run_onboarding
from pipeline.ingestion import IngestionPipeline
from collectors.snapshot import SystemSnapshotWorker
from analyst.analyst import AIAnalystWorker
from api.events import router as events_router
from api.routes import router as api_router

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level   = logging.DEBUG if settings.debug else logging.INFO,
    format  = "%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    datefmt = "%H:%M:%S",
)
# Quiet noisy third-party loggers
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# LIFESPAN — startup / shutdown
# ══════════════════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Start all background tasks on startup, cancel cleanly on shutdown.
    Order matters: AI analyst must start before ingestion pipeline
    (pipeline enqueues jobs, analyst must exist to receive them).
    """
    logger.info("=" * 60)
    logger.info("  AI SOC Control Plane starting")
    logger.info(f"  Dashboard:    http://localhost:{settings.port}")
    logger.info(f"  API docs:     http://localhost:{settings.port}/docs")
    logger.info(f"  Ollama model: {settings.ollama_model}")
    logger.info(f"  DB:           {settings.db_path}")
    logger.info(f"  Wazuh alerts: {settings.wazuh_alerts_path}")
    logger.info("=" * 60)

    # ── 0. Run onboarding on first boot ───────────────────────────────────
    is_first_boot = db.conn.execute(
        "SELECT COUNT(*) FROM events"
    ).fetchone()[0] == 0

    onboarding_report = None
    if is_first_boot:
        logger.info("First boot detected — running environment analysis...")
        onboarding_report = await run_onboarding()
        app.state.onboarding = onboarding_report.to_dict()
        app.state.first_boot = True
        for warning in onboarding_report.warnings:
            logger.warning(f"  ⚠ {warning}")
        logger.info(
            f"Environment: {onboarding_report.os_name}, "
            f"{onboarding_report.ram_gb}GB RAM, "
            f"recommended model: {onboarding_report.recommended_model}"
        )
    else:
        app.state.onboarding = None
        app.state.first_boot = False

    # ── 1. Start AI analyst worker (must be first — pipeline enqueues to it)
    analyst_worker = AIAnalystWorker(db=db, bus=bus)
    analyst_task   = asyncio.create_task(
        analyst_worker.run(), name="ai-analyst"
    )

    # ── 2. Create ingestion pipeline (injects analyst's enqueue method)
    pipeline = IngestionPipeline(db=db, bus=bus, ai_queue=analyst_worker)

    # ── 3. Start snapshot worker
    snapshot_worker = SystemSnapshotWorker(db=db, bus=bus, pipeline=pipeline)
    snapshot_task   = asyncio.create_task(
        snapshot_worker.run(), name="snapshot-worker"
    )

    # ── 4. Start Wazuh ingestion
    wazuh_task = asyncio.create_task(
        pipeline.run_wazuh(), name="wazuh-ingestion"
    )

    # ── 5. Start Docker events ingestion
    docker_task = asyncio.create_task(
        pipeline.run_docker(), name="docker-ingestion"
    )

    # Announce startup on the event bus
    await bus.emit({
        "type":    "system_start",
        "message": f"AI SOC Control Plane started — model: {settings.ollama_model}",
        "ts":      __import__("time").time(),
    })

    logger.info("All background tasks started")

    yield  # ── app is running ──

    # ── Shutdown: cancel all background tasks
    logger.info("Shutting down background tasks...")
    for task in [analyst_task, snapshot_task, wazuh_task, docker_task]:
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    db.close()
    logger.info("Shutdown complete")


# ══════════════════════════════════════════════════════════════════════════════
# APP
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title       = "AI SOC Control Plane",
    description = "Local AI-powered Security Operations Center",
    version     = "1.0.0",
    lifespan    = lifespan,
    docs_url    = "/docs",
    redoc_url   = None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],   # localhost only in practice
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

# ── API routes ────────────────────────────────────────────────────────────────
app.include_router(events_router)
app.include_router(api_router)

@app.get("/api/onboarding", include_in_schema=True)
async def get_onboarding():
    """Returns environment analysis from first boot. None if not first boot."""
    return {
        "first_boot": getattr(app.state, "first_boot", False),
        "report":     getattr(app.state, "onboarding", None),
    }

# ── Frontend static files ─────────────────────────────────────────────────────
_frontend = Path(__file__).parent / "frontend"

if _frontend.exists():
    # Serve /assets/* as static
    _assets = _frontend / "assets"
    if _assets.exists():
        app.mount("/assets", StaticFiles(directory=str(_assets)), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_index():
        return FileResponse(str(_frontend / "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    async def serve_frontend(path: str):
        """Catch-all: serve frontend files or fall back to index.html."""
        file_path = _frontend / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        # SPA fallback
        index = _frontend / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"error": "Frontend not found"}


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host    = settings.host,
        port    = settings.port,
        reload  = settings.debug,
        log_level = "debug" if settings.debug else "info",
    )
