"""
api/events.py

GET /api/events/stream  — SSE stream of all system events and assessments.
GET /api/events/recent  — Recent event history (for dashboard on load).
"""

import asyncio
import json
import logging
from typing import AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from core.event_bus import bus

logger   = logging.getLogger(__name__)
router   = APIRouter(prefix="/api/events", tags=["events"])


@router.get("/stream")
async def event_stream():
    """
    SSE endpoint. Dashboard connects here and receives all events in real time.
    Replays recent history on connect so the dashboard isn't empty.

    Event types pushed:
      event             — new security event ingested
      assessment_ready  — AI assessment completed
      system_status     — periodic health update
    """
    async def generator() -> AsyncIterator[str]:
        # Replay recent history for new subscribers
        for event_dict in bus.history(limit=50):
            yield f"data: {json.dumps(event_dict)}\n\n"

        q = bus.subscribe()
        try:
            while True:
                try:
                    event_dict = await asyncio.wait_for(q.get(), timeout=25.0)
                    yield f"data: {json.dumps(event_dict)}\n\n"
                except asyncio.TimeoutError:
                    # Keep-alive ping — prevents proxies from closing the connection
                    yield ": ping\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            bus.unsubscribe(q)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":        "keep-alive",
        },
    )


@router.get("/recent")
async def recent_events(limit: int = 50):
    """Return recent event history. Used by dashboard on initial load."""
    return {"events": bus.history(limit=min(limit, 200))}
