"""
core/event_bus.py

Central asyncio event bus.
Producers emit events. Consumers subscribe to queues.
The SSE endpoint in api/events.py subscribes here.
The AI analyst worker subscribes here for high-severity triggers.

Thread-safe via asyncio (single event loop).
"""

import asyncio
import logging
import time
from collections import deque
from typing import Optional, Any

logger = logging.getLogger(__name__)


class EventBus:
    """
    Fan-out broadcast hub.
    One emit → every subscriber receives it.
    Maintains a ring buffer of recent events for new subscribers
    to replay on connect (so the dashboard doesn't start empty).
    """

    def __init__(self, history_size: int = 500):
        self._subscribers: set[asyncio.Queue] = set()
        self._history: deque[dict] = deque(maxlen=history_size)
        self._lock = asyncio.Lock()

    async def emit(self, event_dict: dict) -> None:
        """
        Publish an event to all subscribers.
        Slow subscribers have their queues dropped (not our problem).
        """
        # Add metadata if missing
        if "ts" not in event_dict:
            event_dict["ts"] = time.time()

        self._history.append(event_dict)

        dead: set[asyncio.Queue] = set()
        for q in self._subscribers:
            try:
                q.put_nowait(event_dict)
            except asyncio.QueueFull:
                dead.add(q)

        if dead:
            async with self._lock:
                self._subscribers -= dead
            logger.debug(f"Dropped {len(dead)} slow subscriber(s)")

    def subscribe(self, maxsize: int = 256) -> asyncio.Queue:
        """Subscribe and return a queue. Caller must unsubscribe when done."""
        q: asyncio.Queue = asyncio.Queue(maxsize=maxsize)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    def history(self, limit: int = 50) -> list[dict]:
        """Return recent events for dashboard replay on connect."""
        events = list(self._history)
        return events[-limit:]

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)


# ── Module-level singleton ───────────────────────────────────────────────────
bus = EventBus()
