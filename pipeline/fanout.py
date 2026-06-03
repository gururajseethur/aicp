"""
pipeline/fanout.py

Stage 5: Fanout.

One event → three independent destinations:
  1. SQLite database (persistent storage)
  2. Event bus (SSE stream to dashboard)
  3. AI analysis queue (if classifier says analyze)

Failures are isolated: a DB write failure doesn't drop the SSE event.
All three run concurrently via asyncio.gather(return_exceptions=True).
"""

import asyncio
import logging
from typing import Optional

from core.models import Event, ClassificationResult, AnalysisJob
from core.database import Database
from core.event_bus import EventBus

logger = logging.getLogger(__name__)


class EventFanout:
    def __init__(self, db: Database, bus: EventBus, ai_queue):
        self._db       = db
        self._bus      = bus
        self._ai_queue = ai_queue  # AIAnalystWorker instance

    async def process(
        self, event: Event, classification: ClassificationResult
    ) -> None:
        """
        Fan the event out to all three destinations concurrently.
        Failures in any one destination are logged but never propagate.
        """
        results = await asyncio.gather(
            self._write_db(event),
            self._publish_bus(event),
            self._maybe_enqueue_ai(event, classification),
            return_exceptions=True,
        )

        # Log any failures — never raise
        stage_names = ["db_write", "bus_publish", "ai_enqueue"]
        for stage, result in zip(stage_names, results):
            if isinstance(result, Exception):
                logger.error(f"Fanout stage '{stage}' failed for {event.id}: {result}")

    async def _write_db(self, event: Event) -> None:
        """Write event and entity index to SQLite."""
        # SQLite is sync — run in thread pool to avoid blocking event loop
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._db.store_event, event)

    async def _publish_bus(self, event: Event) -> None:
        """Publish to the SSE event bus for the dashboard."""
        event_dict = {
            "type":       "event",
            "id":         event.id,
            "ts":         event.ts,
            "source":     event.source.value,
            "event_type": event.type.value,
            "severity":   event.severity.value,
            "title":      event.title,
            "entities": {
                "ips":        event.entities.ips,
                "users":      event.entities.users,
                "files":      event.entities.files,
                "containers": event.entities.containers,
            },
            "incident_id": event.incident_id,
            "wazuh": {
                "rule_id":       event.wazuh.rule_id,
                "rule_level":    event.wazuh.rule_level,
                "description":   event.wazuh.description,
                "agent_name":    event.wazuh.agent_name,
                "mitre_id":      event.wazuh.mitre_id,
                "mitre_tactic":  event.wazuh.mitre_tactic,
                "ecs_category":  event.wazuh.ecs_category,
            } if event.wazuh else None,
            "docker": {
                "action":         event.docker.action,
                "container_name": event.docker.container_name,
                "image":          event.docker.image,
                "is_privileged":  event.docker.is_privileged,
            } if event.docker else None,
        }
        await self._bus.emit(event_dict)

    async def _maybe_enqueue_ai(
        self, event: Event, classification: ClassificationResult
    ) -> None:
        """Add to AI analysis queue if classification says to."""
        if not classification.should_analyze:
            return
        await self._ai_queue.enqueue(
            event_id = event.id,
            priority = classification.analysis_priority,
        )
