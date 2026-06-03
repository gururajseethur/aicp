"""
pipeline/ingestion.py

The main ingestion pipeline. Orchestrates all 5 stages for Wazuh and Docker.

    Raw alert (dict)
         ↓
    Stage 2: Normalize  →  Event
         ↓
    Stage 3: Entity Extract  →  Event.entities populated
         ↓
    Stage 3.5: Honeytoken Check  (may escalate severity)
         ↓
    Stage 4: Classify  →  ClassificationResult
         ↓
    Stage 5: Fanout  →  DB + Bus + AI Queue

The outer try/except ensures one bad alert never kills the pipeline.
"""

import asyncio
import logging
from typing import Optional

from core.models import Event
from core.database import Database
from core.event_bus import EventBus
from pipeline.normalizer import WazuhNormalizer, DockerNormalizer
from pipeline.extractor import EntityExtractor
from pipeline.classifier import EventClassifier, HoneytokenDetector
from pipeline.fanout import EventFanout
from collectors.wazuh import AlertsTailer, DockerEventsTailer

logger = logging.getLogger(__name__)


class IngestionPipeline:
    """
    Orchestrates the full ingestion pipeline.
    One instance handles both Wazuh and Docker events.
    """

    def __init__(self, db: Database, bus: EventBus, ai_queue):
        self._db    = db
        self._bus   = bus

        # Stage instances
        self._wazuh_norm   = WazuhNormalizer()
        self._docker_norm  = DockerNormalizer()
        self._extractor    = EntityExtractor()
        self._classifier   = EventClassifier(db=db)
        self._honeydetect  = HoneytokenDetector()
        self._fanout       = EventFanout(db=db, bus=bus, ai_queue=ai_queue)

        # Load honeytoken paths
        self._refresh_honeytokens()

    def _refresh_honeytokens(self) -> None:
        """Load honeytoken paths from DB."""
        try:
            paths = self._db.get_honeytoken_paths()
            self._honeydetect.update_paths(paths)
            logger.debug(f"Loaded {len(paths)} honeytoken paths")
        except Exception as e:
            logger.warning(f"Could not load honeytokens: {e}")

    async def process_event(self, event: Event) -> None:
        """
        Process a pre-built Event object through stages 3-5.
        Used by SystemSnapshotWorker for port change events.
        """
        # Stage 3: Extract entities (if not already populated)
        if not event.entities.has_any():
            event.entities = self._extractor.extract(event)

        # Stage 3.5: Honeytoken check
        self._honeydetect.check(event)

        # Stage 4: Classify
        classification = self._classifier.classify(event)

        # Stage 5: Fanout
        await self._fanout.process(event, classification)

    async def run_wazuh(self) -> None:
        """
        Continuously tail Wazuh alerts.json and process each alert.
        Runs forever as a background asyncio task.
        """
        logger.info("Wazuh ingestion pipeline started")
        tailer = AlertsTailer()

        async for raw_alert in tailer.tail():
            try:
                await self._process_wazuh(raw_alert)
            except asyncio.CancelledError:
                return
            except Exception as e:
                # ONE bad alert never kills the pipeline
                logger.error(
                    f"Pipeline error on Wazuh alert: {e}", exc_info=True
                )
                continue

    async def run_docker(self) -> None:
        """
        Continuously stream Docker events and process each one.
        Runs forever as a background asyncio task.
        """
        logger.info("Docker ingestion pipeline started")
        tailer = DockerEventsTailer()

        async for raw_event in tailer.tail():
            try:
                await self._process_docker(raw_event)
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error(
                    f"Pipeline error on Docker event: {e}", exc_info=True
                )
                continue

    # ── Internal processing ───────────────────────────────────────────────────

    async def _process_wazuh(self, raw: dict) -> None:
        # Stage 2: Normalize
        event = self._wazuh_norm.normalize(raw)
        if not event:
            return  # malformed alert, skip

        # Stage 3: Entity extraction
        event.entities = self._extractor.extract(event)

        # Stage 3.5: Honeytoken check (may escalate to CRITICAL)
        self._honeydetect.check(event)

        # Stage 4: Classify
        classification = self._classifier.classify(event)

        # Stage 5: Fanout
        await self._fanout.process(event, classification)

    async def _process_docker(self, raw: dict) -> None:
        # Stage 2: Normalize
        event = self._docker_norm.normalize(raw)
        if not event:
            return

        # Stage 3: Entity extraction
        event.entities = self._extractor.extract(event)

        # Stage 3.5: Honeytoken check (less common for Docker but included)
        self._honeydetect.check(event)

        # Stage 4: Classify
        classification = self._classifier.classify(event)

        # Stage 5: Fanout
        await self._fanout.process(event, classification)
