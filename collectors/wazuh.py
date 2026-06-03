"""
collectors/wazuh.py

Tails /var/ossec/logs/alerts/alerts.json in real time.

Handles:
  - File rotation (Wazuh rotates daily at midnight)
  - Partial line reads (Wazuh sometimes flushes mid-line)
  - File not yet existing (Wazuh starting up)
  - Malformed JSON lines (skipped, logged, never crash)

Starts from END of file — no historical replay on startup.
This prevents flooding the AI queue with old events.
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import AsyncIterator, Optional

from core.config import settings

logger = logging.getLogger(__name__)


class AlertsTailer:
    """
    Async generator that yields raw Wazuh alert dicts as they appear.

    Two modes:
      Production: tail a live alerts.json, seek to end on open (no replay).
      Dev/test:   replay a static fixture file from the beginning,
                  then wait for new lines (simulates live feed).

    Dev mode is auto-detected: if the path is inside tests/fixtures/
    or the filename ends with _test.json or _sample.json, it replays
    from the start instead of seeking to end.

    Usage:
        tailer = AlertsTailer()
        async for alert in tailer.tail():
            process(alert)
    """

    def __init__(self, path: Optional[str] = None):
        self.path     = Path(path or settings.wazuh_alerts_path)
        self._file    = None
        self._inode:  Optional[int] = None
        # Dev mode: replay file from beginning instead of seeking to end
        self._dev_mode = (
            "fixtures" in str(self.path) or
            "sample"   in self.path.name or
            "test"     in self.path.name
        )
        if self._dev_mode:
            logger.info(f"DEV MODE: replaying {self.path} from start")

    async def tail(self) -> AsyncIterator[dict]:
        """Yields raw alert dicts. Runs forever until cancelled."""
        logger.info(f"Wazuh tailer starting: {self.path}")

        await self._open()

        while True:
            line = await asyncio.get_event_loop().run_in_executor(
                None, self._read_line
            )

            if line:
                alert = self._parse(line.strip())
                if alert:
                    # Small delay in dev mode so the pipeline isn't flooded
                    if self._dev_mode:
                        await asyncio.sleep(0.1)
                    yield alert
            else:
                # No new data — check for file rotation
                await asyncio.sleep(0.3)

                rotated = await asyncio.get_event_loop().run_in_executor(
                    None, self._rotated
                )
                if rotated:
                    logger.info("Wazuh alerts.json rotated — reopening")
                    await self._open()

    async def _open(self) -> None:
        """Open the alerts file and seek to end (no historical replay)."""
        if self._file:
            try:
                self._file.close()
            except Exception:
                pass
            self._file = None

        # Wait for file to exist (Wazuh may be starting)
        for attempt in range(30):
            if self.path.exists():
                break
            if attempt == 0:
                logger.warning(f"Waiting for {self.path} to exist...")
            await asyncio.sleep(2)
        else:
            logger.error(f"Alerts file never appeared: {self.path}")
            return

        try:
            self._file = open(self.path, "r", encoding="utf-8", errors="replace")
            if not self._dev_mode:
                self._file.seek(0, 2)  # SEEK_END — production: no replay
            # Dev mode: read from beginning (replays all sample alerts)
            self._inode = self.path.stat().st_ino
            mode_str = "DEV replay" if self._dev_mode else "LIVE tail"
            logger.info(f"Tailing [{mode_str}]: {self.path} (inode {self._inode})")
        except Exception as e:
            logger.error(f"Failed to open {self.path}: {e}")
            self._file = None

    def _read_line(self) -> Optional[str]:
        """Read next line from the file. Returns None if no new data."""
        if not self._file:
            return None
        try:
            return self._file.readline() or None
        except Exception as e:
            logger.warning(f"Read error: {e}")
            return None

    def _rotated(self) -> bool:
        """
        True if the file has been replaced since we opened it.
        Detects both inode change (rotation) and file deletion.
        """
        if not self._file or not self._inode:
            return True
        try:
            current_inode = self.path.stat().st_ino
            return current_inode != self._inode
        except FileNotFoundError:
            return True

    def _parse(self, line: str) -> Optional[dict]:
        """
        Parse a JSON line. Wazuh occasionally writes partial lines during
        buffer flushes — skip those gracefully.
        """
        if not line or not line.startswith("{"):
            return None
        try:
            return json.loads(line)
        except json.JSONDecodeError as e:
            # Don't log every partial line — would flood logs during high alert volume
            logger.debug(f"Skipped malformed line ({len(line)} chars): {e}")
            return None


class DockerEventsTailer:
    """
    Streams Docker socket events for container lifecycle tracking.
    Uses the Docker HTTP API via unix socket.
    """

    def __init__(self):
        self._socket = settings.docker_socket

    async def tail(self) -> AsyncIterator[dict]:
        """Yields raw Docker event dicts. Reconnects on error with backoff."""
        logger.info("Docker events tailer starting")
        fail_count = 0

        while True:
            try:
                async for event in self._stream_events():
                    fail_count = 0  # reset on successful event
                    yield event
            except asyncio.CancelledError:
                return
            except Exception as e:
                fail_count += 1
                # First failure: warn. Subsequent: debug (expected when Docker absent)
                if fail_count == 1:
                    logger.warning(f"Docker events stream error: {e}")
                else:
                    logger.debug(f"Docker events stream error (attempt {fail_count}): {e}")
                # Exponential backoff: 5s, 10s, 20s, 40s, cap at 60s
                wait = min(5 * (2 ** (fail_count - 1)), 60)
                await asyncio.sleep(wait)

    async def _stream_events(self) -> AsyncIterator[dict]:
        """Connect to Docker API and stream events."""
        import httpx

        # Filter to container events only
        filters = json.dumps({"type": ["container", "image"]})

        transport = httpx.AsyncHTTPTransport(uds=self._socket.replace("unix://", ""))

        async with httpx.AsyncClient(transport=transport, timeout=None) as client:
            async with client.stream(
                "GET",
                "http://localhost/events",
                params={"filters": filters},
            ) as response:
                if response.status_code != 200:
                    logger.error(f"Docker API returned {response.status_code}")
                    return

                async for line in response.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
