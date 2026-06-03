"""
collectors/snapshot.py

SystemSnapshotWorker — captures system state every 60 seconds.

Stores in SQLite for:
  - Context builder baseline (what was running when an incident occurred)
  - Port change detection (new listening ports = security signal)
  - Trend analysis (v2)

Port change detection:
  - Compares current ports to previous snapshot
  - Filters out container-owned ports (Docker noise)
  - Emits NEW_LISTENING_PORT events for unexpected new ports
"""

import asyncio
import json
import logging
import socket
import uuid
import time
from typing import Optional

import psutil

from core.config import settings
from core.models import (
    SystemSnapshot, Event, EventSource, EventType, Severity,
    SystemPayload, Entities,
)

logger = logging.getLogger(__name__)

# Ports that are always expected and should never trigger an alert
EXPECTED_PORTS = frozenset({
    22,    # SSH
    53,    # DNS
    80,    # HTTP
    443,   # HTTPS
    631,   # CUPS
    8000,  # Our own app
    9090,  # Prometheus
    11434, # Ollama
    55000, # Wazuh API
})


class SystemSnapshotWorker:
    """
    Background task that periodically captures system state.
    Also detects new listening ports and emits security events.
    """

    def __init__(self, db, bus, pipeline=None):
        self._db        = db
        self._bus       = bus
        self._pipeline  = pipeline  # set after pipeline is created
        self._prev_ports: set[int] = set()
        self._first_run = True

    async def run(self) -> None:
        """Main loop — runs every 60 seconds."""
        logger.info("Snapshot worker starting")
        while True:
            try:
                await self._take_snapshot()
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error(f"Snapshot worker error: {e}", exc_info=True)
            await asyncio.sleep(settings.snapshot_interval)

    async def _take_snapshot(self) -> None:
        loop = asyncio.get_event_loop()

        # Collect metrics in thread pool (psutil is blocking)
        snapshot = await loop.run_in_executor(None, self._collect)

        # Write to DB in thread pool using a fresh connection to avoid
        # "cannot start a transaction within a transaction" when the
        # main asyncio loop is mid-write on the shared connection
        await loop.run_in_executor(None, self._store_snapshot_safe, snapshot)

        # Detect new ports (after first run baseline)
        if not self._first_run:
            await self._check_port_changes(snapshot)
        else:
            # Set baseline on first run
            self._prev_ports = {p["port"] for p in snapshot.open_ports}
            self._first_run  = False
            logger.info(
                f"Snapshot baseline: {snapshot.cpu_pct}% CPU, "
                f"{snapshot.mem_pct}% MEM, "
                f"{len(snapshot.open_ports)} listening ports"
            )

    def _store_snapshot_safe(self, snapshot: SystemSnapshot) -> None:
        """
        Write snapshot using a dedicated connection.
        Avoids "cannot start transaction within transaction" when the shared
        db singleton connection is mid-write on another thread.
        """
        import sqlite3 as _sqlite3
        from core.config import settings as _s
        conn = _sqlite3.connect(_s.db_path, check_same_thread=False)
        try:
            conn.execute("""
                INSERT OR REPLACE INTO system_snapshots
                    (id, ts, cpu_pct, mem_pct, disk_pct,
                     containers_json, models_json, ports_json, users_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                snapshot.id, snapshot.ts,
                snapshot.cpu_pct, snapshot.mem_pct, snapshot.disk_pct,
                json.dumps(snapshot.containers),
                json.dumps(snapshot.models),
                json.dumps(snapshot.open_ports),
                json.dumps(snapshot.active_users),
            ))
            conn.commit()
        finally:
            conn.close()

    def _collect(self) -> SystemSnapshot:
        """Collect all system metrics. Runs in thread pool."""
        return SystemSnapshot(
            id           = str(uuid.uuid4()),
            ts           = time.time(),
            cpu_pct      = round(psutil.cpu_percent(interval=1), 1),
            mem_pct      = round(psutil.virtual_memory().percent, 1),
            disk_pct     = round(psutil.disk_usage("/").percent, 1),
            containers   = self._get_containers(),
            models       = self._get_ollama_models(),
            open_ports   = self._get_listening_ports(),
            active_users = self._get_active_users(),
        )

    def _get_containers(self) -> list[dict]:
        """Get running containers via Docker socket API."""
        try:
            import httpx
            # Try Unix socket first (inside container)
            transport = httpx.HTTPTransport(uds="/var/run/docker.sock")
            with httpx.Client(transport=transport, timeout=5.0) as client:
                r = client.get("http://localhost/containers/json?all=true")
                if r.status_code == 200:
                    return [
                        {
                            "name":  (c.get("Names") or [c["Id"][:12]])[0].lstrip("/"),
                            "state": c.get("State", "unknown"),
                            "image": c.get("Image", ""),
                        }
                        for c in r.json()
                    ]
        except Exception:
            pass
        # Fallback: try subprocess (host environment)
        try:
            import subprocess, json as _json
            result = subprocess.run(
                ["docker", "ps", "--all", "--format",
                 '{"name":"{{.Names}}","state":"{{.Status}}","image":"{{.Image}}"}'],
                capture_output=True, text=True, timeout=5,
            )
            containers = []
            for line in result.stdout.strip().splitlines():
                try:
                    c = _json.loads(line)
                    c["state"] = "running" if "Up" in c.get("state","") else "stopped"
                    containers.append(c)
                except Exception:
                    pass
            return containers
        except Exception:
            return []

    def _get_ollama_models(self) -> list[str]:
        """Get loaded Ollama models."""
        try:
            import httpx
            response = httpx.get(
                f"{settings.ollama_url}/api/tags", timeout=3.0
            )
            if response.status_code == 200:
                return [
                    m.get("name", "") for m in
                    response.json().get("models", [])
                    if m.get("name")
                ]
        except Exception:
            pass
        return []

    def _get_listening_ports(self) -> list[dict]:
        """Get all listening ports with owning process info."""
        ports = []
        seen  = set()
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "LISTEN":
                    continue
                port = conn.laddr.port
                if port in seen:
                    continue
                seen.add(port)

                proc_name = None
                proc_pid  = None
                binary    = None
                try:
                    if conn.pid:
                        proc = psutil.Process(conn.pid)
                        proc_name = proc.name()
                        proc_pid  = conn.pid
                        binary    = proc.exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                ports.append({
                    "port":         port,
                    "process":      proc_name,
                    "pid":          proc_pid,
                    "binary":       binary,
                    "is_container": self._is_container_port(port),
                })
        except Exception as e:
            logger.debug(f"Port scan error: {e}")
        return sorted(ports, key=lambda p: p["port"])

    def _is_container_port(self, port: int) -> bool:
        """Heuristic: is this port likely owned by a Docker container?"""
        # Common container port ranges
        if port in (80, 443, 8080, 8443, 3000, 9090, 9100, 11434, 55000):
            return True
        return False

    def _get_active_users(self) -> list[str]:
        """Get currently logged-in users."""
        try:
            return list({u.name for u in psutil.users()})
        except Exception:
            return []

    async def _check_port_changes(self, snapshot: SystemSnapshot) -> None:
        """
        Detect new listening ports since last snapshot.
        Only emit events for ports not owned by known containers.
        """
        current_ports = {p["port"] for p in snapshot.open_ports}
        new_ports     = current_ports - self._prev_ports

        for port in new_ports:
            # Find process info
            port_info = next(
                (p for p in snapshot.open_ports if p["port"] == port), {}
            )

            # Skip if it's a known container port
            if port_info.get("is_container"):
                logger.debug(f"New port {port} owned by container — skipping")
                self._prev_ports = current_ports
                continue

            # Skip expected ports
            if port in EXPECTED_PORTS:
                self._prev_ports = current_ports
                continue

            # This is an unexpected new port — emit event
            severity = Severity.HIGH if port < 1024 else Severity.MEDIUM
            proc     = port_info.get("process", "unknown")
            binary   = port_info.get("binary", "")

            logger.warning(
                f"New listening port detected: {port} "
                f"(process: {proc}, binary: {binary})"
            )

            event = Event(
                id       = str(uuid.uuid4()),
                ts       = time.time(),
                source   = EventSource.SYSTEM,
                type     = EventType.NEW_PORT,
                severity = severity,
                title    = f"New listening port: {port} (process: {proc})",
                entities = Entities(
                    ports     = [port],
                    processes = [proc] if proc != "unknown" else [],
                ),
                raw = {
                    "port":    port,
                    "process": proc,
                    "binary":  binary,
                    "pid":     port_info.get("pid"),
                },
                system = SystemPayload(
                    metric       = "new_listening_port",
                    value        = float(port),
                    threshold    = 0,
                    unit         = "port_number",
                    detail       = f"Port {port} opened by {proc}",
                    process_name = proc,
                    pid          = port_info.get("pid"),
                    binary_path  = binary,
                ),
            )

            # Send through pipeline if available, otherwise just emit to bus
            if self._pipeline:
                await self._pipeline.process_event(event)
            else:
                await self._bus.emit({
                    "type":       "event",
                    "id":         event.id,
                    "ts":         event.ts,
                    "source":     event.source.value,
                    "event_type": event.type.value,
                    "severity":   event.severity.value,
                    "title":      event.title,
                })

        self._prev_ports = current_ports
