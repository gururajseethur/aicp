"""
core/database.py

SQLite database layer.
Single class, all queries in one place.
Uses row_factory for dict-like access.

Tables:
  events              — every ingested event
  event_entities      — entity index for fast correlation
  assessments         — AI analysis results
  incidents           — grouped event clusters
  system_snapshots    — hourly system state
  feedback_patterns   — learned false positive patterns
  honeytokens         — files/ports that should never be accessed
  identities          — human operator identity definitions
  identity_accounts   — per-device accounts mapped to identities
  ai_audit_log        — every AI interaction (prompt + response)
"""

import sqlite3
import json
import logging
import time
from pathlib import Path
from typing import Optional
from dataclasses import asdict

from core.models import (
    Event, Entities, WazuhPayload, DockerPayload, SystemPayload,
    AIAssessment, AssessmentNarrative, Incident, SystemSnapshot,
    Honeytoken, FeedbackPattern, Identity, IdentityAccount,
    EventSource, EventType, Severity, IncidentStatus,
    IncidentType, FeedbackLabel,
)
from core.config import settings

logger = logging.getLogger(__name__)

# ── Schema SQL ───────────────────────────────────────────────────────────────
SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Events ──────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    ts              REAL NOT NULL,
    source          TEXT NOT NULL,
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    raw             TEXT NOT NULL,       -- original JSON payload
    entities_json   TEXT NOT NULL,       -- Entities serialized
    payload_json    TEXT NOT NULL,       -- typed payload serialized
    incident_id     TEXT,
    FOREIGN KEY (incident_id) REFERENCES incidents(id)
);

CREATE INDEX IF NOT EXISTS idx_events_ts        ON events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_incident  ON events(incident_id);

-- ── Entity index — the correlation engine ───────────────────────────────────
CREATE TABLE IF NOT EXISTS event_entities (
    event_id        TEXT NOT NULL,
    entity_type     TEXT NOT NULL,   -- ip|user|file|container|process|port|hash|cve
    entity_val      TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_entity_lookup ON event_entities(entity_type, entity_val);
CREATE INDEX IF NOT EXISTS idx_entity_event  ON event_entities(event_id);

-- Composite index for the key correlation query:
-- "find all events of this entity type and value"
CREATE UNIQUE INDEX IF NOT EXISTS idx_entity_unique
    ON event_entities(event_id, entity_type, entity_val);

-- ── AI Assessments ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS assessments (
    id                      TEXT PRIMARY KEY,
    ts                      REAL NOT NULL,
    triggered_by            TEXT NOT NULL,
    correlated_events_json  TEXT NOT NULL,   -- JSON array of event IDs
    model_used              TEXT NOT NULL,
    inference_ms            INTEGER,
    severity                TEXT NOT NULL,
    confidence              REAL NOT NULL,
    summary                 TEXT NOT NULL,
    incident_type           TEXT NOT NULL,
    narrative_json          TEXT NOT NULL,   -- AssessmentNarrative as JSON
    fp_indicators_json      TEXT NOT NULL,   -- JSON array
    mitre_technique         TEXT,
    requires_immediate      INTEGER NOT NULL DEFAULT 0,
    feedback                TEXT,
    feedback_ts             REAL,
    feedback_note           TEXT,
    FOREIGN KEY (triggered_by) REFERENCES events(id)
);

CREATE INDEX IF NOT EXISTS idx_assessments_ts           ON assessments(ts DESC);
CREATE INDEX IF NOT EXISTS idx_assessments_severity     ON assessments(severity);
CREATE INDEX IF NOT EXISTS idx_assessments_triggered    ON assessments(triggered_by);

-- ── Incidents ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS incidents (
    id                  TEXT PRIMARY KEY,
    created_ts          REAL NOT NULL,
    updated_ts          REAL NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open',
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    confidence          REAL NOT NULL DEFAULT 0.0,
    first_seen          REAL NOT NULL,
    last_seen           REAL NOT NULL,
    event_count         INTEGER NOT NULL DEFAULT 0,
    entities_json       TEXT NOT NULL,   -- primary entities
    notes_json          TEXT NOT NULL DEFAULT '[]',
    resolution          TEXT
);

CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_last_seen  ON incidents(last_seen DESC);

-- ── System snapshots ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_snapshots (
    id              TEXT PRIMARY KEY,
    ts              REAL NOT NULL,
    cpu_pct         REAL,
    mem_pct         REAL,
    disk_pct        REAL,
    containers_json TEXT NOT NULL DEFAULT '[]',
    models_json     TEXT NOT NULL DEFAULT '[]',
    ports_json      TEXT NOT NULL DEFAULT '[]',
    users_json      TEXT NOT NULL DEFAULT '[]'
);

CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON system_snapshots(ts DESC);

-- ── Feedback patterns — learned from operator ────────────────────────────────
CREATE TABLE IF NOT EXISTS feedback_patterns (
    id                  TEXT PRIMARY KEY,
    created_ts          REAL NOT NULL,
    pattern_type        TEXT NOT NULL,   -- ip|user|file|rule_id|container
    pattern_value       TEXT NOT NULL,
    label               TEXT NOT NULL,   -- false_positive|confirmed
    occurrence_count    INTEGER NOT NULL DEFAULT 1,
    last_seen           REAL NOT NULL,
    UNIQUE(pattern_type, pattern_value)
);

CREATE INDEX IF NOT EXISTS idx_fp_value ON feedback_patterns(pattern_type, pattern_value);

-- ── Honeytokens ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS honeytokens (
    id          TEXT PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    type        TEXT NOT NULL DEFAULT 'file',
    description TEXT,
    created_ts  REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 1
);

-- ── Identities ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS identities (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL UNIQUE,
    created_ts      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS identity_accounts (
    id              TEXT PRIMARY KEY,
    identity_id     TEXT NOT NULL,
    username        TEXT NOT NULL,
    hostname        TEXT,
    platform        TEXT,
    FOREIGN KEY (identity_id) REFERENCES identities(id)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_account_unique
    ON identity_accounts(identity_id, username, hostname);

-- ── Pending actions — AI-proposed remediations awaiting operator approval ───
CREATE TABLE IF NOT EXISTS pending_actions (
    id            TEXT PRIMARY KEY,
    created_ts    REAL NOT NULL,
    action_type   TEXT NOT NULL,
    target        TEXT NOT NULL,
    reason        TEXT NOT NULL,
    incident_id   TEXT,
    assessment_id TEXT,
    status        TEXT NOT NULL DEFAULT 'pending',
    resolved_ts   REAL,
    resolve_note  TEXT,
    result        TEXT
);

CREATE INDEX IF NOT EXISTS idx_pending_status ON pending_actions(status);

-- ── AI Audit log — black box for every inference ─────────────────────────────
CREATE TABLE IF NOT EXISTS ai_audit_log (
    id              TEXT PRIMARY KEY,
    ts              REAL NOT NULL,
    model           TEXT NOT NULL,
    prompt          TEXT NOT NULL,
    response        TEXT NOT NULL,
    inference_ms    INTEGER,
    triggered_by    TEXT,
    assessment_id   TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts ON ai_audit_log(ts DESC);
"""

# ── Default honeytokens (created on first run) ────────────────────────────────
DEFAULT_HONEYTOKENS = [
    ("/tmp/id_rsa",           "file",       "Fake SSH private key"),
    ("/tmp/.secret_key",      "file",       "Fake API secret"),
    ("/root/.aws/credentials","file",       "Fake AWS credentials"),
    ("/tmp/passwords.txt",    "file",       "Fake password store"),
]


class Database:
    """
    All database operations for the AI-SOC system.
    Uses WAL mode for concurrent reads during SSE streaming.
    Thread-safe: each call uses its own connection from the same file.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or settings.db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._init()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def _init(self):
        """Apply schema and seed default data."""
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
            self._seed_honeytokens(conn)
        finally:
            conn.close()
        logger.info(f"Database initialized: {self.path}")

    def _seed_honeytokens(self, conn: sqlite3.Connection):
        """Insert default honeytokens if they don't exist."""
        import uuid
        for path, htype, desc in DEFAULT_HONEYTOKENS:
            conn.execute("""
                INSERT OR IGNORE INTO honeytokens (id, path, type, description, created_ts)
                VALUES (?, ?, ?, ?, ?)
            """, (str(uuid.uuid4()), path, htype, desc, time.time()))
        conn.commit()

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = self._connect()
        return self._conn

    # ── Events ───────────────────────────────────────────────────────────────

    def store_event(self, event: Event) -> None:
        payload_json = self._serialize_payload(event)
        self.conn.execute("""
            INSERT OR REPLACE INTO events
                (id, ts, source, type, severity, title, raw,
                 entities_json, payload_json, incident_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.id,
            event.ts,
            event.source.value,
            event.type.value,
            event.severity.value,
            event.title,
            json.dumps(event.raw),
            event.entities.to_json(),
            payload_json,
            event.incident_id,
        ))

        # Write entity index rows
        for entity_type, entity_val in event.entities.as_pairs():
            self.conn.execute("""
                INSERT OR IGNORE INTO event_entities
                    (event_id, entity_type, entity_val)
                VALUES (?, ?, ?)
            """, (event.id, entity_type, entity_val))

        self.conn.commit()

    def get_event(self, event_id: str) -> Optional[Event]:
        row = self.conn.execute(
            "SELECT * FROM events WHERE id = ?", (event_id,)
        ).fetchone()
        return self._row_to_event(row) if row else None

    def get_recent_events(self, limit: int = 50, severity: Optional[str] = None) -> list[Event]:
        if severity:
            rows = self.conn.execute("""
                SELECT * FROM events WHERE severity = ?
                ORDER BY ts DESC LIMIT ?
            """, (severity, limit)).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_event(r) for r in rows if r]

    def get_correlated_events(
        self,
        entity_vals: list[str],
        cutoff_ts: float,
        exclude_id: str,
        limit: int = 40,
    ) -> list[Event]:
        """
        Core correlation query: find events sharing entities with the trigger.
        This is what makes the context builder work.
        """
        if not entity_vals:
            return []

        placeholders = ",".join("?" * len(entity_vals))
        rows = self.conn.execute(f"""
            SELECT DISTINCT e.*
            FROM events e
            JOIN event_entities ee ON e.id = ee.event_id
            WHERE ee.entity_val IN ({placeholders})
              AND e.ts > ?
              AND e.id != ?
            ORDER BY e.ts DESC
            LIMIT ?
        """, (*entity_vals, cutoff_ts, exclude_id, limit)).fetchall()
        return [self._row_to_event(r) for r in rows if r]

    def get_events_by_window(
        self, from_ts: float, to_ts: float, limit: int = 100
    ) -> list[Event]:
        rows = self.conn.execute("""
            SELECT * FROM events
            WHERE ts BETWEEN ? AND ?
            ORDER BY ts DESC LIMIT ?
        """, (from_ts, to_ts, limit)).fetchall()
        return [self._row_to_event(r) for r in rows if r]

    def link_event_to_incident(self, event_id: str, incident_id: str) -> None:
        self.conn.execute(
            "UPDATE events SET incident_id = ? WHERE id = ?",
            (incident_id, event_id)
        )
        self.conn.commit()

    # ── Assessments ──────────────────────────────────────────────────────────

    def store_assessment(self, a: AIAssessment) -> None:
        self.conn.execute("""
            INSERT OR REPLACE INTO assessments (
                id, ts, triggered_by, correlated_events_json, model_used,
                inference_ms, severity, confidence, summary, incident_type,
                narrative_json, fp_indicators_json, mitre_technique,
                requires_immediate
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            a.id, a.ts, a.triggered_by,
            json.dumps(a.correlated_event_ids),
            a.model_used, a.inference_ms,
            a.severity.value, a.confidence, a.summary,
            a.incident_type.value,
            json.dumps({
                "source":               a.narrative.source,
                "evidence":             a.narrative.evidence,
                "assessment":           a.narrative.assessment,
                "risk":                 a.narrative.risk,
                "recommended_actions":  a.narrative.recommended_actions,
            }),
            json.dumps(a.false_positive_indicators),
            a.mitre_technique,
            int(a.requires_immediate),
        ))
        self.conn.commit()

    def get_assessment(self, assessment_id: str) -> Optional[AIAssessment]:
        row = self.conn.execute(
            "SELECT * FROM assessments WHERE id = ?", (assessment_id,)
        ).fetchone()
        return self._row_to_assessment(row) if row else None

    def get_assessment_for_event(self, event_id: str) -> Optional[AIAssessment]:
        row = self.conn.execute(
            "SELECT * FROM assessments WHERE triggered_by = ?", (event_id,)
        ).fetchone()
        return self._row_to_assessment(row) if row else None

    def get_assessments_for_incident(self, incident_id: str) -> list[AIAssessment]:
        """
        Batch fetch all assessments for events in an incident.
        Eliminates N+1 query problem in the incident detail endpoint.
        """
        rows = self.conn.execute("""
            SELECT a.* FROM assessments a
            JOIN events e ON e.id = a.triggered_by
            WHERE e.incident_id = ?
            ORDER BY a.ts ASC
        """, (incident_id,)).fetchall()
        return [self._row_to_assessment(r) for r in rows if r]

    def update_assessment_feedback(
        self,
        assessment_id: str,
        label: FeedbackLabel,
        note: Optional[str] = None,
    ) -> None:
        self.conn.execute("""
            UPDATE assessments
            SET feedback = ?, feedback_ts = ?, feedback_note = ?
            WHERE id = ?
        """, (label.value, time.time(), note, assessment_id))
        self.conn.commit()

    def get_recent_assessments(self, limit: int = 20) -> list[AIAssessment]:
        rows = self.conn.execute(
            "SELECT * FROM assessments ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_assessment(r) for r in rows if r]

    # ── Incidents ─────────────────────────────────────────────────────────────

    def store_incident(self, inc: Incident) -> None:
        self.conn.execute("""
            INSERT OR REPLACE INTO incidents (
                id, created_ts, updated_ts, status, title, severity,
                confidence, first_seen, last_seen, event_count,
                entities_json, notes_json, resolution
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            inc.id, inc.created_ts, inc.updated_ts, inc.status.value,
            inc.title, inc.severity.value, inc.confidence,
            inc.first_seen, inc.last_seen, inc.event_count,
            inc.primary_entities.to_json(),
            json.dumps(inc.notes), inc.resolution,
        ))
        self.conn.commit()

    def update_incident(self, inc: Incident) -> None:
        self.conn.execute("""
            UPDATE incidents SET
                updated_ts = ?, status = ?, title = ?, severity = ?,
                confidence = ?, last_seen = ?, event_count = ?,
                entities_json = ?, notes_json = ?, resolution = ?
            WHERE id = ?
        """, (
            time.time(), inc.status.value, inc.title, inc.severity.value,
            inc.confidence, inc.last_seen, inc.event_count,
            inc.primary_entities.to_json(), json.dumps(inc.notes),
            inc.resolution, inc.id,
        ))
        self.conn.commit()

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        row = self.conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row) if row else None

    def get_open_incidents(self, limit: int = 50) -> list[Incident]:
        rows = self.conn.execute("""
            SELECT * FROM incidents
            WHERE status IN ('open', 'investigating')
            ORDER BY last_seen DESC LIMIT ?
        """, (limit,)).fetchall()
        return [self._row_to_incident(r) for r in rows if r]

    def get_recent_incidents(self, limit: int = 20) -> list[Incident]:
        rows = self.conn.execute(
            "SELECT * FROM incidents ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_incident(r) for r in rows if r]

    def find_related_open_incident(
        self, entity_vals: list[str], time_window: float
    ) -> Optional[Incident]:
        """
        Find an open incident that shares entities with the given values,
        within the time window. Used by IncidentManager for correlation.
        """
        if not entity_vals:
            return None

        cutoff = time.time() - time_window
        placeholders = ",".join("?" * len(entity_vals))

        row = self.conn.execute(f"""
            SELECT DISTINCT i.*
            FROM incidents i
            JOIN events e ON e.incident_id = i.id
            JOIN event_entities ee ON ee.event_id = e.id
            WHERE i.status IN ('open', 'investigating')
              AND ee.entity_val IN ({placeholders})
              AND i.last_seen > ?
            ORDER BY i.last_seen DESC
            LIMIT 1
        """, (*entity_vals, cutoff)).fetchone()
        return self._row_to_incident(row) if row else None

    def get_incident_for_event(self, event_id: str) -> Optional[Incident]:
        row = self.conn.execute("""
            SELECT i.* FROM incidents i
            JOIN events e ON e.incident_id = i.id
            WHERE e.id = ?
        """, (event_id,)).fetchone()
        return self._row_to_incident(row) if row else None

    def update_incident_status(
        self, incident_id: str, status: IncidentStatus
    ) -> None:
        self.conn.execute("""
            UPDATE incidents SET status = ?, updated_ts = ? WHERE id = ?
        """, (status.value, time.time(), incident_id))
        self.conn.commit()

    # ── Snapshots ─────────────────────────────────────────────────────────────

    def store_snapshot(self, snap: SystemSnapshot) -> None:
        self.conn.execute("""
            INSERT OR REPLACE INTO system_snapshots
                (id, ts, cpu_pct, mem_pct, disk_pct,
                 containers_json, models_json, ports_json, users_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            snap.id, snap.ts, snap.cpu_pct, snap.mem_pct, snap.disk_pct,
            json.dumps(snap.containers),
            json.dumps(snap.models),
            json.dumps(snap.open_ports),
            json.dumps(snap.active_users),
        ))
        self.conn.commit()

    def get_latest_snapshot(self) -> Optional[SystemSnapshot]:
        row = self.conn.execute(
            "SELECT * FROM system_snapshots ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return SystemSnapshot(
            id=row["id"], ts=row["ts"],
            cpu_pct=row["cpu_pct"] or 0.0,
            mem_pct=row["mem_pct"] or 0.0,
            disk_pct=row["disk_pct"] or 0.0,
            containers=json.loads(row["containers_json"]),
            models=json.loads(row["models_json"]),
            open_ports=json.loads(row["ports_json"]),
            active_users=json.loads(row["users_json"]),
        )

    def get_snapshot_before(self, ts: float) -> Optional[SystemSnapshot]:
        """Get the most recent snapshot before a given timestamp."""
        row = self.conn.execute(
            "SELECT * FROM system_snapshots WHERE ts <= ? ORDER BY ts DESC LIMIT 1",
            (ts,)
        ).fetchone()
        if not row:
            return None
        return SystemSnapshot(
            id=row["id"], ts=row["ts"],
            cpu_pct=row["cpu_pct"] or 0.0,
            mem_pct=row["mem_pct"] or 0.0,
            disk_pct=row["disk_pct"] or 0.0,
            containers=json.loads(row["containers_json"]),
            models=json.loads(row["models_json"]),
            open_ports=json.loads(row["ports_json"]),
            active_users=json.loads(row["users_json"]),
        )

    # ── Feedback patterns ─────────────────────────────────────────────────────

    def store_feedback_pattern(self, p: FeedbackPattern) -> None:
        self.conn.execute("""
            INSERT INTO feedback_patterns
                (id, created_ts, pattern_type, pattern_value, label,
                 occurrence_count, last_seen)
            VALUES (?, ?, ?, ?, ?, 1, ?)
            ON CONFLICT(pattern_type, pattern_value) DO UPDATE SET
                occurrence_count = occurrence_count + 1,
                last_seen        = excluded.last_seen
        """, (
            p.id, p.created_ts, p.pattern_type,
            p.pattern_value, p.label, p.last_seen,
        ))
        self.conn.commit()

    def get_fp_patterns_for_entities(
        self, entity_vals: list[str]
    ) -> list[FeedbackPattern]:
        if not entity_vals:
            return []
        placeholders = ",".join("?" * len(entity_vals))
        rows = self.conn.execute(f"""
            SELECT * FROM feedback_patterns
            WHERE pattern_value IN ({placeholders})
              AND label = 'false_positive'
            ORDER BY occurrence_count DESC
            LIMIT 10
        """, entity_vals).fetchall()
        return [
            FeedbackPattern(
                id=r["id"], created_ts=r["created_ts"],
                pattern_type=r["pattern_type"], pattern_value=r["pattern_value"],
                label=r["label"], occurrence_count=r["occurrence_count"],
                last_seen=r["last_seen"],
            )
            for r in rows
        ]

    # ── Honeytokens ───────────────────────────────────────────────────────────

    def get_active_honeytokens(self) -> list[Honeytoken]:
        rows = self.conn.execute(
            "SELECT * FROM honeytokens WHERE active = 1"
        ).fetchall()
        return [
            Honeytoken(
                id=r["id"], path=r["path"], type=r["type"],
                description=r["description"], created_ts=r["created_ts"],
                active=bool(r["active"]),
            )
            for r in rows
        ]

    def get_honeytoken_paths(self) -> set[str]:
        rows = self.conn.execute(
            "SELECT path FROM honeytokens WHERE active = 1"
        ).fetchall()
        return {r["path"] for r in rows}

    # ── AI Audit log ──────────────────────────────────────────────────────────

    def store_audit_log(
        self,
        log_id: str,
        model: str,
        prompt: str,
        response: str,
        inference_ms: int,
        triggered_by: Optional[str] = None,
        assessment_id: Optional[str] = None,
    ) -> None:
        self.conn.execute("""
            INSERT INTO ai_audit_log
                (id, ts, model, prompt, response, inference_ms,
                 triggered_by, assessment_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            log_id, time.time(), model, prompt, response,
            inference_ms, triggered_by, assessment_id,
        ))
        self.conn.commit()

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_event_counts_by_severity(self, hours: int = 24) -> dict[str, int]:
        cutoff = time.time() - (hours * 3600)
        rows = self.conn.execute("""
            SELECT severity, COUNT(*) as cnt
            FROM events
            WHERE ts > ?
            GROUP BY severity
        """, (cutoff,)).fetchall()
        return {r["severity"]: r["cnt"] for r in rows}

    def get_incident_counts(self) -> dict[str, int]:
        rows = self.conn.execute("""
            SELECT status, COUNT(*) as cnt
            FROM incidents
            GROUP BY status
        """).fetchall()
        return {r["status"]: r["cnt"] for r in rows}

    # ── Identity ──────────────────────────────────────────────────────────────

    def get_identity_for_username(self, username: str) -> Optional[Identity]:
        row = self.conn.execute("""
            SELECT i.* FROM identities i
            JOIN identity_accounts ia ON ia.identity_id = i.id
            WHERE ia.username = ?
            LIMIT 1
        """, (username,)).fetchone()
        if not row:
            return None
        return Identity(id=row["id"], display_name=row["display_name"],
                       created_ts=row["created_ts"])

    # ── Internal serialization helpers ────────────────────────────────────────

    def _serialize_payload(self, event: Event) -> str:
        if event.wazuh:
            d = {
                "type": "wazuh",
                "rule_id": event.wazuh.rule_id,
                "rule_level": event.wazuh.rule_level,
                "rule_groups": event.wazuh.rule_groups,
                "description": event.wazuh.description,
                "agent_name": event.wazuh.agent_name,
                "agent_id": event.wazuh.agent_id,
                "location": event.wazuh.location,
                "mitre_id": event.wazuh.mitre_id,
                "mitre_tactic": event.wazuh.mitre_tactic,
                "mitre_technique": event.wazuh.mitre_technique,
                "ecs_category": event.wazuh.ecs_category,
                "ecs_action": event.wazuh.ecs_action,
                "ecs_outcome": event.wazuh.ecs_outcome,
            }
        elif event.docker:
            d = {
                "type": "docker",
                "action": event.docker.action,
                "container_id": event.docker.container_id,
                "container_name": event.docker.container_name,
                "image": event.docker.image,
                "exit_code": event.docker.exit_code,
                "is_privileged": event.docker.is_privileged,
            }
        elif event.system:
            d = {
                "type": "system",
                "metric": event.system.metric,
                "value": event.system.value,
                "threshold": event.system.threshold,
                "unit": event.system.unit,
                "detail": event.system.detail,
                "process_name": event.system.process_name,
                "pid": event.system.pid,
                "binary_path": event.system.binary_path,
            }
        else:
            d = {"type": "unknown"}
        return json.dumps(d)

    def _row_to_event(self, row: sqlite3.Row) -> Optional[Event]:
        if not row:
            return None
        try:
            entities = Entities.from_json(row["entities_json"])
            payload  = json.loads(row["payload_json"])
            ptype    = payload.get("type", "unknown")

            wazuh_p = docker_p = system_p = None
            if ptype == "wazuh":
                wazuh_p = WazuhPayload(
                    rule_id=payload["rule_id"],
                    rule_level=payload["rule_level"],
                    rule_groups=payload["rule_groups"],
                    description=payload["description"],
                    agent_name=payload["agent_name"],
                    agent_id=payload["agent_id"],
                    location=payload["location"],
                    mitre_id=payload.get("mitre_id"),
                    mitre_tactic=payload.get("mitre_tactic"),
                    mitre_technique=payload.get("mitre_technique"),
                    ecs_category=payload.get("ecs_category"),
                    ecs_action=payload.get("ecs_action"),
                    ecs_outcome=payload.get("ecs_outcome"),
                )
            elif ptype == "docker":
                docker_p = DockerPayload(
                    action=payload["action"],
                    container_id=payload["container_id"],
                    container_name=payload["container_name"],
                    image=payload["image"],
                    exit_code=payload.get("exit_code"),
                    is_privileged=payload.get("is_privileged", False),
                )
            elif ptype == "system":
                system_p = SystemPayload(
                    metric=payload["metric"],
                    value=payload["value"],
                    threshold=payload["threshold"],
                    unit=payload["unit"],
                    detail=payload["detail"],
                    process_name=payload.get("process_name"),
                    pid=payload.get("pid"),
                    binary_path=payload.get("binary_path"),
                )

            return Event(
                id=row["id"],
                ts=row["ts"],
                source=EventSource(row["source"]),
                type=EventType(row["type"]),
                severity=Severity(row["severity"]),
                title=row["title"],
                entities=entities,
                raw=json.loads(row["raw"]),
                wazuh=wazuh_p,
                docker=docker_p,
                system=system_p,
                incident_id=row["incident_id"],
            )
        except Exception as e:
            logger.error(f"Failed to deserialize event row {row['id']}: {e}")
            return None

    def _row_to_assessment(self, row: sqlite3.Row) -> Optional[AIAssessment]:
        if not row:
            return None
        try:
            narr_data = json.loads(row["narrative_json"])
            narrative = AssessmentNarrative(
                source=narr_data["source"],
                evidence=narr_data["evidence"],
                assessment=narr_data["assessment"],
                risk=narr_data["risk"],
                recommended_actions=narr_data["recommended_actions"],
            )
            return AIAssessment(
                id=row["id"], ts=row["ts"],
                triggered_by=row["triggered_by"],
                correlated_event_ids=json.loads(row["correlated_events_json"]),
                model_used=row["model_used"],
                inference_ms=row["inference_ms"] or 0,
                severity=Severity(row["severity"]),
                confidence=row["confidence"],
                summary=row["summary"],
                incident_type=IncidentType(row["incident_type"]),
                narrative=narrative,
                false_positive_indicators=json.loads(row["fp_indicators_json"]),
                mitre_technique=row["mitre_technique"],
                requires_immediate=bool(row["requires_immediate"]),
                feedback=FeedbackLabel(row["feedback"]) if row["feedback"] else None,
                feedback_ts=row["feedback_ts"],
                feedback_note=row["feedback_note"],
            )
        except Exception as e:
            logger.error(f"Failed to deserialize assessment row {row['id']}: {e}")
            return None

    def _row_to_incident(self, row: sqlite3.Row) -> Optional[Incident]:
        if not row:
            return None
        try:
            return Incident(
                id=row["id"],
                created_ts=row["created_ts"],
                updated_ts=row["updated_ts"],
                status=IncidentStatus(row["status"]),
                title=row["title"],
                severity=Severity(row["severity"]),
                confidence=row["confidence"],
                first_seen=row["first_seen"],
                last_seen=row["last_seen"],
                event_count=row["event_count"],
                primary_entities=Entities.from_json(row["entities_json"]),
                notes=json.loads(row["notes_json"]),
                resolution=row["resolution"],
            )
        except Exception as e:
            logger.error(f"Failed to deserialize incident row {row['id']}: {e}")
            return None

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None


# ── Module-level singleton ───────────────────────────────────────────────────
db = Database()
