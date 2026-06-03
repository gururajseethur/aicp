"""
core/models.py

All dataclasses, enums, and typed schemas for the entire system.
Single source of truth — every module imports from here.

Three-layer event design:
  Layer 1 — EventBase:   identity (id, ts, source, type, severity, title)
  Layer 2 — Entities:    normalized actors (IPs, users, files, containers, ...)
  Layer 3 — Payload:     typed details (WazuhPayload | DockerPayload | SystemPayload)
"""

from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
import time
import json


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS
# ══════════════════════════════════════════════════════════════════════════════

class EventSource(str, Enum):
    WAZUH   = "wazuh"
    DOCKER  = "docker"
    SYSTEM  = "system"
    OLLAMA  = "ollama"
    USER    = "user"          # manually created by operator


class EventType(str, Enum):
    # ── Wazuh: authentication ──────────────────────────────────
    AUTH_FAILURE        = "auth_failure"
    AUTH_SUCCESS        = "auth_success"
    BRUTE_FORCE         = "brute_force"

    # ── Wazuh: file integrity ──────────────────────────────────
    FIM_CHANGE          = "fim_change"
    HONEYTOKEN_ACCESS   = "honeytoken_access"  # always CRITICAL

    # ── Wazuh: network ─────────────────────────────────────────
    NETWORK_SCAN        = "network_scan"
    WEB_ATTACK          = "web_attack"

    # ── Wazuh: system ──────────────────────────────────────────
    PRIV_ESCALATION     = "priv_escalation"
    ROOTKIT_DETECTED    = "rootkit_detected"
    MALWARE_DETECTED    = "malware_detected"
    VULN_DETECTED       = "vuln_detected"
    POLICY_VIOLATION    = "policy_violation"
    WAZUH_GENERIC       = "wazuh_generic"

    # ── Docker ─────────────────────────────────────────────────
    CONTAINER_STARTED   = "container_started"
    CONTAINER_STOPPED   = "container_stopped"
    CONTAINER_DIED      = "container_died"
    CONTAINER_CREATED   = "container_created"
    CONTAINER_DESTROYED = "container_destroyed"
    PRIVILEGED_CONTAINER = "privileged_container"  # always HIGH

    # ── System ─────────────────────────────────────────────────
    HIGH_CPU            = "high_cpu"
    HIGH_MEMORY         = "high_memory"
    HIGH_DISK           = "high_disk"
    NEW_PORT            = "new_listening_port"
    SUSPICIOUS_PROCESS  = "suspicious_process"

    # ── Ollama ─────────────────────────────────────────────────
    MODEL_LOADED        = "model_loaded"
    MODEL_REMOVED       = "model_removed"


class Severity(str, Enum):
    INFO        = "info"      # Wazuh level 1-3
    LOW         = "low"       # Wazuh level 4-6
    MEDIUM      = "medium"    # Wazuh level 7-9
    HIGH        = "high"      # Wazuh level 10-12
    CRITICAL    = "critical"  # Wazuh level 13-15

    def __gt__(self, other: Severity) -> bool:
        return SEVERITY_ORDER[self] > SEVERITY_ORDER[other]

    def __ge__(self, other: Severity) -> bool:
        return SEVERITY_ORDER[self] >= SEVERITY_ORDER[other]


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO:     0,
    Severity.LOW:      1,
    Severity.MEDIUM:   2,
    Severity.HIGH:     3,
    Severity.CRITICAL: 4,
}


class IncidentStatus(str, Enum):
    OPEN            = "open"
    INVESTIGATING   = "investigating"
    RESOLVED        = "resolved"
    FALSE_POSITIVE  = "false_positive"


class FeedbackLabel(str, Enum):
    CONFIRMED       = "confirmed"
    FALSE_POSITIVE  = "false_positive"
    INVESTIGATE     = "investigate"


class IncidentType(str, Enum):
    BRUTE_FORCE         = "brute_force"
    PORT_SCAN           = "port_scan"
    FIM_CHANGE          = "fim_change"
    PRIV_ESCALATION     = "priv_escalation"
    MALWARE             = "malware"
    VULNERABILITY       = "vulnerability"
    CONTAINER_ANOMALY   = "container_anomaly"
    HONEYTOKEN          = "honeytoken"
    ANOMALY             = "anomaly"
    BENIGN              = "benign"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — ENTITIES (normalized, same structure for all event types)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Entities:
    """
    Normalized actors extracted from any event.
    Stored separately in event_entities table for fast correlation queries.
    """
    ips:        list[str] = field(default_factory=list)
    users:      list[str] = field(default_factory=list)
    files:      list[str] = field(default_factory=list)
    containers: list[str] = field(default_factory=list)
    processes:  list[str] = field(default_factory=list)
    ports:      list[int] = field(default_factory=list)
    hashes:     list[str] = field(default_factory=list)
    cves:       list[str] = field(default_factory=list)

    def has_any(self) -> bool:
        return any([self.ips, self.users, self.files,
                    self.containers, self.processes, self.ports])

    def all_values(self) -> list[str]:
        """All entity values as a flat list — used for SQL IN queries."""
        vals: list[str] = []
        vals.extend(self.ips)
        vals.extend(self.users)
        vals.extend(self.files)
        vals.extend(self.containers)
        vals.extend(self.processes)
        vals.extend(str(p) for p in self.ports)
        vals.extend(self.hashes)
        vals.extend(self.cves)
        return list(set(vals))  # deduplicate

    def as_pairs(self) -> list[tuple[str, str]]:
        """
        Returns (entity_type, entity_value) pairs.
        Used when writing to the event_entities table.
        """
        pairs: list[tuple[str, str]] = []
        for ip in self.ips:         pairs.append(("ip",        ip))
        for u  in self.users:       pairs.append(("user",      u))
        for f  in self.files:       pairs.append(("file",      f))
        for c  in self.containers:  pairs.append(("container", c))
        for p  in self.processes:   pairs.append(("process",   p))
        for pt in self.ports:       pairs.append(("port",      str(pt)))
        for h  in self.hashes:      pairs.append(("hash",      h))
        for cv in self.cves:        pairs.append(("cve",       cv))
        return pairs

    def merge(self, other: Entities) -> Entities:
        """Merge two Entities objects (used when updating incidents)."""
        return Entities(
            ips        = list(set(self.ips        + other.ips)),
            users      = list(set(self.users      + other.users)),
            files      = list(set(self.files      + other.files)),
            containers = list(set(self.containers + other.containers)),
            processes  = list(set(self.processes  + other.processes)),
            ports      = list(set(self.ports      + other.ports)),
            hashes     = list(set(self.hashes     + other.hashes)),
            cves       = list(set(self.cves       + other.cves)),
        )

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @classmethod
    def from_json(cls, s: str) -> Entities:
        d = json.loads(s)
        return cls(**d)


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — TYPED PAYLOADS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class WazuhPayload:
    rule_id:            int
    rule_level:         int             # 1-15
    rule_groups:        list[str]
    description:        str
    agent_name:         str
    agent_id:           str
    location:           str             # log file the event came from
    mitre_id:           Optional[str]   # "T1110.001"
    mitre_tactic:       Optional[str]   # "Credential Access"
    mitre_technique:    Optional[str]   # "Brute Force: Password Spraying"

    # ECS-normalized fields (populated by normalizer)
    ecs_category:       Optional[str] = None  # "authentication"
    ecs_action:         Optional[str] = None  # "login_failure"
    ecs_outcome:        Optional[str] = None  # "failure"


@dataclass
class DockerPayload:
    action:             str             # "start" | "stop" | "die" | "create" | "destroy"
    container_id:       str
    container_name:     str
    image:              str
    exit_code:          Optional[int]
    is_privileged:      bool = False
    attributes:         dict = field(default_factory=dict)


@dataclass
class SystemPayload:
    metric:             str             # "cpu" | "memory" | "disk" | "new_port"
    value:              float
    threshold:          float
    unit:               str             # "percent" | "bytes" | "port_number"
    detail:             str
    process_name:       Optional[str] = None
    pid:                Optional[int]  = None
    binary_path:        Optional[str] = None


@dataclass
class OllamaPayload:
    action:             str             # "model_loaded" | "model_removed" | "inference_slow"
    model:              str
    detail:             str


# ══════════════════════════════════════════════════════════════════════════════
# THE EVENT (full, all three layers)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Event:
    # Layer 1 — Identity
    id:         str
    ts:         float               # unix timestamp, millisecond precision
    source:     EventSource
    type:       EventType
    severity:   Severity
    title:      str                 # one sentence, max 80 chars

    # Layer 2 — Entities
    entities:   Entities

    # Raw original payload (never modified after ingestion)
    raw:        dict

    # Layer 3 — Typed payload (only one is populated)
    wazuh:      Optional[WazuhPayload]   = None
    docker:     Optional[DockerPayload]  = None
    system:     Optional[SystemPayload]  = None
    ollama:     Optional[OllamaPayload]  = None

    # Set by pipeline after correlation
    incident_id: Optional[str] = None

    def to_json(self) -> str:
        """Serialize for SSE stream and database storage."""
        return json.dumps({
            "id":          self.id,
            "ts":          self.ts,
            "source":      self.source.value,
            "type":        self.type.value,
            "severity":    self.severity.value,
            "title":       self.title,
            "entities":    asdict(self.entities),
            "incident_id": self.incident_id,
        })


# ══════════════════════════════════════════════════════════════════════════════
# AI ASSESSMENT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class AssessmentNarrative:
    """The structured narrative section of an AI assessment."""
    source:              str            # who/what is causing this
    evidence:            list[str]      # specific observations
    assessment:          str            # what is likely happening
    risk:                str            # consequence if ignored
    recommended_actions: list[str]      # ordered by priority


@dataclass
class AIAssessment:
    id:                         str
    ts:                         float
    triggered_by:               str             # event.id
    correlated_event_ids:       list[str]
    model_used:                 str
    inference_ms:               int

    # Core AI output
    severity:                   Severity
    confidence:                 float           # 0.0 to 1.0
    summary:                    str             # one sentence max 100 chars
    incident_type:              IncidentType
    narrative:                  AssessmentNarrative
    false_positive_indicators:  list[str]
    mitre_technique:            Optional[str]
    requires_immediate:         bool

    # Human feedback (filled in later via dashboard)
    feedback:                   Optional[FeedbackLabel] = None
    feedback_ts:                Optional[float]         = None
    feedback_note:              Optional[str]           = None

    def to_dashboard_dict(self) -> dict:
        """Serialized form sent to the dashboard via SSE."""
        return {
            "id":                       self.id,
            "ts":                       self.ts,
            "triggered_by":             self.triggered_by,
            "severity":                 self.severity.value,
            "confidence":               self.confidence,
            "summary":                  self.summary,
            "incident_type":            self.incident_type.value,
            "narrative":                {
                "source":               self.narrative.source,
                "evidence":             self.narrative.evidence,
                "assessment":           self.narrative.assessment,
                "risk":                 self.narrative.risk,
                "recommended_actions":  self.narrative.recommended_actions,
            },
            "false_positive_indicators": self.false_positive_indicators,
            "mitre_technique":          self.mitre_technique,
            "requires_immediate":       self.requires_immediate,
            "model_used":               self.model_used,
            "inference_ms":             self.inference_ms,
            "feedback":                 self.feedback.value if self.feedback else None,
        }


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Incident:
    id:                 str
    created_ts:         float
    updated_ts:         float
    status:             IncidentStatus
    title:              str
    severity:           Severity
    confidence:         float
    first_seen:         float
    last_seen:          float
    event_count:        int
    primary_entities:   Entities
    notes:              list[str] = field(default_factory=list)
    resolution:         Optional[str] = None

    def to_dashboard_dict(self) -> dict:
        return {
            "id":               self.id,
            "created_ts":       self.created_ts,
            "updated_ts":       self.updated_ts,
            "status":           self.status.value,
            "title":            self.title,
            "severity":         self.severity.value,
            "confidence":       self.confidence,
            "first_seen":       self.first_seen,
            "last_seen":        self.last_seen,
            "event_count":      self.event_count,
            "entities": {
                "ips":       self.primary_entities.ips,
                "users":     self.primary_entities.users,
                "files":     self.primary_entities.files,
                "containers":self.primary_entities.containers,
            },
        }


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM SNAPSHOT
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SystemSnapshot:
    id:             str
    ts:             float
    cpu_pct:        float
    mem_pct:        float
    disk_pct:       float
    containers:     list[dict]      # [{name, state, image}]
    models:         list[str]       # loaded Ollama models
    open_ports:     list[dict]      # [{port, process, pid, is_container}]
    active_users:   list[str]

    def to_context_string(self) -> str:
        """Human-readable summary for AI prompt context."""
        running = [c["name"] for c in self.containers if c.get("state") == "running"]
        lines = [
            f"CPU: {self.cpu_pct}%  Memory: {self.mem_pct}%  Disk: {self.disk_pct}%",
            f"Containers running: {len(running)} — {', '.join(running[:6])}",
            f"AI models loaded:   {', '.join(self.models) if self.models else 'none'}",
        ]
        if self.active_users:
            lines.append(f"Active users: {', '.join(self.active_users)}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════════
# PIPELINE INTERNAL TYPES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ClassificationResult:
    should_analyze:         bool
    analysis_priority:      int             # 1=CRITICAL, 2=HIGH, 3=MEDIUM
    is_incident_candidate:  bool
    suppressed:             bool
    suppression_reason:     Optional[str] = None
    is_honeytoken_hit:      bool = False


@dataclass
class AnalysisJob:
    event_id:       str
    priority:       int
    enqueued_at:    float = field(default_factory=time.time)

    def __lt__(self, other: AnalysisJob) -> bool:
        """Lower priority number = higher importance. Used by PriorityQueue."""
        return self.priority < other.priority


@dataclass
class AssessmentReadyEvent:
    """Published to EventBus when an AI assessment is complete."""
    event_id:           str
    assessment_id:      str
    incident_id:        Optional[str]
    severity:           Severity
    requires_immediate: bool
    ts:                 float = field(default_factory=time.time)

    def to_sse(self) -> str:
        return json.dumps({
            "type":             "assessment_ready",
            "event_id":         self.event_id,
            "assessment_id":    self.assessment_id,
            "incident_id":      self.incident_id,
            "severity":         self.severity.value,
            "requires_immediate": self.requires_immediate,
            "ts":               self.ts,
        })


# ══════════════════════════════════════════════════════════════════════════════
# IDENTITY MAPPING
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Identity:
    """Maps a human operator to all their system accounts across devices."""
    id:             str
    display_name:   str             # "gururaj"
    created_ts:     float


@dataclass
class IdentityAccount:
    """One specific account belonging to an identity."""
    id:             str
    identity_id:    str
    username:       str             # "root"
    hostname:       Optional[str]   # "ubuntu"
    platform:       Optional[str]   # "linux" | "windows" | "mac"


# ══════════════════════════════════════════════════════════════════════════════
# HONEYTOKENS
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class Honeytoken:
    """
    A file, credential, or port that should NEVER be accessed legitimately.
    Any access = immediate CRITICAL event bypassing normal filtering.
    """
    id:             str
    path:           str             # "/tmp/id_rsa"
    type:           str             # "file" | "credential" | "port"
    description:    Optional[str]
    created_ts:     float
    active:         bool = True


# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK PATTERN
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class FeedbackPattern:
    """
    Learned false positive pattern from operator feedback.
    Injected into AI prompts to reduce future false positives.
    """
    id:                 str
    created_ts:         float
    pattern_type:       str         # "ip" | "user" | "rule_id" | "file"
    pattern_value:      str         # the specific value
    label:              str         # "false_positive" | "confirmed"
    occurrence_count:   int = 1
    last_seen:          float = field(default_factory=time.time)
