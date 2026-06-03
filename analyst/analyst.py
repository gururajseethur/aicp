"""
analyst/analyst.py

The AI Analyst — full implementation.

Components:
  ContextBuilder      — gathers correlated events + system state
  PromptBuilder       — constructs the structured LLM prompt
  OllamaInference     — calls Ollama, validates JSON output
  IncidentManager     — groups events into incidents
  AIAnalystWorker     — priority queue, one inference at a time
"""

import asyncio
import json
import logging
import time
import uuid
from dataclasses import asdict
from typing import Optional

import httpx
from pydantic import BaseModel, Field, ValidationError, field_validator

from core.config import settings
from core.database import Database
from core.event_bus import EventBus
from core.models import (
    Event, AIAssessment, AssessmentNarrative,
    Incident, IncidentStatus, IncidentType,
    Severity, SEVERITY_ORDER, AnalysisJob,
    FeedbackPattern, AssessmentReadyEvent,
)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# CONTEXT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

class ContextBuilder:
    """
    Assembles the context package for the AI analyst.
    Entity-correlated, not time-correlated.
    """

    def __init__(self, db: Database):
        self._db = db

    def build(self, trigger: Event) -> dict:
        """
        Returns a context dict with:
          trigger          — the triggering event
          related          — entity-correlated events (last 24h)
          snapshot         — latest system state
          fp_patterns      — known false positive patterns for these entities
          entity_history   — past incidents involving same entities
        """
        cutoff   = trigger.ts - (settings.context_lookback_hours * 3600)
        entities = trigger.entities.all_values()

        related  = self._db.get_correlated_events(
            entity_vals = entities,
            cutoff_ts   = cutoff,
            exclude_id  = trigger.id,
            limit       = settings.context_related_events,
        )

        snapshot     = self._db.get_latest_snapshot()
        fp_patterns  = self._db.get_fp_patterns_for_entities(entities)
        ip_history   = self._get_entity_history(trigger.entities.ips)

        return {
            "trigger":      trigger,
            "related":      related,
            "snapshot":     snapshot,
            "fp_patterns":  fp_patterns,
            "ip_history":   ip_history,
        }

    def _get_entity_history(self, ips: list[str]) -> list[Incident]:
        """Past incidents involving the same IPs (last 30 days)."""
        if not ips:
            return []
        # Check recent incidents for IP overlap
        recent = self._db.get_recent_incidents(limit=100)
        result = []
        for inc in recent:
            if any(ip in inc.primary_entities.ips for ip in ips):
                result.append(inc)
                if len(result) >= 5:
                    break
        return result


# ══════════════════════════════════════════════════════════════════════════════
# PROMPT BUILDER
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """\
You are a security analyst reviewing alerts from a local Linux infrastructure system.

Your job: analyze the trigger event and all correlated context, then produce a \
structured security assessment.

Rules:
- Be specific. Reference actual IPs, usernames, file paths, and timestamps from evidence.
- Express genuine uncertainty. Use confidence < 0.5 when evidence is ambiguous.
- Always consider benign explanations before concluding malicious.
- "false_positive_indicators" must argue the benign case, even if you think it's malicious.
- "incident_type" must be one of: brute_force, port_scan, fim_change, priv_escalation, \
malware, vulnerability, container_anomaly, honeytoken, anomaly, benign
- Output ONLY valid JSON. No markdown. No explanation outside the JSON.

Output schema (respond with exactly this structure):
{
  "severity": "info|low|medium|high|critical",
  "confidence": 0.0,
  "summary": "one sentence under 100 characters",
  "incident_type": "brute_force",
  "narrative": {
    "source": "who or what is causing this",
    "evidence": ["specific observation 1", "specific observation 2"],
    "assessment": "what is likely happening and why",
    "risk": "consequence if this is ignored",
    "recommended_actions": ["action 1", "action 2"]
  },
  "false_positive_indicators": ["reason this might be benign"],
  "mitre_technique": "T1110.001 or null",
  "requires_immediate_action": false
}"""


def build_user_prompt(ctx: dict) -> str:
    """Build the user-turn prompt from the context dict."""
    trigger: Event      = ctx["trigger"]
    related: list[Event] = ctx["related"]
    snapshot             = ctx["snapshot"]
    fp_patterns          = ctx["fp_patterns"]
    ip_history           = ctx["ip_history"]

    parts = []

    # ── Trigger event ─────────────────────────────────────────────────────────
    parts.append("=== TRIGGER EVENT ===")
    parts.append(f"Time:     {_fmt_ts(trigger.ts)}")
    parts.append(f"Source:   {trigger.source.value}")
    parts.append(f"Type:     {trigger.type.value}")
    parts.append(f"Severity: {trigger.severity.value}")
    parts.append(f"Title:    {trigger.title}")

    if trigger.wazuh:
        w = trigger.wazuh
        parts.append(f"Rule:     [{w.rule_id}] {w.description}")
        parts.append(f"Level:    {w.rule_level}/15")
        parts.append(f"Agent:    {w.agent_name}")
        if w.rule_groups:
            parts.append(f"Groups:   {', '.join(w.rule_groups[:5])}")
        if w.mitre_id:
            parts.append(f"MITRE:    {w.mitre_id} — {w.mitre_technique or ''} ({w.mitre_tactic or ''})")
        if w.ecs_category:
            parts.append(f"ECS:      {w.ecs_category} / {w.ecs_action or ''}")

    if trigger.entities.ips:
        parts.append(f"Source IPs:  {', '.join(trigger.entities.ips)}")
    if trigger.entities.users:
        parts.append(f"Users:       {', '.join(trigger.entities.users)}")
    if trigger.entities.files:
        parts.append(f"Files:       {', '.join(trigger.entities.files[:5])}")
    if trigger.entities.ports:
        parts.append(f"Ports:       {', '.join(str(p) for p in trigger.entities.ports)}")
    if trigger.entities.cves:
        parts.append(f"CVEs:        {', '.join(trigger.entities.cves)}")

    # ── Related events ────────────────────────────────────────────────────────
    if related:
        parts.append(f"\n=== CORRELATED EVENTS ({len(related)} found, last 24h) ===")

        # Group by type for readability — summarize high-volume repetitive events
        by_type: dict[str, list[Event]] = {}
        for e in related:
            by_type.setdefault(e.type.value, []).append(e)

        for etype, events in sorted(by_type.items()):
            if len(events) > 5:
                # Summarize to avoid flooding the context window
                parts.append(
                    f"• {etype}: {len(events)} occurrences "
                    f"({_fmt_ts(events[-1].ts)} → {_fmt_ts(events[0].ts)})"
                )
            else:
                for e in events:
                    parts.append(f"• {_fmt_ts(e.ts)} [{e.severity.value}] {e.title}")
    else:
        parts.append("\n=== CORRELATED EVENTS ===\nNone found in last 24h.")

    # ── Entity history (past incidents) ───────────────────────────────────────
    if ip_history:
        parts.append("\n=== ENTITY HISTORY (past incidents) ===")
        for inc in ip_history:
            parts.append(
                f"• {_fmt_ts(inc.first_seen)} [{inc.severity.value}] "
                f"{inc.title} — {inc.status.value}"
            )

    # ── System state ──────────────────────────────────────────────────────────
    if snapshot:
        parts.append(f"\n=== CURRENT SYSTEM STATE ===")
        parts.append(snapshot.to_context_string())

    # ── False positive patterns ───────────────────────────────────────────────
    if fp_patterns:
        parts.append("\n=== KNOWN FALSE POSITIVE PATTERNS (from operator feedback) ===")
        parts.append("These patterns have been marked false positive on this system:")
        for p in fp_patterns:
            parts.append(
                f"• [{p.pattern_type}] {p.pattern_value} "
                f"— marked FP {p.occurrence_count} time(s)"
            )

    parts.append("\nAnalyze all of the above and respond with the JSON schema only.")
    return "\n".join(parts)


def _fmt_ts(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ══════════════════════════════════════════════════════════════════════════════
# OUTPUT VALIDATION (pydantic)
# ══════════════════════════════════════════════════════════════════════════════

class NarrativeOutput(BaseModel):
    source:              str
    evidence:            list[str]
    assessment:          str
    risk:                str
    recommended_actions: list[str]


class AssessmentOutput(BaseModel):
    severity:                  str
    confidence:                float = Field(ge=0.0, le=1.0)
    summary:                   str   = Field(max_length=200)
    incident_type:             str
    narrative:                 NarrativeOutput
    false_positive_indicators: list[str]
    mitre_technique:           Optional[str]
    requires_immediate_action: bool

    @field_validator("severity")
    @classmethod
    def valid_severity(cls, v):
        allowed = {"info", "low", "medium", "high", "critical"}
        if v.lower() not in allowed:
            raise ValueError(f"severity must be one of {allowed}")
        return v.lower()

    @field_validator("incident_type")
    @classmethod
    def valid_incident_type(cls, v):
        allowed = {t.value for t in IncidentType}
        if v.lower() not in allowed:
            return "anomaly"  # safe fallback
        return v.lower()


# ══════════════════════════════════════════════════════════════════════════════
# OLLAMA INFERENCE ENGINE
# ══════════════════════════════════════════════════════════════════════════════

class OllamaInferenceEngine:
    """
    Calls Ollama API, validates output, handles retries.
    temperature: 0.1 — deterministic security analysis.
    format: "json" — Ollama tokenizer-level JSON enforcement.
    """

    async def analyze(
        self, ctx: dict, db: Database
    ) -> Optional[AIAssessment]:
        trigger: Event = ctx["trigger"]
        system_prompt  = SYSTEM_PROMPT
        user_prompt    = build_user_prompt(ctx)

        start_ts = time.time()

        for attempt, model in enumerate(
            [settings.ollama_model, settings.ollama_fallback_model]
        ):
            try:
                raw_output = await asyncio.wait_for(
                    self._call_ollama(model, system_prompt, user_prompt),
                    timeout=settings.ollama_timeout,
                )

                # Audit log — black box record of every inference
                log_id = str(uuid.uuid4())
                inference_ms = int((time.time() - start_ts) * 1000)

                assessment = self._parse_and_validate(
                    raw_output, trigger, ctx["related"],
                    model, inference_ms,
                )

                if assessment:
                    # Store audit log
                    db.store_audit_log(
                        log_id       = log_id,
                        model        = model,
                        prompt       = user_prompt[:10000],  # cap size
                        response     = raw_output[:10000],
                        inference_ms = inference_ms,
                        triggered_by = trigger.id,
                        assessment_id= assessment.id,
                    )
                    logger.info(
                        f"Assessment complete: {assessment.severity.value} "
                        f"conf={assessment.confidence:.2f} "
                        f"model={model} "
                        f"time={inference_ms}ms"
                    )
                    return assessment

                logger.warning(
                    f"Attempt {attempt+1}: output failed validation — "
                    f"trying fallback model"
                )

            except asyncio.TimeoutError:
                logger.warning(
                    f"Inference timeout ({settings.ollama_timeout}s) "
                    f"on attempt {attempt+1}, model {model}"
                )
                if attempt == 1:
                    return self._fallback_assessment(trigger, "inference_timeout")

            except Exception as e:
                # Log as WARNING not ERROR — Ollama being unavailable is expected
                # (e.g. user hasn't started it yet). ERROR implies a code bug.
                logger.warning(f"Inference unavailable (attempt {attempt+1}, {model}): {type(e).__name__}")
                if attempt == 1:
                    return self._fallback_assessment(trigger, str(e))

        return self._fallback_assessment(trigger, "all_attempts_failed")

    async def _call_ollama(
        self, model: str, system: str, user: str
    ) -> str:
        """Make the Ollama API call."""
        # Sanitize prompt — prevent prompt injection from log content
        user_clean = self._sanitize(user)

        async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
            response = await client.post(
                f"{settings.ollama_url}/api/chat",
                json={
                    "model":  model,
                    "format": "json",           # tokenizer-level JSON enforcement
                    "stream": False,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user_clean},
                    ],
                    "options": {
                        "temperature": settings.ollama_temperature,
                        "top_p":       0.9,
                        "num_predict": 1024,
                    },
                },
            )
            response.raise_for_status()
            return response.json()["message"]["content"]

    def _sanitize(self, text: str) -> str:
        """
        Remove prompt injection attempts from log content before sending to AI.
        Attackers can write "Ignore previous instructions" to log files.
        """
        injection_patterns = [
            "ignore previous instructions",
            "ignore all previous",
            "disregard the above",
            "forget your instructions",
            "you are now",
            "act as",
            "jailbreak",
            "DAN mode",
            "developer mode",
        ]
        text_lower = text.lower()
        for pattern in injection_patterns:
            if pattern in text_lower:
                logger.warning(f"Prompt injection attempt detected: '{pattern}'")
                # Replace with safe marker
                text = text.replace(pattern, "[SANITIZED]")
                text = text.replace(pattern.title(), "[SANITIZED]")
                text = text.replace(pattern.upper(), "[SANITIZED]")
        return text

    def _parse_and_validate(
        self,
        raw: str,
        trigger: Event,
        related: list[Event],
        model: str,
        inference_ms: int,
    ) -> Optional[AIAssessment]:
        """Parse JSON output and validate against schema."""
        try:
            data = json.loads(raw)
            validated = AssessmentOutput(**data)

            narrative = AssessmentNarrative(
                source              = validated.narrative.source,
                evidence            = validated.narrative.evidence,
                assessment          = validated.narrative.assessment,
                risk                = validated.narrative.risk,
                recommended_actions = validated.narrative.recommended_actions,
            )

            return AIAssessment(
                id                        = str(uuid.uuid4()),
                ts                        = time.time(),
                triggered_by              = trigger.id,
                correlated_event_ids      = [e.id for e in related],
                model_used                = model,
                inference_ms              = inference_ms,
                severity                  = Severity(validated.severity),
                confidence                = validated.confidence,
                summary                   = validated.summary,
                incident_type             = IncidentType(validated.incident_type),
                narrative                 = narrative,
                false_positive_indicators = validated.false_positive_indicators,
                mitre_technique           = validated.mitre_technique,
                requires_immediate        = validated.requires_immediate_action,
            )

        except json.JSONDecodeError as e:
            logger.warning(f"JSON decode failed: {e} | Raw: {raw[:200]}")
            return None
        except ValidationError as e:
            logger.warning(f"Schema validation failed: {e}")
            return None

    def _fallback_assessment(
        self, trigger: Event, reason: str
    ) -> AIAssessment:
        """
        When AI completely fails, return a minimal honest assessment.
        'Analysis unavailable' is better than silence — operator still
        sees the alert and knows to investigate manually.
        """
        return AIAssessment(
            id                        = str(uuid.uuid4()),
            ts                        = time.time(),
            triggered_by              = trigger.id,
            correlated_event_ids      = [],
            model_used                = "fallback",
            inference_ms              = 0,
            severity                  = trigger.severity,
            confidence                = 0.0,
            summary                   = f"AI analysis unavailable: {reason[:80]}",
            incident_type             = IncidentType.ANOMALY,
            narrative                 = AssessmentNarrative(
                source              = "unknown — analysis failed",
                evidence            = [trigger.title],
                assessment          = "Manual review required. AI analysis failed.",
                risk                = "Unknown — assess manually.",
                recommended_actions = ["Review alert manually", "Check system logs"],
            ),
            false_positive_indicators = [],
            mitre_technique           = (
                trigger.wazuh.mitre_id if trigger.wazuh else None
            ),
            requires_immediate        = trigger.severity in (
                Severity.HIGH, Severity.CRITICAL
            ),
        )


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENT MANAGER
# ══════════════════════════════════════════════════════════════════════════════

class IncidentManager:
    """
    Groups correlated events into incidents.
    Option C: auto-group by entity + time window.
    """

    def __init__(self, db: Database):
        self._db = db

    def process(
        self, event: Event, assessment: AIAssessment
    ) -> Incident:
        """Find or create the incident this event belongs to."""
        entity_vals = event.entities.all_values()
        existing    = self._db.find_related_open_incident(
            entity_vals = entity_vals,
            time_window = settings.incident_window,
        )

        if existing:
            return self._update_incident(existing, event, assessment)
        else:
            return self._create_incident(event, assessment)

    def _create_incident(
        self, event: Event, assessment: AIAssessment
    ) -> Incident:
        # Use AI summary as title, but fall back to event title if AI failed
        ai_failed = assessment.model_used == "fallback" or assessment.confidence == 0.0
        title = event.title if ai_failed else assessment.summary

        incident = Incident(
            id               = str(uuid.uuid4()),
            created_ts       = time.time(),
            updated_ts       = time.time(),
            status           = IncidentStatus.OPEN,
            title            = title,
            severity         = assessment.severity,
            confidence       = assessment.confidence,
            first_seen       = event.ts,
            last_seen        = event.ts,
            event_count      = 1,
            primary_entities = event.entities,
        )
        self._db.store_incident(incident)
        logger.info(
            f"New incident: [{incident.severity.value}] {incident.title}"
        )
        return incident

    def _update_incident(
        self, incident: Incident, event: Event, assessment: AIAssessment
    ) -> Incident:
        # Escalate severity if new event is more severe
        if SEVERITY_ORDER[assessment.severity] > SEVERITY_ORDER[incident.severity]:
            incident.severity = assessment.severity
            logger.info(
                f"Incident {incident.id[:8]} escalated to "
                f"{incident.severity.value}"
            )

        # Update confidence to the latest assessment
        incident.confidence   = assessment.confidence
        incident.updated_ts   = time.time()
        incident.last_seen    = event.ts
        incident.event_count += 1

        # Merge entities
        incident.primary_entities = incident.primary_entities.merge(
            event.entities
        )

        self._db.update_incident(incident)
        return incident


# ══════════════════════════════════════════════════════════════════════════════
# AI ANALYST WORKER — priority queue, single inference at a time
# ══════════════════════════════════════════════════════════════════════════════

class AIAnalystWorker:
    """
    Bounded priority queue. One inference at a time.

    Priority levels:
      1 = CRITICAL (honeytoken hits, level 13-15) — never dropped
      2 = HIGH (level 10-12)                      — never dropped
      3 = MEDIUM (correlated)                     — dropped if queue full

    MAX_QUEUE = 50. When full, lowest priority job is dropped first.
    """

    MAX_QUEUE    = 50
    STALE_AFTER  = 300  # seconds — skip jobs older than this

    def __init__(self, db: Database, bus: EventBus):
        self._db              = db
        self._bus             = bus
        self._queue:list      = []          # sorted list of (priority, job)
        self._sem             = asyncio.Semaphore(1)   # one inference at a time
        self._queue_lock      = asyncio.Lock()
        self._has_work        = asyncio.Event()
        self._inference       = OllamaInferenceEngine()
        self._context_builder: Optional[ContextBuilder] = None
        self._incident_manager: Optional[IncidentManager] = None
        self.running          = False

    def _init_helpers(self):
        if not self._context_builder:
            self._context_builder  = ContextBuilder(self._db)
            self._incident_manager = IncidentManager(self._db)

    async def enqueue(self, event_id: str, priority: int) -> None:
        """Add a job to the queue. Drop lowest priority if full."""
        async with self._queue_lock:
            job = AnalysisJob(event_id=event_id, priority=priority)

            if len(self._queue) < self.MAX_QUEUE:
                self._queue.append((priority, job))
                self._queue.sort(key=lambda x: x[0])  # ascending — lower = higher priority
            else:
                # Find the lowest priority (highest number) droppable job
                # Never drop priority 1 (CRITICAL) or 2 (HIGH)
                droppable = [
                    i for i, (p, _) in enumerate(self._queue) if p >= 3
                ]
                if not droppable:
                    logger.warning(
                        f"Queue full of HIGH/CRITICAL jobs — dropping {event_id}"
                    )
                    return

                # Drop the one with highest priority number (least important)
                # and oldest enqueue time (if tie)
                worst_idx = max(
                    droppable,
                    key=lambda i: (self._queue[i][0], self._queue[i][1].enqueued_at)
                )
                dropped = self._queue.pop(worst_idx)
                logger.debug(
                    f"Queue full: dropped P{dropped[0]} job "
                    f"{dropped[1].event_id[:8]}"
                )
                self._queue.append((priority, job))
                self._queue.sort(key=lambda x: x[0])

        self._has_work.set()

    async def run(self) -> None:
        """Main worker loop. Runs forever as background task."""
        self.running = True
        self._init_helpers()
        logger.info("AI Analyst worker started")

        while self.running:
            try:
                await asyncio.wait_for(self._has_work.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return

            # Pop next job
            async with self._queue_lock:
                if not self._queue:
                    self._has_work.clear()
                    continue
                _, job = self._queue.pop(0)
                if not self._queue:
                    self._has_work.clear()

            # Process
            try:
                await self._process_job(job)
            except asyncio.CancelledError:
                return
            except Exception as e:
                logger.error(f"Analyst worker error: {e}", exc_info=True)

    async def _process_job(self, job: AnalysisJob) -> None:
        # Staleness check
        age = time.time() - job.enqueued_at
        if age > self.STALE_AFTER:
            logger.warning(
                f"Skipping stale job {job.event_id[:8]} "
                f"(queued {age:.0f}s ago)"
            )
            return

        # Duplicate check — already assessed?
        event = self._db.get_event(job.event_id)
        if not event:
            return
        if self._db.get_assessment_for_event(job.event_id):
            logger.debug(f"Already assessed {job.event_id[:8]}, skipping")
            return

        # Build context
        ctx = self._context_builder.build(event)

        # Run inference (single inference at a time via semaphore)
        async with self._sem:
            assessment = await self._inference.analyze(ctx, self._db)

        if not assessment:
            return

        # Store assessment
        self._db.store_assessment(assessment)

        # Create or update incident
        incident = self._incident_manager.process(event, assessment)

        # Link trigger event to incident
        self._db.link_event_to_incident(event.id, incident.id)

        # Also link all correlated events to this same incident
        # This gives accurate event_count and lets operators see the full chain
        # e.g. 5 SSH failures + 1 brute-force detection = 1 incident, 6 events
        for related_event in ctx["related"]:
            if related_event.incident_id is None:
                self._db.link_event_to_incident(related_event.id, incident.id)
                # Update the local incident event_count for each linked event
                incident.event_count += 1
        if ctx["related"]:
            # Persist the updated event_count
            self._db.update_incident(incident)

        # Learn false positive patterns if model flagged benign signals
        if assessment.false_positive_indicators:
            self._record_fp_signals(event, assessment)

        # Notify dashboard via SSE
        await self._bus.emit({
            "type":               "assessment_ready",
            "event_id":           event.id,
            "assessment_id":      assessment.id,
            "incident_id":        incident.id,
            "severity":           assessment.severity.value,
            "confidence":         assessment.confidence,
            "summary":            assessment.summary,
            "requires_immediate": assessment.requires_immediate,
            "ts":                 assessment.ts,
            "assessment":         assessment.to_dashboard_dict(),
            "incident":           incident.to_dashboard_dict(),
        })

    def _record_fp_signals(
        self, event: Event, assessment: AIAssessment
    ) -> None:
        """
        Store the entity patterns the AI flagged as potentially benign.
        These are injected into future prompts via ContextBuilder.
        Only records patterns the operator later confirms as FP.
        (Here we just pre-stage them — operator feedback confirms.)
        """
        # This is called when AI itself notes FP indicators.
        # The actual pattern storage happens in the feedback endpoint
        # when the operator marks an assessment as false_positive.
        pass
