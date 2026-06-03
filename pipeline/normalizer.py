"""
pipeline/normalizer.py

Stage 2 of the ingestion pipeline: Raw dict → typed Event.

WazuhNormalizer maps raw Wazuh JSON to our Event schema.
ECS normalization happens internally as an intermediate step.
DockerNormalizer maps raw Docker socket events.
"""

import logging
import uuid
import time
from typing import Optional

from core.models import (
    Event, EventSource, EventType, Severity,
    WazuhPayload, DockerPayload, Entities,
)

logger = logging.getLogger(__name__)

# ── ECS category mappings ─────────────────────────────────────────────────────
# Maps Wazuh rule groups → ECS event.category + event.action
ECS_MAPPINGS: dict[str, tuple[str, str, str]] = {
    # group_keyword: (ecs_category, ecs_action, ecs_outcome)
    "authentication_failures":  ("authentication", "login_failure", "failure"),
    "authentication_success":   ("authentication", "login_success", "success"),
    "sshd":                     ("authentication", "ssh", None),
    "web_attack":               ("network",         "attack",       "failure"),
    "attack":                   ("network",         "attack",       None),
    "syscheck":                 ("file",            "change",       None),
    "rootcheck":                ("process",         "suspicious",   None),
    "vulnerability-detector":   ("package",         "vulnerability",None),
    "docker":                   ("container",       "event",        None),
    "pci_dss":                  ("configuration",   "audit",        None),
}


class WazuhNormalizer:
    """
    Converts raw Wazuh alert dicts into typed Event objects.
    Handles field variations across Wazuh versions and rule packs.
    """

    def normalize(self, raw: dict) -> Optional[Event]:
        try:
            return self._normalize(raw)
        except Exception as e:
            logger.warning(f"Normalization failed: {e} — raw keys: {list(raw.keys())}")
            return None

    def _normalize(self, raw: dict) -> Event:
        rule  = raw.get("rule",  {})
        agent = raw.get("agent", {})
        data  = raw.get("data",  {})

        # ── Core fields ──────────────────────────────────────────────────────
        level     = int(rule.get("level", 0))
        severity  = self._map_severity(level)
        groups    = rule.get("groups", [])
        event_type = self._map_event_type(groups, rule.get("id", "0"))

        # ── ECS normalization (internal) ──────────────────────────────────────
        ecs_cat, ecs_action, ecs_outcome = self._map_ecs(groups)

        # ── MITRE ─────────────────────────────────────────────────────────────
        mitre      = rule.get("mitre", {})
        mitre_ids  = mitre.get("id", [])
        mitre_tacs = mitre.get("tactic", [])
        mitre_techs= mitre.get("technique", [])

        # ── Human-readable title ──────────────────────────────────────────────
        title = self._build_title(rule, data, event_type)

        # ── Timestamp ─────────────────────────────────────────────────────────
        ts = self._parse_timestamp(raw.get("timestamp", ""))

        payload = WazuhPayload(
            rule_id          = int(rule.get("id", 0)),
            rule_level       = level,
            rule_groups      = groups,
            description      = rule.get("description", ""),
            agent_name       = agent.get("name", "unknown"),
            agent_id         = agent.get("id", "000"),
            location         = raw.get("location", ""),
            mitre_id         = mitre_ids[0]   if mitre_ids   else None,
            mitre_tactic     = mitre_tacs[0]  if mitre_tacs  else None,
            mitre_technique  = mitre_techs[0] if mitre_techs else None,
            ecs_category     = ecs_cat,
            ecs_action       = ecs_action,
            ecs_outcome      = ecs_outcome,
        )

        return Event(
            id       = str(uuid.uuid4()),
            ts       = ts,
            source   = EventSource.WAZUH,
            type     = event_type,
            severity = severity,
            title    = title,
            entities = Entities(),          # populated by EntityExtractor in stage 3
            raw      = raw,
            wazuh    = payload,
        )

    # ── Severity mapping ──────────────────────────────────────────────────────

    def _map_severity(self, level: int) -> Severity:
        if level >= 13: return Severity.CRITICAL
        if level >= 10: return Severity.HIGH
        if level >= 7:  return Severity.MEDIUM
        if level >= 4:  return Severity.LOW
        return Severity.INFO

    # ── Event type mapping ────────────────────────────────────────────────────

    def _map_event_type(self, groups: list[str], rule_id: str) -> EventType:
        # More specific checks first
        if "rootkit"                  in groups: return EventType.ROOTKIT_DETECTED
        if "malware"                  in groups: return EventType.MALWARE_DETECTED
        if "vulnerability-detector"   in groups: return EventType.VULN_DETECTED
        if "syscheck"                 in groups: return EventType.FIM_CHANGE
        if "authentication_failures"  in groups: return EventType.AUTH_FAILURE
        if "authentication_success"   in groups: return EventType.AUTH_SUCCESS
        if "web_attack"               in groups: return EventType.WEB_ATTACK
        if "attack"                   in groups: return EventType.NETWORK_SCAN
        if "pci_dss"                  in groups: return EventType.POLICY_VIOLATION
        # Privilege escalation indicators
        if any(g in groups for g in ("su", "sudo", "escalation")):
            return EventType.PRIV_ESCALATION
        # Brute force detection (high frequency auth failures)
        # Rule IDs 5551, 5712, 5716 = Wazuh SSH brute force
        if rule_id in ("5551", "5712", "5716", "5720"):
            return EventType.BRUTE_FORCE
        return EventType.WAZUH_GENERIC

    # ── ECS mapping ───────────────────────────────────────────────────────────

    def _map_ecs(
        self, groups: list[str]
    ) -> tuple[Optional[str], Optional[str], Optional[str]]:
        for group in groups:
            if group in ECS_MAPPINGS:
                cat, action, outcome = ECS_MAPPINGS[group]
                return cat, action, outcome
        return None, None, None

    # ── Title builder ─────────────────────────────────────────────────────────

    def _build_title(self, rule: dict, data: dict, etype: EventType) -> str:
        """Build the most informative one-liner possible for the operator."""
        description = rule.get("description", "Unknown event")

        # Enrich with source IP
        src_ip = (data.get("srcip") or data.get("src_ip") or
                  data.get("remote_ip") or data.get("remoteip"))
        if src_ip:
            return f"{description} from {src_ip}"[:80]

        # Enrich FIM events with file path
        if etype == EventType.FIM_CHANGE:
            syscheck = data.get("syscheck", {})
            path = syscheck.get("path") or data.get("path")
            if path:
                return f"File changed: {path}"[:80]

        # Enrich vulnerability events with CVE
        vuln = data.get("vulnerability", {})
        if vuln.get("cve"):
            return f"{vuln['cve']}: {description}"[:80]

        return description[:80]

    # ── Timestamp parser ──────────────────────────────────────────────────────

    def _parse_timestamp(self, ts_str: str) -> float:
        if not ts_str:
            return time.time()
        try:
            from datetime import datetime, timezone
            # Wazuh format: "2024-01-15T10:30:00.000+0000"
            ts_str = ts_str.replace("+0000", "+00:00").replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp()
        except Exception:
            return time.time()


class DockerNormalizer:
    """Converts raw Docker socket events into typed Event objects."""

    def normalize(self, raw: dict) -> Optional[Event]:
        try:
            return self._normalize(raw)
        except Exception as e:
            logger.warning(f"Docker normalization failed: {e}")
            return None

    def _normalize(self, raw: dict) -> Optional[Event]:
        ev_type  = raw.get("Type", "")
        action   = raw.get("Action", "")
        actor    = raw.get("Actor", {})
        attrs    = actor.get("Attributes", {})

        if ev_type != "container":
            return None  # only handle container events for now

        name    = attrs.get("name", actor.get("ID", "unknown")[:12])
        image   = attrs.get("image", "unknown")
        cid     = actor.get("ID", "")

        event_type, severity = self._map_action(action, attrs)
        if event_type is None:
            return None  # ignore events we don't care about

        title = self._build_title(action, name, image, attrs)

        return Event(
            id       = str(uuid.uuid4()),
            ts       = float(raw.get("time", time.time())),
            source   = EventSource.DOCKER,
            type     = event_type,
            severity = severity,
            title    = title,
            entities = Entities(),
            raw      = raw,
            docker   = DockerPayload(
                action         = action,
                container_id   = cid[:12],
                container_name = name,
                image          = image,
                exit_code      = self._get_exit_code(attrs),
                is_privileged  = self._is_privileged(attrs),
                attributes     = attrs,
            ),
        )

    def _map_action(
        self, action: str, attrs: dict
    ) -> tuple[Optional[EventType], Severity]:
        # Privileged container is always HIGH regardless of action
        if action == "start" and self._is_privileged(attrs):
            return EventType.PRIVILEGED_CONTAINER, Severity.HIGH

        mapping = {
            "start":   (EventType.CONTAINER_STARTED,   Severity.INFO),
            "stop":    (EventType.CONTAINER_STOPPED,   Severity.INFO),
            "die":     (EventType.CONTAINER_DIED,      Severity.MEDIUM),
            "create":  (EventType.CONTAINER_CREATED,   Severity.INFO),
            "destroy": (EventType.CONTAINER_DESTROYED, Severity.LOW),
            "kill":    (EventType.CONTAINER_DIED,      Severity.MEDIUM),
            "oom":     (EventType.CONTAINER_DIED,      Severity.HIGH),
        }
        return mapping.get(action, (None, Severity.INFO))

    def _is_privileged(self, attrs: dict) -> bool:
        security_opt = attrs.get("security_opt", "")
        return "privileged=true" in str(security_opt).lower()

    def _get_exit_code(self, attrs: dict) -> Optional[int]:
        code = attrs.get("exitCode")
        if code is not None:
            try:
                return int(code)
            except (ValueError, TypeError):
                pass
        return None

    def _build_title(
        self, action: str, name: str, image: str, attrs: dict
    ) -> str:
        if action == "die":
            exit_code = attrs.get("exitCode", "?")
            return f"Container {name} exited (code {exit_code})"[:80]
        if action == "oom":
            return f"Container {name} killed: out of memory"[:80]
        return f"Container {action}: {name} ({image})"[:80]
