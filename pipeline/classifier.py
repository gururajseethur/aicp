"""
pipeline/classifier.py

Stage 4: Classification and Honeytoken Detection.

Decides:
  - Should the AI analyze this event?
  - What priority (1=CRITICAL, 2=HIGH, 3=MEDIUM)?
  - Is this an incident candidate (needs correlation check)?
  - Is this a honeytoken hit (always CRITICAL, bypasses normal flow)?

Honeytoken detection runs BEFORE normal classification.
A honeytoken hit overrides everything and goes to priority 1.
"""

import logging
from typing import Optional

from core.models import Event, EventType, Severity, ClassificationResult
from core.config import settings

logger = logging.getLogger(__name__)

# ── Rule groups that are always noise (never worth analyzing) ────────────────
# These are routine system events that produce false positives constantly.
ALWAYS_NOISE_GROUPS = frozenset({
    "pam_unix",       # routine PAM authentication
    "syslog",         # general syslog chatter
    "cron",           # scheduled jobs
    "dpkg",           # package manager
    "apt",            # apt operations
    "service_control",# systemd unit state changes
    "logrotate",      # log rotation
    "kernel",         # kernel messages (unless high level)
    "local",          # local syslog
})

# Rule IDs known to produce noise on most systems
NOISE_RULE_IDS = frozenset({
    "5500",  # PAM: user login attempt
    "5501",  # PAM: user logged off
    "5502",  # PAM: unsuccessful login
})


class HoneytokenDetector:
    """
    Pre-filter that runs before all other classification.
    If a FIM event touches a known honeytoken path → CRITICAL, bypass filter.
    """

    def __init__(self, honeytoken_paths: Optional[set[str]] = None):
        # Injected from DB on pipeline startup
        self._paths: set[str] = honeytoken_paths or set()

    def update_paths(self, paths: set[str]) -> None:
        """Refresh honeytoken paths from database."""
        self._paths = paths

    def check(self, event: Event) -> bool:
        """
        Returns True if this event is a honeytoken hit.
        Side effect: escalates event severity to CRITICAL and updates title.
        """
        if event.type not in (EventType.FIM_CHANGE, EventType.WAZUH_GENERIC):
            return False

        if not self._paths:
            return False

        for file_path in event.entities.files:
            if file_path in self._paths:
                # Override — honeytoken access is always critical
                event.severity = Severity.CRITICAL
                event.type     = EventType.HONEYTOKEN_ACCESS
                event.title    = f"HONEYTOKEN ACCESSED: {file_path}"
                logger.warning(f"Honeytoken hit: {file_path} in event {event.id}")
                return True

        # Also check the raw syscheck path for events before entity extraction
        syscheck = event.raw.get("data", {}).get("syscheck", {})
        raw_path = syscheck.get("path") or event.raw.get("data", {}).get("path")
        if raw_path and raw_path in self._paths:
            event.severity = Severity.CRITICAL
            event.type     = EventType.HONEYTOKEN_ACCESS
            event.title    = f"HONEYTOKEN ACCESSED: {raw_path}"
            logger.warning(f"Honeytoken hit (raw): {raw_path} in event {event.id}")
            return True

        return False


class EventClassifier:
    """
    Decides whether and how urgently the AI should analyze an event.

    Rules:
      CRITICAL or HIGH (Wazuh level >= 10) → always analyze, priority 1 or 2
      MEDIUM (level 7-9) → analyze only if entity has prior activity
      LOW / INFO → store only, no AI analysis
      Known noise groups → suppress regardless of level
    """

    def __init__(self, db=None):
        # db is injected to avoid circular imports
        self._db = db

    def classify(self, event: Event) -> ClassificationResult:
        # ── Suppress known noise first ────────────────────────────────────────
        if self._is_known_noise(event):
            return ClassificationResult(
                should_analyze        = False,
                analysis_priority     = 99,
                is_incident_candidate = False,
                suppressed            = True,
                suppression_reason    = "known noise pattern",
            )

        # ── CRITICAL ──────────────────────────────────────────────────────────
        if event.severity == Severity.CRITICAL:
            return ClassificationResult(
                should_analyze        = True,
                analysis_priority     = 1,
                is_incident_candidate = True,
                suppressed            = False,
            )

        # ── HIGH ──────────────────────────────────────────────────────────────
        if event.severity == Severity.HIGH:
            return ClassificationResult(
                should_analyze        = True,
                analysis_priority     = 2,
                is_incident_candidate = True,
                suppressed            = False,
            )

        # ── MEDIUM — conditional analysis ─────────────────────────────────────
        if event.severity == Severity.MEDIUM:
            if self._has_prior_activity(event):
                return ClassificationResult(
                    should_analyze        = True,
                    analysis_priority     = 3,
                    is_incident_candidate = True,
                    suppressed            = False,
                )
            return ClassificationResult(
                should_analyze        = False,
                analysis_priority     = 99,
                is_incident_candidate = True,   # still track for incidents
                suppressed            = False,
                suppression_reason    = "medium severity, no prior activity",
            )

        # ── LOW / INFO — store only ───────────────────────────────────────────
        return ClassificationResult(
            should_analyze        = False,
            analysis_priority     = 99,
            is_incident_candidate = False,
            suppressed            = False,
            suppression_reason    = "below analysis threshold",
        )

    def _is_known_noise(self, event: Event) -> bool:
        """True if this event is routine system noise not worth analyzing."""
        if not event.wazuh:
            return False

        # If rule level is high enough, override noise suppression
        if event.wazuh.rule_level >= settings.always_analyze_level:
            return False

        groups   = set(event.wazuh.rule_groups)
        rule_id  = str(event.wazuh.rule_id)

        if groups & ALWAYS_NOISE_GROUPS:
            return True

        if rule_id in NOISE_RULE_IDS:
            return True

        return False

    def _has_prior_activity(self, event: Event) -> bool:
        """
        Check if any entity in this event has appeared in a recent event.
        Medium-severity events are only analyzed if the same entity is active.
        """
        if not self._db:
            return False  # safe default: don't analyze if no DB

        if not event.entities.has_any():
            return False

        import time
        cutoff = time.time() - (2 * 3600)  # 2-hour window
        entity_vals = event.entities.all_values()

        if not entity_vals:
            return False

        placeholders = ",".join("?" * len(entity_vals))
        try:
            row = self._db.conn.execute(f"""
                SELECT COUNT(*) as cnt
                FROM event_entities ee
                JOIN events e ON ee.event_id = e.id
                WHERE ee.entity_val IN ({placeholders})
                  AND e.ts > ?
                  AND e.severity IN ('medium', 'high', 'critical')
                  AND e.id != ?
            """, (*entity_vals, cutoff, event.id)).fetchone()
            return (row["cnt"] if row else 0) > 0
        except Exception as ex:
            logger.warning(f"Prior activity check failed: {ex}")
            return False
