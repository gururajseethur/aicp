"""
api/routes.py

All API routes for the SOC dashboard.
"""

import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.config import settings
from core.database import db
from core.event_bus import bus
from core.models import (
    FeedbackLabel, IncidentStatus, FeedbackPattern,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["api"])


# ══════════════════════════════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/health")
async def health():
    ollama_ok = await _check_ollama()
    snap      = db.get_latest_snapshot()
    return {
        "status":         "ok",
        "ts":             time.time(),
        "ollama":         ollama_ok,
        "ollama_model":   settings.ollama_model,
        "db":             "ok",
        "subscribers":    bus.subscriber_count,
        "snapshot_age_s": round(time.time() - snap.ts) if snap else None,
    }


# ══════════════════════════════════════════════════════════════════════════════
# INCIDENTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/incidents")
async def list_incidents(status: Optional[str] = None, limit: int = 50):
    if status:
        incidents = [
            i for i in db.get_recent_incidents(limit=200)
            if i.status.value == status
        ][:limit]
    else:
        incidents = db.get_open_incidents(limit=limit)
    return {"incidents": [i.to_dashboard_dict() for i in incidents], "count": len(incidents)}


@router.get("/incidents/{incident_id}")
async def get_incident(incident_id: str):
    incident = db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    rows = db.conn.execute(
        "SELECT * FROM events WHERE incident_id = ? ORDER BY ts ASC",
        (incident_id,)
    ).fetchall()
    incident_events = [db._row_to_event(r) for r in rows if r]
    incident_events = [e for e in incident_events if e]
    assessments = [
        a.to_dashboard_dict()
        for a in db.get_assessments_for_incident(incident_id)
    ]
    return {
        "incident":    incident.to_dashboard_dict(),
        "events":      [_event_to_dict(e) for e in incident_events],
        "assessments": assessments,
    }


class IncidentStatusUpdate(BaseModel):
    status: str
    note:   Optional[str] = None


@router.post("/incidents/{incident_id}/status")
async def update_incident_status(incident_id: str, body: IncidentStatusUpdate):
    try:
        status = IncidentStatus(body.status)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid status")
    incident = db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    db.update_incident_status(incident_id, status)
    if body.note:
        incident.notes.append(f"{_fmt_ts(time.time())}: {body.note}")
        db.update_incident(incident)
    await bus.emit({"type": "incident_updated", "incident_id": incident_id,
                    "status": status.value, "ts": time.time()})
    return {"ok": True, "status": status.value}


# ══════════════════════════════════════════════════════════════════════════════
# ASSESSMENTS
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/assessments")
async def list_assessments(limit: int = 20):
    assessments = db.get_recent_assessments(limit=limit)
    return {"assessments": [a.to_dashboard_dict() for a in assessments], "count": len(assessments)}


@router.get("/assessments/{assessment_id}")
async def get_assessment(assessment_id: str):
    a = db.get_assessment(assessment_id)
    if not a:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return a.to_dashboard_dict()


@router.get("/events/{event_id}/assessment")
async def get_event_assessment(event_id: str):
    a = db.get_assessment_for_event(event_id)
    if not a:
        raise HTTPException(status_code=404, detail="No assessment for this event")
    return a.to_dashboard_dict()


# ══════════════════════════════════════════════════════════════════════════════
# FEEDBACK
# ══════════════════════════════════════════════════════════════════════════════

class FeedbackRequest(BaseModel):
    label: str
    note:  Optional[str] = None


@router.post("/assessments/{assessment_id}/feedback")
async def submit_feedback(assessment_id: str, body: FeedbackRequest):
    try:
        label = FeedbackLabel(body.label)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid label")
    assessment = db.get_assessment(assessment_id)
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    db.update_assessment_feedback(assessment_id, label, body.note)
    if label == FeedbackLabel.FALSE_POSITIVE:
        event = db.get_event(assessment.triggered_by)
        if event:
            await _learn_fp_patterns(event)
    if assessment.triggered_by:
        event = db.get_event(assessment.triggered_by)
        if event and event.incident_id:
            if label == FeedbackLabel.FALSE_POSITIVE:
                db.update_incident_status(event.incident_id, IncidentStatus.FALSE_POSITIVE)
            elif label == FeedbackLabel.CONFIRMED:
                db.update_incident_status(event.incident_id, IncidentStatus.INVESTIGATING)
    await bus.emit({"type": "feedback_recorded", "assessment_id": assessment_id,
                    "label": label.value, "ts": time.time()})
    return {"ok": True, "label": label.value,
            "message": "False positive pattern recorded." if label == FeedbackLabel.FALSE_POSITIVE else "Feedback recorded."}


async def _learn_fp_patterns(event) -> None:
    for entity_type, entity_val in event.entities.as_pairs():
        pattern = FeedbackPattern(
            id=str(uuid.uuid4()), created_ts=time.time(),
            pattern_type=entity_type, pattern_value=entity_val,
            label="false_positive", last_seen=time.time(),
        )
        db.store_feedback_pattern(pattern)


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM STATE
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/system/state")
async def system_state():
    snap       = db.get_latest_snapshot()
    sev_counts = db.get_event_counts_by_severity(hours=24)
    inc_counts = db.get_incident_counts()
    open_incs  = db.get_open_incidents(limit=5)
    return {
        "ts": time.time(),
        "snapshot": {
            "cpu_pct":      snap.cpu_pct    if snap else 0,
            "mem_pct":      snap.mem_pct    if snap else 0,
            "disk_pct":     snap.disk_pct   if snap else 0,
            "containers":   snap.containers if snap else [],
            "models":       snap.models     if snap else [],
            "active_users": snap.active_users if snap else [],
            "open_ports":   snap.open_ports if snap else [],
            "age_s":        round(time.time() - snap.ts) if snap else None,
        },
        "events_24h":       sev_counts,
        "incident_counts":  inc_counts,
        "open_incidents":   [i.to_dashboard_dict() for i in open_incs],
        "ollama_available": await _check_ollama(),
    }


@router.get("/system/events")
async def recent_events(limit: int = 50, severity: Optional[str] = None):
    events = db.get_recent_events(limit=limit, severity=severity)
    return {"events": [_event_to_dict(e) for e in events], "count": len(events)}


@router.get("/system/models")
async def list_models():
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"{settings.ollama_url}/api/tags")
            if r.status_code == 200:
                models = [{"name": m.get("name",""), "size_gb": round(m.get("size",0)/1e9,2),
                           "modified_at": m.get("modified_at",""), "details": m.get("details",{})}
                          for m in r.json().get("models",[])]
                return {"models": models, "count": len(models)}
    except Exception as e:
        logger.debug(f"Ollama models: {e}")
    return {"models": [], "count": 0, "error": "Ollama unavailable"}


# ══════════════════════════════════════════════════════════════════════════════
# ANALYTICS — timeline, MITRE, top IPs
# ══════════════════════════════════════════════════════════════════════════════

@router.get("/analytics/timeline")
async def event_timeline(hours: int = 24):
    """
    Hourly event counts for the last N hours, broken down by severity.
    Used by the 24h attack timeline chart.
    """
    cutoff = time.time() - (hours * 3600)
    rows = db.conn.execute("""
        SELECT
            CAST((ts - ?) / 3600 AS INTEGER) AS hour_bucket,
            severity,
            COUNT(*) AS cnt
        FROM events
        WHERE ts > ?
        GROUP BY hour_bucket, severity
        ORDER BY hour_bucket
    """, (cutoff, cutoff)).fetchall()

    # Build dense array: one entry per hour
    buckets: dict[int, dict] = {}
    for i in range(hours):
        buckets[i] = {"hour": i, "critical":0, "high":0, "medium":0, "low":0, "info":0}

    for row in rows:
        h   = min(int(row["hour_bucket"]), hours - 1)
        sev = row["severity"]
        if sev in buckets[h]:
            buckets[h][sev] = row["cnt"]

    # Add timestamps
    now = time.time()
    result = []
    for i in range(hours):
        b = buckets[i]
        b["ts"] = now - (hours - i - 1) * 3600
        result.append(b)

    return {"timeline": result, "hours": hours}


@router.get("/analytics/mitre")
async def mitre_breakdown():
    """MITRE ATT&CK tactic and technique counts from recent events."""
    cutoff = time.time() - (7 * 24 * 3600)  # last 7 days
    rows = db.conn.execute("""
        SELECT payload_json, COUNT(*) as cnt
        FROM events
        WHERE ts > ? AND source = 'wazuh'
        GROUP BY payload_json
    """, (cutoff,)).fetchall()

    tactics:    dict[str, int] = {}
    techniques: dict[str, int] = {}

    for row in rows:
        try:
            p = json.loads(row["payload_json"])
            tac  = p.get("mitre_tactic")
            tech = p.get("mitre_id")
            cnt  = row["cnt"]
            if tac:  tactics[tac]    = tactics.get(tac, 0)    + cnt
            if tech: techniques[tech] = techniques.get(tech, 0) + cnt
        except Exception:
            pass

    return {
        "tactics":    sorted([{"name":k,"count":v} for k,v in tactics.items()],    key=lambda x:-x["count"]),
        "techniques": sorted([{"name":k,"count":v} for k,v in techniques.items()], key=lambda x:-x["count"])[:10],
    }


@router.get("/analytics/top-ips")
async def top_ips(limit: int = 10):
    """Top source IPs by event count — for the attack map and ranking table."""
    cutoff = time.time() - (24 * 3600)
    rows = db.conn.execute("""
        SELECT ee.entity_val AS ip, COUNT(*) AS cnt,
               MAX(e.severity) AS max_sev,
               MAX(e.ts) AS last_seen
        FROM event_entities ee
        JOIN events e ON ee.event_id = e.id
        WHERE ee.entity_type = 'ip'
          AND e.ts > ?
          AND ee.entity_val NOT IN ('127.0.0.1','::1','0.0.0.0')
        GROUP BY ee.entity_val
        ORDER BY cnt DESC
        LIMIT ?
    """, (cutoff, limit)).fetchall()
    return {
        "ips": [{"ip": r["ip"], "count": r["cnt"],
                 "max_severity": r["max_sev"], "last_seen": r["last_seen"]}
                for r in rows]
    }


@router.get("/analytics/geoip/{ip}")
async def geoip(ip: str):
    """
    Resolve an IP to country/coordinates for the attack map.
    Uses ipapi.co (free, no key, 1000 req/day).
    Falls back to a hardcoded table for known IPs.
    """
    # Known IPs hardcoded for offline/dev use
    KNOWN = {
        "185.220.101.47": {"country": "Germany", "country_code": "DE",
                           "lat": 51.1657, "lon": 10.4515, "org": "Tor Exit Node"},
        "185.220.101.1":  {"country": "Germany", "country_code": "DE",
                           "lat": 51.1657, "lon": 10.4515, "org": "Tor Network"},
    }
    if ip in KNOWN:
        return KNOWN[ip]

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(f"https://ipapi.co/{ip}/json/")
            if r.status_code == 200:
                d = r.json()
                if not d.get("error"):
                    return {
                        "country":      d.get("country_name", "Unknown"),
                        "country_code": d.get("country_code", "XX"),
                        "lat":          d.get("latitude",  0),
                        "lon":          d.get("longitude", 0),
                        "org":          d.get("org", ""),
                        "city":         d.get("city", ""),
                    }
    except Exception:
        pass

    return {"country": "Unknown", "country_code": "XX", "lat": 0, "lon": 0, "org": ""}


# ══════════════════════════════════════════════════════════════════════════════
# PENDING ACTIONS — AI proposes, human approves, then executes
# This is NOT auto-execution. Every action requires explicit operator approval.
# ══════════════════════════════════════════════════════════════════════════════

class PendingActionCreate(BaseModel):
    action_type:   str        # "block_ip" | "restart_container" | "notify"
    target:        str        # "185.220.101.47" | "nginx"
    reason:        str        # Why the AI is recommending this
    incident_id:   Optional[str] = None
    assessment_id: Optional[str] = None


class PendingActionApprove(BaseModel):
    approved: bool
    note:     Optional[str] = None


@router.get("/pending-actions")
async def list_pending_actions():
    """List all pending AI-recommended actions awaiting operator approval."""
    rows = db.conn.execute("""
        SELECT * FROM pending_actions
        WHERE status = 'pending'
        ORDER BY created_ts DESC
    """).fetchall()
    return {
        "actions": [dict(r) for r in rows],
        "count":   len(rows),
    }


@router.post("/pending-actions")
async def create_pending_action(body: PendingActionCreate):
    """Create a new pending action (called by AI analyst)."""
    action_id = str(uuid.uuid4())
    db.conn.execute("""
        INSERT INTO pending_actions
            (id, created_ts, action_type, target, reason,
             incident_id, assessment_id, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    """, (action_id, time.time(), body.action_type, body.target,
          body.reason, body.incident_id, body.assessment_id))
    db.conn.commit()

    await bus.emit({
        "type":        "pending_action",
        "action_id":   action_id,
        "action_type": body.action_type,
        "target":      body.target,
        "reason":      body.reason,
        "ts":          time.time(),
    })
    return {"ok": True, "action_id": action_id}


@router.post("/pending-actions/{action_id}/approve")
async def approve_action(action_id: str, body: PendingActionApprove):
    """
    Operator approves or denies a pending action.
    Approved actions execute their safe implementation.
    Denied actions are marked rejected — no execution.
    """
    row = db.conn.execute(
        "SELECT * FROM pending_actions WHERE id = ?", (action_id,)
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Action not found")
    if dict(row)["status"] != "pending":
        raise HTTPException(status_code=400, detail="Action already resolved")

    status   = "approved" if body.approved else "rejected"
    result   = None

    if body.approved:
        result = await _execute_action(dict(row))

    db.conn.execute("""
        UPDATE pending_actions
        SET status = ?, resolved_ts = ?, resolve_note = ?, result = ?
        WHERE id = ?
    """, (status, time.time(), body.note, json.dumps(result), action_id))
    db.conn.commit()

    await bus.emit({
        "type":      "action_resolved",
        "action_id": action_id,
        "status":    status,
        "result":    result,
        "ts":        time.time(),
    })
    return {"ok": True, "status": status, "result": result}


async def _execute_action(action: dict) -> dict:
    """
    Safe execution of approved actions.
    Each action type has a guarded implementation.
    Returns a result dict describing what happened.
    """
    atype  = action["action_type"]
    target = action["target"]

    if atype == "block_ip":
        # In production: run iptables -I INPUT -s {target} -j DROP
        # Here we log it and return — real implementation requires root + safety checks
        logger.warning(f"ACTION: Block IP {target} (approved by operator)")
        return {"executed": True, "command": f"iptables -I INPUT -s {target} -j DROP",
                "note": "Manual execution required — see README for root access setup"}

    if atype == "restart_container":
        try:
            import httpx as _httpx
            transport = _httpx.AsyncHTTPTransport(uds="/var/run/docker.sock")
            async with _httpx.AsyncClient(transport=transport, timeout=10) as client:
                r = await client.post(f"http://localhost/containers/{target}/restart")
                return {"executed": True, "status": r.status_code}
        except Exception as e:
            return {"executed": False, "error": str(e)}

    if atype == "notify":
        logger.info(f"ACTION: Notification — {target}")
        return {"executed": True, "note": target}

    return {"executed": False, "error": f"Unknown action type: {atype}"}


# ══════════════════════════════════════════════════════════════════════════════
# CHAT
# ══════════════════════════════════════════════════════════════════════════════

CHAT_SYSTEM_PROMPT = """\
You are an AI security analyst assistant for a local SOC (Security Operations Center).
You have access to current system state and recent security incidents.
Answer operator questions about security events, system state, and incidents.
Be specific. Reference actual data. Be direct — this is a security tool, not a chatbot.
If you don't have enough data to answer confidently, say so clearly."""


class ChatRequest(BaseModel):
    message: str
    history: list[dict] = []


@router.post("/chat")
async def chat(req: ChatRequest):
    snap       = db.get_latest_snapshot()
    open_incs  = db.get_open_incidents(limit=10)
    sev_counts = db.get_event_counts_by_severity(hours=24)

    context = "\n".join([
        "=== CURRENT SYSTEM STATE ===",
        snap.to_context_string() if snap else "No snapshot.",
        "",
        "=== EVENTS LAST 24h ===",
        ", ".join(f"{k}: {v}" for k,v in sev_counts.items()) or "None",
        "",
        "=== OPEN INCIDENTS ===",
        *([f"• [{i.severity.value.upper()}] {i.title} ({i.event_count} events)"
           for i in open_incs[:5]] or ["No open incidents."]),
    ])

    messages = [{"role": "system", "content": CHAT_SYSTEM_PROMPT + "\n\n" + context}]
    for h in req.history[-10:]:
        if h.get("role") in ("user","assistant") and h.get("content"):
            messages.append({"role": h["role"], "content": h["content"]})
    messages.append({"role": "user", "content": req.message})

    async def stream_response():
        try:
            async with httpx.AsyncClient(timeout=settings.ollama_timeout) as client:
                async with client.stream("POST", f"{settings.ollama_url}/api/chat",
                    json={"model": settings.ollama_model, "messages": messages,
                          "stream": True, "options": {"temperature": 0.3}}) as resp:
                    if resp.status_code != 200:
                        yield f"data: {json.dumps({'type':'error','message':'Ollama unavailable'})}\n\n"
                        return
                    async for line in resp.aiter_lines():
                        if not line.strip(): continue
                        try:
                            chunk = json.loads(line)
                            token = chunk.get("message",{}).get("content","")
                            done  = chunk.get("done", False)
                            if token: yield f"data: {json.dumps({'type':'token','content':token})}\n\n"
                            if done:  yield f"data: {json.dumps({'type':'done'})}\n\n"; return
                        except json.JSONDecodeError:
                            continue
        except Exception as e:
            yield f"data: {json.dumps({'type':'error','message':str(e)})}\n\n"

    return StreamingResponse(stream_response(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


# ══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════════════════

async def _check_ollama() -> bool:
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{settings.ollama_url}/api/tags")
            return r.status_code == 200
    except Exception:
        return False


def _event_to_dict(event) -> dict:
    if not event: return {}
    return {
        "id": event.id, "ts": event.ts,
        "source": event.source.value, "type": event.type.value,
        "severity": event.severity.value, "title": event.title,
        "incident_id": event.incident_id,
        "entities": {"ips": event.entities.ips, "users": event.entities.users,
                     "files": event.entities.files, "containers": event.entities.containers},
        "wazuh": {"rule_id": event.wazuh.rule_id, "rule_level": event.wazuh.rule_level,
                  "description": event.wazuh.description, "agent_name": event.wazuh.agent_name,
                  "mitre_id": event.wazuh.mitre_id, "mitre_tactic": event.wazuh.mitre_tactic,
                  "mitre_technique": event.wazuh.mitre_technique,
                  "ecs_category": event.wazuh.ecs_category,
                  "ecs_action": event.wazuh.ecs_action} if event.wazuh else None,
        "docker": {"action": event.docker.action, "container_name": event.docker.container_name,
                   "image": event.docker.image, "is_privileged": event.docker.is_privileged} if event.docker else None,
    }


def _fmt_ts(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M UTC")


import asyncio
import json
import logging
import time
import uuid
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.config import settings
from core.database import db
from core.event_bus import bus
from core.models import (
    FeedbackLabel, IncidentStatus, FeedbackPattern,
)

