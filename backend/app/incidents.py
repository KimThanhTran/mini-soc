"""Alerts become incidents: one open incident per attacker address (or account), a status life cycle, a timeline, playbooks."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import AlertRow, IncidentRow, utc

SEVERITIES = ["low", "medium", "high", "critical"]
STATUSES = ["new", "investigating", "contained", "closed"]
TRANSITIONS = {
    "new": {"investigating", "closed"},
    "investigating": {"contained", "closed"},
    "contained": {"investigating", "closed"},
    "closed": {"investigating"},  # reopen
}
GROUP_WINDOW_S = 1800  # alerts for the same entity within 30 minutes of the last one join the open incident

PLAYBOOKS = {
    "brute_force": ["Confirm the source address is not a known scanner or a user behind NAT",
                    "Block the source address at the firewall", "Check whether any login from it succeeded",
                    "Reset the password of every account that was targeted and succeeded"],
    "password_spraying": ["Block the source address at the firewall", "List every account the source tried",
                          "Check for successful logins on those accounts after the spray",
                          "Enforce MFA on the targeted accounts"],
    "impossible_travel": ["Contact the user and ask whether both logins were theirs",
                          "Revoke the active sessions and tokens of the account", "Reset the password and re-enrol MFA",
                          "Review what the account did after the second login"],
    "web_attack": ["Block the source address at the WAF", "Check the application logs for a 200 on the probed path",
                   "Review the probed endpoint for the vulnerability class", "Patch or add a WAF rule, then close"],
    "privilege_escalation": ["Isolate the host from the network", "Disable the account and kill its sessions",
                             "Review sudoers and administrator group membership against the baseline",
                             "Preserve logs and a memory image before any rebuild"],
    "honeypot_contact": ["Confirm the source is not an internal scanner", "Add the source to the blocklist",
                         "Search the production logs for the same source", "Record the credentials and paths it tried"],
    "anomaly": ["Open the source's recent events and judge whether the behaviour is hostile",
                "If hostile, follow the playbook of the closest rule type", "If benign, note why so the model can be tuned"],
}


def _entry(kind: str, text: str, ts: datetime | None = None) -> dict:
    return {"ts": (ts or datetime.now(timezone.utc)).isoformat(), "kind": kind, "text": text}


def attach(db: Session, alert: AlertRow) -> IncidentRow:
    """Puts the alert into the open incident for its entity, or opens a new one. Caller commits."""
    kind, entity = ("ip", alert.src_ip) if alert.src_ip else ("user", alert.user or "unknown")
    incident = next((i for i in db.scalars(select(IncidentRow).where(IncidentRow.entity == entity,
                     IncidentRow.status != "closed").order_by(IncidentRow.updated_at.desc()).limit(1))
                     if abs((alert.ts - utc(i.updated_at)).total_seconds()) <= GROUP_WINDOW_S), None)
    note = f"[{alert.severity}] {alert.title}: {alert.summary}"
    if incident is None:
        incident = IncidentRow(entity=entity, entity_kind=kind, types=[], severity=alert.severity, status="new",
                               created_at=alert.ts, updated_at=alert.ts, notes="", playbook=[], timeline=[])
        db.add(incident)
        db.flush()
    timeline = [*incident.timeline, _entry("alert", note, alert.ts)]
    if incident.status == "contained":
        incident.status = "investigating"
        timeline.append(_entry("status", "Reopened to investigating: new activity after containment"))
    if alert.incident_type not in incident.types:
        incident.types = [*incident.types, alert.incident_type]
        incident.playbook = [*incident.playbook, *({"type": alert.incident_type, "step": s, "done": False}
                                                   for s in PLAYBOOKS.get(alert.incident_type, []))]
    if SEVERITIES.index(alert.severity) > SEVERITIES.index(incident.severity):
        incident.severity = alert.severity
    incident.timeline = timeline
    incident.updated_at = max(alert.ts, utc(incident.updated_at))
    alert.incident_id = incident.id
    return incident


def change_status(incident: IncidentRow, new: str) -> None:
    if new == incident.status:
        return
    if new not in TRANSITIONS[incident.status]:
        raise ValueError(f"cannot move an incident from {incident.status} to {new}")
    incident.timeline = [*incident.timeline, _entry("status", f"{incident.status} -> {new}")]
    incident.status = new


def set_step(incident: IncidentRow, index: int, done: bool) -> None:
    if not 0 <= index < len(incident.playbook):
        raise IndexError(index)
    step = incident.playbook[index]
    incident.playbook = [{**s, "done": done} if i == index else s for i, s in enumerate(incident.playbook)]
    incident.timeline = [*incident.timeline, _entry("playbook", f"{'Done' if done else 'Reopened'}: {step['step']}")]


def add_note(incident: IncidentRow, notes: str) -> None:
    if notes != incident.notes:
        incident.notes = notes
        incident.timeline = [*incident.timeline, _entry("note", "Analyst notes updated")]
