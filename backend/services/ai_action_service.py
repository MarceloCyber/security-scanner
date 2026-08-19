from datetime import datetime

from sqlalchemy.orm import Session

from models.saas import AIAction, Finding, RemediationTask

ALLOWED_ACTIONS = {"create_remediation_task"}


def propose_action(db: Session, organization_id: int, user_id: int, action_type: str, payload: dict) -> AIAction:
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError("Action type is not allowlisted")
    finding_id = payload.get("finding_id")
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == organization_id).first()
    if not finding:
        raise ValueError("Finding not found in current organization")
    safe_payload = {"finding_id": finding.id, "title": str(payload.get("title") or f"Remediar: {finding.title}")[:255], "description": str(payload.get("description") or finding.remediation or "Investigar e corrigir o finding.")[:10000], "priority": str(payload.get("priority") or finding.severity)[:20]}
    action = AIAction(organization_id=organization_id, user_id=user_id, action_type=action_type, payload=safe_payload, status="proposed", requires_approval=True)
    db.add(action)
    db.flush()
    return action


def execute_action(db: Session, action: AIAction) -> RemediationTask:
    if action.status != "approved" or not action.approved_by:
        raise ValueError("Action must be approved before execution")
    if action.action_type != "create_remediation_task":
        raise ValueError("Action type is not executable")
    payload = action.payload or {}
    finding = db.query(Finding).filter(Finding.id == payload.get("finding_id"), Finding.organization_id == action.organization_id).first()
    if not finding:
        raise ValueError("Finding is no longer available")
    task = RemediationTask(organization_id=action.organization_id, finding_id=finding.id, title=payload["title"], description=payload.get("description"), priority=payload.get("priority", "medium"), status="open")
    db.add(task)
    db.flush()
    action.status = "executed"
    action.executed_at = datetime.utcnow()
    return task
