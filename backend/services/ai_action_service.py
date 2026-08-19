from datetime import datetime

from sqlalchemy.orm import Session

from models.saas import AIAction, Finding, RemediationTask

ALLOWED_ACTIONS = {"create_remediation_task"}
TASK_TRANSITIONS = {
    "open": {"in_progress", "cancelled"},
    "in_progress": {"open", "completed", "cancelled"},
    "completed": {"in_progress"},
    "cancelled": {"open"},
}


def propose_action(db: Session, organization_id: int, user_id: int, action_type: str, payload: dict) -> AIAction:
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError("Action type is not allowlisted")
    finding_id = payload.get("finding_id")
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == organization_id).first()
    if not finding:
        raise ValueError("Finding not found in current organization")
    pending_actions = db.query(AIAction).filter(
        AIAction.organization_id == organization_id,
        AIAction.status.in_({"proposed", "approved"}),
    ).all()
    if any((item.payload or {}).get("finding_id") == finding.id for item in pending_actions):
        raise ValueError("Já existe uma ação aguardando decisão para este risco")
    existing_task = db.query(RemediationTask).filter(
        RemediationTask.organization_id == organization_id,
        RemediationTask.finding_id == finding.id,
        RemediationTask.status.in_({"open", "in_progress"}),
    ).first()
    if existing_task:
        raise ValueError(f"Este risco já possui a tarefa de correção #{existing_task.id} em andamento")
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
    existing_task = db.query(RemediationTask).filter(
        RemediationTask.organization_id == action.organization_id,
        RemediationTask.finding_id == finding.id,
        RemediationTask.status.in_({"open", "in_progress"}),
    ).first()
    if existing_task:
        raise ValueError(f"Este risco já possui a tarefa de correção #{existing_task.id} em andamento")
    task = RemediationTask(organization_id=action.organization_id, finding_id=finding.id, title=payload["title"], description=payload.get("description"), priority=payload.get("priority", "medium"), status="open")
    db.add(task)
    db.flush()
    action.status = "executed"
    action.executed_at = datetime.utcnow()
    return task


def transition_remediation_task(db: Session, task: RemediationTask, new_status: str) -> tuple[str, Finding | None]:
    previous = task.status
    if new_status == previous:
        return previous, None
    if new_status not in TASK_TRANSITIONS.get(previous, set()):
        raise ValueError(f"Transição inválida de {previous} para {new_status}")
    task.status = new_status
    task.completed_at = datetime.utcnow() if new_status == "completed" else None
    finding = None
    if task.finding_id:
        finding = db.query(Finding).filter(
            Finding.id == task.finding_id,
            Finding.organization_id == task.organization_id,
        ).first()
        if finding and new_status == "completed":
            finding.status = "resolved"
            finding.resolved_at = datetime.utcnow()
        elif finding and new_status in {"open", "in_progress"} and finding.status == "resolved":
            finding.status = "in_progress"
            finding.resolved_at = None
    return previous, finding
