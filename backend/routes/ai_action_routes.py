from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.saas import AIAction
from services.ai_action_service import execute_action, propose_action
from services.audit_service import record_audit
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


class ActionProposal(BaseModel):
    action_type: str = "create_remediation_task"
    finding_id: int
    title: str = Field(default="", max_length=255)
    description: str = Field(default="", max_length=10000)
    priority: str = Field(default="", max_length=20)


def _get_action(db: Session, context: TenantContext, action_id: int) -> AIAction:
    action = db.query(AIAction).filter(AIAction.id == action_id, AIAction.organization_id == context.organization.id).first()
    if not action:
        raise HTTPException(status_code=404, detail="AI action not found")
    return action


@router.post("/ai/actions")
def create_action(payload: ActionProposal, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    try:
        action = propose_action(db, context.organization.id, context.user.id, payload.action_type, payload.model_dump(exclude={"action_type"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_audit(db, context, "ai_action_proposed", "ai_action", action.id, request, {"action_type": action.action_type})
    db.commit()
    return {"id": action.id, "status": action.status, "requires_approval": action.requires_approval, "payload": action.payload}


@router.get("/ai/actions")
def list_actions(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    actions = db.query(AIAction).filter(AIAction.organization_id == context.organization.id).order_by(AIAction.created_at.desc()).limit(100).all()
    return {"actions": [{"id": action.id, "action_type": action.action_type, "status": action.status, "requires_approval": action.requires_approval, "payload": action.payload, "created_at": action.created_at.isoformat()} for action in actions]}


@router.post("/ai/actions/{action_id}/approve")
def approve_action(action_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    action = _get_action(db, context, action_id)
    if action.status != "proposed":
        raise HTTPException(status_code=409, detail="Only proposed actions can be approved")
    action.status = "approved"
    action.approved_by = context.user.id
    record_audit(db, context, "ai_action_approved", "ai_action", action.id, request)
    db.commit()
    return {"id": action.id, "status": action.status}


@router.post("/ai/actions/{action_id}/reject")
def reject_action(action_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    action = _get_action(db, context, action_id)
    if action.status not in {"proposed", "approved"}:
        raise HTTPException(status_code=409, detail="Action cannot be rejected")
    action.status = "rejected"
    record_audit(db, context, "ai_action_rejected", "ai_action", action.id, request)
    db.commit()
    return {"id": action.id, "status": action.status}


@router.post("/ai/actions/{action_id}/execute")
def run_action(action_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    action = _get_action(db, context, action_id)
    try:
        task = execute_action(db, action)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    record_audit(db, context, "ai_action_executed", "ai_action", action.id, request, {"remediation_task_id": task.id})
    db.commit()
    return {"id": action.id, "status": action.status, "remediation_task_id": task.id}
