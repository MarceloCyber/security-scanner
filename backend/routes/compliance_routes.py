from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from services.audit_service import record_audit
from services.compliance_service import attest_control, compliance_summary
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


class ControlUpdate(BaseModel):
    status: Literal["not_started", "in_progress", "implemented"]
    evidence: Optional[str] = Field(default=None, max_length=4000)


@router.get("/compliance")
def get_compliance(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return compliance_summary(db, context.organization.id)


@router.patch("/compliance/{control_key}")
def update_compliance(control_key: str, payload: ControlUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    try:
        item = attest_control(db, context.organization.id, context.user.id, control_key, payload.status, payload.evidence)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record_audit(db, context, "compliance_control_updated", "compliance_control", control_key, request, {"status": payload.status})
    db.commit()
    return {"key": item.control_key, "status": item.status, "reviewed_at": item.reviewed_at.isoformat()}
