from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ai.provider import configured_provider
from ai.service import IronAIService
from database import get_db
from services.audit_service import record_audit
from services.tenant import TenantContext, get_tenant_context

router = APIRouter()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    finding_id: Optional[int] = None


def _answer(payload: ChatRequest, request: Request, context: TenantContext, db: Session):
    service = IronAIService(configured_provider())
    result = service.answer(db, context, payload.message, payload.finding_id)
    service.persist_conversation(db, context, payload.message, result)
    record_audit(db, context, "ai_read_only_query", "ai_conversation", None, request, {"finding_id": payload.finding_id})
    db.commit()
    result.setdefault("sources", ["Iron AI normalized findings", "Iron AI deterministic risk engine"])
    return result


@router.post("/ai/chat")
def chat(payload: ChatRequest, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _answer(payload, request, context, db)


@router.get("/ai/security-summary")
def security_summary(request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _answer(ChatRequest(message="Faça um resumo executivo da segurança."), request, context, db)


@router.post("/ai/explain-finding/{finding_id}")
def explain_finding(finding_id: int, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _answer(ChatRequest(message="Explique este finding.", finding_id=finding_id), request, context, db)


@router.post("/ai/remediation-plan")
def remediation_plan(request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _answer(ChatRequest(message="Crie um plano de remediação."), request, context, db)


@router.get("/ai/status")
def ai_status(context: TenantContext = Depends(get_tenant_context)):
    provider = configured_provider()
    return {"connected": provider.name != "local-deterministic", "provider": provider.name, "mode": "grounded_read_only"}
