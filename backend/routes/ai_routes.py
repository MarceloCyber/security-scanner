from typing import Optional

import json
from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ai.provider import configured_provider, provider_candidates
from ai.service import IronAIService
from database import get_db
from services.audit_service import record_audit
from services.tenant import TenantContext, get_tenant_context

router = APIRouter()


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    finding_id: Optional[int] = None
    conversation_id: Optional[int] = None
    history: Optional[list[dict]] = None


def _answer(payload: ChatRequest, request: Request, context: TenantContext, db: Session):
    service = IronAIService(providers=provider_candidates())
    result = service.answer(db, context, payload.message, payload.finding_id, payload.history, payload.conversation_id)
    conversation = service.persist_conversation(db, context, payload.message, result, payload.conversation_id)
    record_audit(db, context, "ai_read_only_query", "ai_conversation", None, request, {"finding_id": payload.finding_id})
    db.commit()
    result.setdefault("sources", ["Iron AI normalized findings", "Iron AI deterministic risk engine"])
    result["conversation_id"] = conversation.id
    return result


@router.post("/ai/chat")
def chat(payload: ChatRequest, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _answer(payload, request, context, db)


@router.post("/ai/chat/stream")
def chat_stream(payload: ChatRequest, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    service = IronAIService(providers=provider_candidates())
    chunks, metadata = service.stream(db, context, payload.message, payload.history, payload.conversation_id, payload.finding_id)

    def events():
        collected = []
        for chunk in chunks:
            collected.append(chunk)
            yield "data: " + json.dumps({"delta": chunk}, ensure_ascii=False) + "\n\n"
        result = {"summary": "".join(collected), "provider": metadata.get("provider"), "model": metadata.get("model"), "task": metadata.get("task"), "reasoning_effort": metadata.get("reasoning_effort"), "tools_used": []}
        conversation = service.persist_conversation(db, context, payload.message, result, payload.conversation_id)
        record_audit(db, context, "ai_stream_query", "ai_conversation", conversation.id, request, {})
        db.commit()
        result["conversation_id"] = conversation.id
        yield "data: " + json.dumps({"done": True, "result": result}, ensure_ascii=False) + "\n\n"
        yield "data: [DONE]\n\n"

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


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
    providers = provider_candidates()
    return {"connected": provider.name != "local-deterministic", "provider": provider.name, "available_providers": [item.name for item in providers], "mode": "copilot_grounded", "fallback_enabled": len(providers) > 1}
