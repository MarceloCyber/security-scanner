from typing import Optional
from sqlalchemy.orm import Session

from ai.guardrails import safe_response
from ai.provider import AIProvider, LocalProvider
from ai.tool_registry import get_finding, get_findings, get_security_summary
from models.saas import AIConversation, AIMessage
from services.tenant import TenantContext


class IronAIService:
    def __init__(self, provider: Optional[AIProvider] = None):
        self.provider = provider or LocalProvider()

    def answer(self, db: Session, context: TenantContext, message: str, finding_id: Optional[int] = None) -> dict:
        if finding_id is not None:
            finding = get_finding(db, context, finding_id)
            if not finding:
                return {"summary": "Não há dados suficientes na Iron AI para confirmar isso.", "facts": [], "recommendations": [], "sources": []}
            provider_context = {"findings": [finding]}
            try:
                result = self.provider.structured_output(intent="finding", context=provider_context, message=message)
            except Exception:
                result = LocalProvider().structured_output(intent="finding", context=provider_context, message=message)
                result["provider_error"] = True
        else:
            summary = get_security_summary(db, context)
            findings = get_findings(db, context)
            intent = "remediation" if any(word in (message or "").lower() for word in ("corrigir", "plano", "remediação", "remediacao")) else "summary"
            provider_context = {**summary, "findings": findings}
            try:
                result = self.provider.structured_output(intent=intent, context=provider_context, message=message)
            except Exception:
                result = LocalProvider().structured_output(intent=intent, context=provider_context, message=message)
                result["provider_error"] = True
        result["summary"] = safe_response(result.get("summary", ""))
        result["provider"] = "local-deterministic" if result.get("provider_error") else self.provider.name
        return result

    def persist_conversation(self, db: Session, context: TenantContext, message: str, response: dict) -> AIConversation:
        conversation = AIConversation(organization_id=context.organization.id, user_id=context.user.id, title="Iron AI")
        db.add(conversation)
        db.flush()
        db.add(AIMessage(conversation_id=conversation.id, role="user", content=safe_response(message)))
        db.add(AIMessage(conversation_id=conversation.id, role="assistant", content=safe_response(response.get("summary", "")), tool_calls={"read_only": True}))
        return conversation
