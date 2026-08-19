"""Allowlisted, tenant-scoped read-only tools for Iron AI."""

from typing import Optional
from sqlalchemy.orm import Session

from models.saas import Asset, Finding
from risk.engine import organization_security_score
from services.tenant import TenantContext

READ_ONLY_TOOL_SCHEMAS = [
    {"type": "function", "function": {"name": "get_security_summary", "description": "Consulta o resumo de segurança da organização atual.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
    {"type": "function", "function": {"name": "get_findings", "description": "Lista riscos abertos da organização atual, ordenados por score.", "parameters": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 20}}, "additionalProperties": False}}},
    {"type": "function", "function": {"name": "get_assets", "description": "Lista ativos autorizados da organização atual.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}},
]


def execute_read_only_tool(name: str, arguments: dict, db: Session, context: TenantContext) -> dict:
    if name == "get_security_summary":
        return get_security_summary(db, context)
    if name == "get_findings":
        limit = int(arguments.get("limit", 10)) if isinstance(arguments, dict) else 10
        return {"findings": get_findings(db, context, limit)}
    if name == "get_assets":
        return {"assets": get_assets(db, context)}
    raise ValueError("Ferramenta não permitida")


def get_security_summary(db: Session, context: TenantContext) -> dict:
    return organization_security_score(db, context.organization.id)


def get_assets(db: Session, context: TenantContext) -> list[dict]:
    return [{"id": asset.id, "name": asset.name, "type": asset.type, "environment": asset.environment, "criticality": asset.criticality, "internet_exposed": asset.internet_exposed} for asset in db.query(Asset).filter(Asset.organization_id == context.organization.id).limit(500).all()]


def get_findings(db: Session, context: TenantContext, limit: int = 10) -> list[dict]:
    findings = db.query(Finding).filter(Finding.organization_id == context.organization.id, Finding.status == "open").order_by(Finding.risk_score.desc()).limit(min(max(limit, 1), 50)).all()
    return [{"id": finding.id, "title": finding.title, "severity": finding.severity, "risk_score": finding.risk_score, "asset_id": finding.asset_id, "remediation": finding.remediation} for finding in findings]


def get_finding(db: Session, context: TenantContext, finding_id: int) -> Optional[dict]:
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == context.organization.id).first()
    if not finding:
        return None
    return {"id": finding.id, "title": finding.title, "description": finding.description, "severity": finding.severity, "confidence": finding.confidence, "risk_score": finding.risk_score, "risk_factors": finding.risk_factors or {}, "evidence": finding.evidence, "remediation": finding.remediation, "scanner_source": finding.scanner_source}
