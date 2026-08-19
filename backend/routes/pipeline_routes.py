"""CI/CD ingestion and Security Gate APIs for Iron AI."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import secrets
from typing import Any, Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, AuditLog, Organization, PipelineApiKey
from services.audit_service import record_audit
from services.pipeline_service import consolidate_findings, evaluate_gate, normalize_findings, normalize_sarif
from services.tenant import TenantContext, require_roles

router = APIRouter()


class PipelineKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    expires_in_days: Optional[int] = Field(default=365, ge=1, le=730)


class FindingInput(BaseModel):
    title: str = Field(min_length=1, max_length=255)
    severity: str = "medium"
    description: Optional[str] = None
    category: Optional[str] = None
    confidence: Optional[str] = "medium"
    cve: Optional[str] = None
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    location: Optional[str] = None
    fingerprint: Optional[str] = None
    external_id: Optional[str] = None


class PipelineIngest(BaseModel):
    asset_id: int
    source: str = Field(min_length=2, max_length=80)
    scan_reference: Optional[str] = Field(default=None, max_length=160)
    format: Literal["normalized", "sarif"] = "normalized"
    findings: list[FindingInput] = Field(default_factory=list, max_length=1000)
    sarif: Optional[dict[str, Any]] = None
    complete_scan: bool = True
    gate_fail_on: Literal["critical", "high", "medium", "low"] = "high"
    gate_max_allowed: int = Field(default=0, ge=0, le=1000)


class GateRequest(BaseModel):
    asset_id: Optional[int] = None
    fail_on: Literal["critical", "high", "medium", "low"] = "high"
    max_allowed: int = Field(default=0, ge=0, le=1000)


@dataclass(frozen=True)
class PipelineContext:
    organization: Organization
    api_key: PipelineApiKey


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def get_pipeline_context(
    raw_key: str = Header(default="", alias="X-Iron-AI-Key"),
    db: Session = Depends(get_db),
) -> PipelineContext:
    if not raw_key.startswith("iai_") or len(raw_key) < 35:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chave de pipeline inválida")
    api_key = db.query(PipelineApiKey).filter(PipelineApiKey.key_hash == _hash_key(raw_key), PipelineApiKey.revoked_at.is_(None)).first()
    now = datetime.utcnow()
    if not api_key or (api_key.expires_at and api_key.expires_at <= now):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chave de pipeline inválida ou expirada")
    organization = db.query(Organization).filter(Organization.id == api_key.organization_id, Organization.status == "active").first()
    if not organization:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organização indisponível")
    api_key.last_used_at = now
    db.flush()
    return PipelineContext(organization=organization, api_key=api_key)


@router.post("/pipeline-keys")
def create_pipeline_key(payload: PipelineKeyCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    from datetime import timedelta
    raw_key = "iai_" + secrets.token_urlsafe(36)
    expires_at = datetime.utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None
    api_key = PipelineApiKey(
        organization_id=context.organization.id,
        name=payload.name.strip(),
        key_prefix=raw_key[:16],
        key_hash=_hash_key(raw_key),
        scopes=["findings:write", "gates:read"],
        created_by=context.user.id,
        expires_at=expires_at,
    )
    db.add(api_key)
    db.flush()
    record_audit(db, context, "pipeline_key_created", "pipeline_api_key", api_key.id, request, {"name": api_key.name})
    db.commit()
    return {"id": api_key.id, "name": api_key.name, "key": raw_key, "key_prefix": api_key.key_prefix, "expires_at": expires_at.isoformat() if expires_at else None, "warning": "Copie agora. A chave não será exibida novamente."}


@router.get("/pipeline-keys")
def list_pipeline_keys(context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    keys = db.query(PipelineApiKey).filter(PipelineApiKey.organization_id == context.organization.id).order_by(PipelineApiKey.created_at.desc()).all()
    return {"keys": [{"id": key.id, "name": key.name, "key_prefix": key.key_prefix, "scopes": key.scopes, "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None, "expires_at": key.expires_at.isoformat() if key.expires_at else None, "revoked_at": key.revoked_at.isoformat() if key.revoked_at else None, "created_at": key.created_at.isoformat()} for key in keys]}


@router.delete("/pipeline-keys/{key_id}")
def revoke_pipeline_key(key_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    api_key = db.query(PipelineApiKey).filter(PipelineApiKey.id == key_id, PipelineApiKey.organization_id == context.organization.id).first()
    if not api_key:
        raise HTTPException(status_code=404, detail="Chave não encontrada")
    api_key.revoked_at = api_key.revoked_at or datetime.utcnow()
    record_audit(db, context, "pipeline_key_revoked", "pipeline_api_key", api_key.id, request)
    db.commit()
    return {"revoked": True}


@router.post("/pipeline/ingest")
def ingest_pipeline(payload: PipelineIngest, request: Request, context: PipelineContext = Depends(get_pipeline_context), db: Session = Depends(get_db)):
    if "findings:write" not in (context.api_key.scopes or []):
        raise HTTPException(status_code=403, detail="Escopo findings:write ausente")
    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    if payload.format == "sarif":
        if not payload.sarif:
            raise HTTPException(status_code=400, detail="Documento SARIF ausente")
        items = normalize_sarif(payload.sarif)
        for item in items:
            item["scanner_source"] = payload.source
    else:
        items = normalize_findings([item.model_dump() for item in payload.findings], payload.source)
    summary = consolidate_findings(db, context.organization.id, asset.id, payload.source, items, payload.complete_scan)
    gate = evaluate_gate(db, context.organization.id, asset.id, payload.gate_fail_on, payload.gate_max_allowed)
    db.add(AuditLog(
        organization_id=context.organization.id,
        action="pipeline_findings_ingested",
        resource_type="asset",
        resource_id=str(asset.id),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:512],
        metadata_json={"source": payload.source, "scan_reference": payload.scan_reference, "received": len(items), "gate_passed": gate["passed"]},
    ))
    db.commit()
    return {"ingestion": summary, "quality_gate": gate}


@router.post("/pipeline/gate")
def pipeline_gate(payload: GateRequest, context: PipelineContext = Depends(get_pipeline_context), db: Session = Depends(get_db)):
    if "gates:read" not in (context.api_key.scopes or []):
        raise HTTPException(status_code=403, detail="Escopo gates:read ausente")
    if payload.asset_id is not None:
        asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first()
        if not asset:
            raise HTTPException(status_code=404, detail="Ativo não encontrado")
    result = evaluate_gate(db, context.organization.id, payload.asset_id, payload.fail_on, payload.max_allowed)
    db.commit()
    return result
