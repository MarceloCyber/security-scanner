"""Managed security policy lifecycle and acknowledgement evidence."""

import re
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.saas import SecurityPolicy, SecurityPolicyAcknowledgement, SecurityPolicyVersion
from services.audit_service import record_audit
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()
ALLOWED_STATUSES = {"draft", "pending_approval", "published", "archived"}


class PolicyCreate(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    slug: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    content: str = Field(min_length=20, max_length=100000)
    review_interval_days: int = Field(default=365, ge=7, le=1095)


class PolicyUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    review_interval_days: int | None = Field(default=None, ge=7, le=1095)


class VersionCreate(BaseModel):
    content: str = Field(min_length=20, max_length=100000)
    change_summary: str | None = Field(default=None, max_length=500)


class PolicyStatus(BaseModel):
    status: str


def _slug(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:110] or "politica-seguranca"


def _policy(db: Session, context: TenantContext, policy_id: int) -> SecurityPolicy:
    item = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id, SecurityPolicy.organization_id == context.organization.id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Política não encontrada")
    return item


def _version_dict(version: SecurityPolicyVersion) -> dict:
    return {"id": version.id, "policy_id": version.policy_id, "version": version.version, "content": version.content,
            "change_summary": version.change_summary, "created_by": version.created_by, "approved_by": version.approved_by,
            "approved_at": version.approved_at.isoformat() if version.approved_at else None, "created_at": version.created_at.isoformat()}


def _policy_dict(db: Session, item: SecurityPolicy, include_content: bool = False) -> dict:
    version = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.id == item.published_version_id).first() if item.published_version_id else None
    latest = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.policy_id == item.id).order_by(SecurityPolicyVersion.version.desc()).first()
    acknowledgements = db.query(SecurityPolicyAcknowledgement).filter(SecurityPolicyAcknowledgement.policy_id == item.id, SecurityPolicyAcknowledgement.version_id == (version.id if version else -1)).count()
    result = {"id": item.id, "slug": item.slug, "title": item.title, "description": item.description, "status": item.status,
              "owner_user_id": item.owner_user_id, "review_interval_days": item.review_interval_days,
              "next_review_at": item.next_review_at.isoformat() if item.next_review_at else None,
              "published_version": _version_dict(version) if version and include_content else ({"id": version.id, "version": version.version} if version else None),
              "latest_version": latest.version if latest else None, "acknowledgements": acknowledgements,
              "created_at": item.created_at.isoformat(), "updated_at": item.updated_at.isoformat()}
    return result


@router.get("/policies")
def list_policies(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    items = db.query(SecurityPolicy).filter(SecurityPolicy.organization_id == context.organization.id).order_by(SecurityPolicy.updated_at.desc()).all()
    return {"policies": [_policy_dict(db, item) for item in items]}


@router.get("/policies/{policy_id}")
def get_policy(policy_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return _policy_dict(db, _policy(db, context, policy_id), include_content=True)


@router.post("/policies")
def create_policy(payload: PolicyCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    slug = _slug(payload.slug or payload.title)
    if db.query(SecurityPolicy).filter(SecurityPolicy.organization_id == context.organization.id, SecurityPolicy.slug == slug).first():
        raise HTTPException(status_code=409, detail="Já existe uma política com esse identificador")
    item = SecurityPolicy(organization_id=context.organization.id, slug=slug, title=payload.title.strip(), description=payload.description,
                          owner_user_id=context.user.id, created_by=context.user.id, review_interval_days=payload.review_interval_days)
    db.add(item)
    db.flush()
    version = SecurityPolicyVersion(organization_id=context.organization.id, policy_id=item.id, version=1, content=payload.content.strip(), created_by=context.user.id)
    db.add(version)
    db.flush()
    record_audit(db, context, "security_policy_created", "security_policy", item.id, request, {"title": item.title})
    db.commit()
    return _policy_dict(db, item, include_content=True)


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: int, payload: PolicyUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    item = _policy(db, context, policy_id)
    if item.status == "archived":
        raise HTTPException(status_code=409, detail="Política arquivada não pode ser editada")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(item, key, value.strip() if isinstance(value, str) else value)
    record_audit(db, context, "security_policy_updated", "security_policy", item.id, request, {})
    db.commit()
    return _policy_dict(db, item)


@router.post("/policies/{policy_id}/versions")
def create_version(policy_id: int, payload: VersionCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    item = _policy(db, context, policy_id)
    if item.status == "archived":
        raise HTTPException(status_code=409, detail="Política arquivada não pode receber novas versões")
    latest = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.policy_id == item.id).order_by(SecurityPolicyVersion.version.desc()).first()
    version = SecurityPolicyVersion(organization_id=context.organization.id, policy_id=item.id, version=(latest.version + 1 if latest else 1), content=payload.content.strip(), change_summary=payload.change_summary, created_by=context.user.id)
    item.status = "draft"
    db.add(version)
    db.flush()
    record_audit(db, context, "security_policy_version_created", "security_policy_version", version.id, request, {"policy_id": item.id, "version": version.version})
    db.commit()
    return _version_dict(version)


@router.get("/policies/{policy_id}/versions")
def list_versions(policy_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    item = _policy(db, context, policy_id)
    versions = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.policy_id == item.id).order_by(SecurityPolicyVersion.version.desc()).all()
    return {"versions": [_version_dict(version) for version in versions]}


@router.post("/policies/{policy_id}/status")
def change_status(policy_id: int, payload: PolicyStatus, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    item = _policy(db, context, policy_id)
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(status_code=422, detail="Status de política inválido")
    latest = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.policy_id == item.id).order_by(SecurityPolicyVersion.version.desc()).first()
    if payload.status == "pending_approval" and not latest:
        raise HTTPException(status_code=409, detail="A política precisa ter uma versão antes da aprovação")
    if payload.status == "published":
        if not latest:
            raise HTTPException(status_code=409, detail="A política precisa ter uma versão antes da publicação")
        latest.approved_by = context.user.id
        latest.approved_at = datetime.utcnow()
        item.published_version_id = latest.id
        item.next_review_at = datetime.utcnow() + timedelta(days=item.review_interval_days)
    item.status = payload.status
    record_audit(db, context, "security_policy_status_changed", "security_policy", item.id, request, {"status": item.status, "version": latest.version if latest else None})
    db.commit()
    return _policy_dict(db, item, include_content=True)


@router.post("/policies/{policy_id}/acknowledge")
def acknowledge_policy(policy_id: int, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    item = _policy(db, context, policy_id)
    if item.status != "published" or not item.published_version_id:
        raise HTTPException(status_code=409, detail="A política ainda não está publicada")
    acknowledgement = db.query(SecurityPolicyAcknowledgement).filter(SecurityPolicyAcknowledgement.version_id == item.published_version_id, SecurityPolicyAcknowledgement.user_id == context.user.id).first()
    if not acknowledgement:
        acknowledgement = SecurityPolicyAcknowledgement(organization_id=context.organization.id, policy_id=item.id, version_id=item.published_version_id, user_id=context.user.id)
        db.add(acknowledgement)
    record_audit(db, context, "security_policy_acknowledged", "security_policy", item.id, request, {"version_id": item.published_version_id})
    db.commit()
    return {"acknowledged": True, "policy_id": item.id, "version_id": item.published_version_id, "acknowledged_at": acknowledgement.acknowledged_at.isoformat()}
