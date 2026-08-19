from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ai.provider import configured_provider
from config import settings
from database import engine, get_db
from models.saas import Asset, AuditLog, Finding, Integration, Organization, RemediationTask
from middleware.subscription import check_subscription_status, normalize_subscription_plan
from risk.engine import organization_security_score
from services.audit_service import record_audit
from services.ai_action_service import transition_remediation_task
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


class FindingStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|accepted_risk|in_progress|resolved|false_positive)$")
    reason: Optional[str] = Field(default=None, max_length=1000)


class TaskStatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|in_progress|completed|cancelled)$")


class OrganizationUpdate(BaseModel):
    name: str = Field(min_length=2, max_length=160)


def _activity(entry: AuditLog) -> dict:
    return {"id": entry.id, "action": entry.action, "resource_type": entry.resource_type, "resource_id": entry.resource_id, "metadata": entry.metadata_json or {}, "created_at": entry.created_at.isoformat()}


@router.get("/platform/bootstrap")
def platform_bootstrap(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    organization_id = context.organization.id
    plan = normalize_subscription_plan(context.user.subscription_plan)
    subscription_status = (context.user.subscription_status or "pending").strip().lower()
    subscription_active = check_subscription_status(context.user).get("valid", False)
    advanced_tools_access = bool(
        context.user.is_developer
        and plan == "enterprise"
        and subscription_status == "active"
        and subscription_active
    )
    summary = organization_security_score(db, organization_id)
    assets_total = db.query(Asset).filter(Asset.organization_id == organization_id).count()
    integrations_total = db.query(Integration).filter(Integration.organization_id == organization_id, Integration.status == "connected").count()
    tasks = db.query(RemediationTask).filter(RemediationTask.organization_id == organization_id).all()
    activity = db.query(AuditLog).filter(AuditLog.organization_id == organization_id).order_by(AuditLog.created_at.desc()).limit(12).all()
    return {
        "user": {"id": context.user.id, "username": context.user.username, "email": context.user.email, "is_admin": bool(context.user.is_admin), "is_developer": bool(getattr(context.user, "is_developer", False)), "subscription_plan": plan, "subscription_status": subscription_status, "advanced_tools_access": advanced_tools_access},
        "organization": {"id": context.organization.id, "name": context.organization.name, "slug": context.organization.slug, "plan": plan, "role": context.membership.role},
        "onboarding": {"completed": assets_total > 0, "assets_added": assets_total > 0, "integration_connected": integrations_total > 0},
        "security": summary,
        "remediation": {"open": sum(1 for task in tasks if task.status in {"open", "in_progress"}), "completed": sum(1 for task in tasks if task.status == "completed")},
        "activity": [_activity(entry) for entry in activity],
    }


@router.get("/audit")
def audit_timeline(limit: int = 50, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    entries = db.query(AuditLog).filter(AuditLog.organization_id == context.organization.id).order_by(AuditLog.created_at.desc()).limit(min(max(limit, 1), 200)).all()
    return {"activity": [_activity(entry) for entry in entries]}


@router.patch("/findings/{finding_id}/status")
def update_finding_status(finding_id: int, payload: FindingStatusUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == context.organization.id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    previous = finding.status
    finding.status = payload.status
    finding.resolved_at = datetime.utcnow() if payload.status == "resolved" else None
    record_audit(db, context, "finding_status_changed", "finding", finding.id, request, {"from": previous, "to": payload.status, "reason": payload.reason or ""})
    db.commit()
    return {"id": finding.id, "status": finding.status}


@router.get("/remediation-tasks")
def list_remediation_tasks(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    tasks = db.query(RemediationTask).filter(RemediationTask.organization_id == context.organization.id).order_by(RemediationTask.created_at.desc()).limit(200).all()
    return {"tasks": [{"id": task.id, "finding_id": task.finding_id, "title": task.title, "description": task.description, "priority": task.priority, "status": task.status, "due_date": task.due_date.isoformat() if task.due_date else None, "created_at": task.created_at.isoformat()} for task in tasks]}


@router.patch("/remediation-tasks/{task_id}/status")
def update_task_status(task_id: int, payload: TaskStatusUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    task = db.query(RemediationTask).filter(RemediationTask.id == task_id, RemediationTask.organization_id == context.organization.id).first()
    if not task:
        raise HTTPException(status_code=404, detail="Remediation task not found")
    try:
        previous, finding = transition_remediation_task(db, task, payload.status)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    record_audit(db, context, "remediation_status_changed", "remediation_task", task.id, request, {
        "from": previous,
        "to": task.status,
        "finding_id": task.finding_id,
        "finding_status": finding.status if finding else None,
    })
    db.commit()
    return {"id": task.id, "status": task.status, "finding_id": task.finding_id, "finding_status": finding.status if finding else None}


@router.patch("/organization")
def update_organization(payload: OrganizationUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    organization = db.query(Organization).filter(Organization.id == context.organization.id).first()
    organization.name = payload.name.strip()
    record_audit(db, context, "organization_updated", "organization", organization.id, request, {"name": organization.name})
    db.commit()
    return {"id": organization.id, "name": organization.name, "slug": organization.slug}


@router.get("/platform/runtime-status")
def runtime_status(context: TenantContext = Depends(get_tenant_context)):
    provider = configured_provider()
    return {
        "environment": settings.APP_ENV,
        "database": engine.dialect.name,
        "ai": {"connected": provider.name != "local-deterministic", "provider": provider.name},
        "credential_encryption": bool(settings.CREDENTIAL_ENCRYPTION_KEY),
        "background_queue": "redis" if settings.REDIS_URL else "database",
        "tenant_isolation": True,
    }
