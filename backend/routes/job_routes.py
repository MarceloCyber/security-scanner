from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, AuthenticatedScanProfile, ScanJob
from services.audit_service import record_audit
from services.job_service import enqueue_job
from services.tenant import TenantContext, get_tenant_context, require_roles
from services.web_scan_service import run_web_scan_job
from services.credential_vault import CredentialVault
from auth import require_enterprise

router = APIRouter()


class JobCreate(BaseModel):
    job_type: str
    asset_id: Optional[int] = None


class ScanProfileCreate(BaseModel):
    asset_id: int
    auth_type: str = Field(pattern=r"^(bearer|api_key|cookie)$")
    header_name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    secret: str = Field(min_length=8, max_length=8000)


@router.get("/scan-profiles")
def list_scan_profiles(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    profiles = db.query(AuthenticatedScanProfile).filter(AuthenticatedScanProfile.organization_id == context.organization.id).all()
    return {"profiles": [{"id": item.id, "asset_id": item.asset_id, "auth_type": item.auth_type, "header_name": item.header_name, "secret_hint": item.secret_hint, "last_used_at": item.last_used_at.isoformat() if item.last_used_at else None} for item in profiles]}


@router.post("/scan-profiles")
def save_scan_profile(payload: ScanProfileCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    require_enterprise(context.user)
    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    if payload.auth_type == "api_key" and not payload.header_name:
        raise HTTPException(status_code=400, detail="header_name is required for API key authentication")
    forbidden_headers = {"host", "content-length", "connection", "transfer-encoding", "proxy-authorization"}
    if payload.header_name and payload.header_name.lower() in forbidden_headers:
        raise HTTPException(status_code=400, detail="Este header não pode ser configurado")
    try:
        encrypted = CredentialVault().encrypt(payload.secret)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    profile = db.query(AuthenticatedScanProfile).filter(AuthenticatedScanProfile.organization_id == context.organization.id, AuthenticatedScanProfile.asset_id == asset.id).first()
    if not profile:
        profile = AuthenticatedScanProfile(organization_id=context.organization.id, asset_id=asset.id, created_by=context.user.id)
        db.add(profile)
    profile.auth_type = payload.auth_type
    profile.header_name = payload.header_name if payload.auth_type == "api_key" else None
    profile.encrypted_value = encrypted
    profile.secret_hint = payload.secret[-4:]
    record_audit(db, context, "authenticated_scan_profile_saved", "asset", asset.id, request, {"auth_type": payload.auth_type, "header_name": profile.header_name})
    db.commit()
    return {"asset_id": asset.id, "auth_type": profile.auth_type, "secret_hint": profile.secret_hint}


@router.delete("/scan-profiles/{asset_id}")
def delete_scan_profile(asset_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    profile = db.query(AuthenticatedScanProfile).filter(AuthenticatedScanProfile.organization_id == context.organization.id, AuthenticatedScanProfile.asset_id == asset_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    db.delete(profile)
    record_audit(db, context, "authenticated_scan_profile_deleted", "asset", asset_id, request)
    db.commit()
    return {"deleted": True}


@router.post("/scan-jobs")
def create_job(payload: JobCreate, request: Request, background_tasks: BackgroundTasks, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    if payload.job_type in {"web_security_scan", "authenticated_web_scan"} and payload.asset_id is None:
        raise HTTPException(status_code=400, detail="asset_id is required for a web scan")
    if payload.job_type == "authenticated_web_scan":
        require_enterprise(context.user)
        profile = db.query(AuthenticatedScanProfile).filter(AuthenticatedScanProfile.organization_id == context.organization.id, AuthenticatedScanProfile.asset_id == payload.asset_id).first()
        if not profile:
            raise HTTPException(status_code=409, detail="Configure o perfil autenticado deste ativo primeiro")
    try:
        if payload.asset_id is not None:
            asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first()
            if not asset:
                raise HTTPException(status_code=404, detail="Asset not found")
        job = enqueue_job(db, context.organization.id, context.user.id, payload.job_type, payload.asset_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_audit(db, context, "job_queued", "scan_job", job.id, request, {"job_type": payload.job_type})
    db.commit()
    if payload.job_type in {"web_security_scan", "authenticated_web_scan"}:
        background_tasks.add_task(run_web_scan_job, job.id)
    return {"id": job.id, "status": job.status, "job_type": job.scanner_type}


@router.get("/scan-jobs")
def list_jobs(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).filter(ScanJob.organization_id == context.organization.id).order_by(ScanJob.created_at.desc()).limit(100).all()
    return {"jobs": [{"id": job.id, "asset_id": job.asset_id, "job_type": job.scanner_type, "status": job.status, "progress": job.progress, "error": job.error, "result": job.result_json, "created_at": job.created_at.isoformat(), "started_at": job.started_at.isoformat() if job.started_at else None, "completed_at": job.completed_at.isoformat() if job.completed_at else None} for job in jobs]}
