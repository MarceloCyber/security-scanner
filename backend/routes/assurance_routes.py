from datetime import datetime
import hashlib
import json

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, AuditExport, AuditLog, Finding, Integration, ScanJob
from services.audit_service import record_audit
from services.compliance_service import compliance_summary
from services.heartbeat_service import process_status
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


@router.get("/operations/status")
def operations_status(context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    processes = process_status(db)
    queued = db.query(ScanJob).filter(ScanJob.organization_id == context.organization.id, ScanJob.status == "queued").count()
    return {"status": "healthy" if all(item["healthy"] for item in processes.values()) else "degraded", "processes": processes, "queued_jobs": queued, "note": "Disponibilidade 24x7 também exige redundância, alertas e SLA no provedor de infraestrutura."}


@router.post("/audit/export")
def export_audit(request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    organization_id = context.organization.id
    logs = db.query(AuditLog).filter(AuditLog.organization_id == organization_id).order_by(AuditLog.created_at.asc()).all()
    findings = db.query(Finding).filter(Finding.organization_id == organization_id).all()
    bundle = {
        "schema": "iron-ai-assurance/v1",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "organization": {"id": context.organization.id, "name": context.organization.name, "slug": context.organization.slug},
        "inventory": {"assets": db.query(Asset).filter(Asset.organization_id == organization_id).count(), "integrations": db.query(Integration).filter(Integration.organization_id == organization_id, Integration.status == "connected").count()},
        "findings": {"total": len(findings), "open": sum(item.status in {"open", "in_progress"} for item in findings), "critical": sum(item.status in {"open", "in_progress"} and item.severity == "critical" for item in findings)},
        "compliance": compliance_summary(db, organization_id),
        "audit_log": [{"id": item.id, "user_id": item.user_id, "action": item.action, "resource_type": item.resource_type, "resource_id": item.resource_id, "metadata": item.metadata_json or {}, "created_at": item.created_at.isoformat()} for item in logs],
    }
    canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(canonical).hexdigest()
    bundle["manifest"] = {"algorithm": "SHA-256", "digest": digest, "canonical_scope": "document without manifest"}
    export = AuditExport(organization_id=organization_id, created_by=context.user.id, sha256=digest, record_count=len(logs))
    db.add(export)
    db.flush()
    record_audit(db, context, "audit_evidence_exported", "audit_export", export.id, request, {"sha256": digest, "records": len(logs)})
    db.commit()
    body = json.dumps(bundle, ensure_ascii=False, indent=2, default=str).encode()
    return Response(content=body, media_type="application/json", headers={"Content-Disposition": f'attachment; filename="iron-ai-audit-{export.id}.json"', "X-Iron-AI-SHA256": digest})
