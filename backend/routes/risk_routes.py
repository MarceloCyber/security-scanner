import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, Finding, SecuritySnapshot
from models.scan import Scan
from schemas.saas import AssetResponse
from services.audit_service import record_audit
from services.finding_service import persist_scan_findings
from services.tenant import TenantContext, get_tenant_context, require_roles
from risk.engine import create_snapshot, organization_security_score

router = APIRouter()


def _finding(finding: Finding) -> dict:
    return {"id": finding.id, "title": finding.title, "description": finding.description, "severity": finding.severity, "confidence": finding.confidence, "status": finding.status, "risk_score": finding.risk_score, "risk_factors": finding.risk_factors or {}, "asset_id": finding.asset_id, "cve": finding.cve, "cwe": finding.cwe, "cvss_score": finding.cvss_score, "evidence": finding.evidence, "remediation": finding.remediation, "scanner_source": finding.scanner_source, "first_seen_at": finding.first_seen_at.isoformat(), "last_seen_at": finding.last_seen_at.isoformat()}


@router.get("/security/overview")
def security_overview(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    summary = organization_security_score(db, context.organization.id)
    top = db.query(Finding).filter(Finding.organization_id == context.organization.id, Finding.status == "open").order_by(Finding.risk_score.desc(), Finding.last_seen_at.desc()).limit(5).all()
    open_tasks = 0
    return {"security_score": summary["score"], "findings": summary["findings"], "assets": {"total": summary["assets_total"], "internet_exposed": summary["assets_exposed"]}, "remediation": {"open": open_tasks, "overdue": 0}, "top_risks": [_finding(finding) for finding in top]}


@router.get("/security/trend")
def security_trend(days: int = 30, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    days = min(max(days, 7), 365)
    snapshots = db.query(SecuritySnapshot).filter(SecuritySnapshot.organization_id == context.organization.id).order_by(SecuritySnapshot.created_at.desc()).limit(365).all()
    return {"days": days, "snapshots": [{"score": snapshot.score, "critical_findings": snapshot.critical_findings, "high_findings": snapshot.high_findings, "assets_exposed": snapshot.assets_exposed, "created_at": snapshot.created_at.isoformat()} for snapshot in reversed(snapshots)]}


@router.post("/security/snapshot")
def take_snapshot(context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    snapshot = create_snapshot(db, context.organization.id)
    db.commit()
    return {"id": snapshot.id, "score": snapshot.score, "created_at": snapshot.created_at.isoformat()}


@router.get("/findings")
def list_findings(severity: Optional[str] = None, status: str = "open", context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    query = db.query(Finding).filter(Finding.organization_id == context.organization.id)
    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if status:
        query = query.filter(Finding.status == status)
    findings = query.order_by(Finding.risk_score.desc(), Finding.last_seen_at.desc()).limit(500).all()
    return {"total": len(findings), "findings": [_finding(finding) for finding in findings]}


@router.get("/findings/{finding_id}")
def finding_detail(finding_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.organization_id == context.organization.id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding(finding)


@router.post("/findings/reconcile")
def reconcile_legacy_scans(request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    scans = db.query(Scan).filter(Scan.user_id == context.user.id, Scan.results.isnot(None)).all()
    total = 0
    for scan in scans:
        try:
            results = json.loads(scan.results)
        except (TypeError, ValueError):
            continue
        total += len(persist_scan_findings(db, context.user, results, scan.scan_type or "legacy", scan.target or "unknown"))
    record_audit(db, context, "findings_reconciled", "finding", None, request, {"scans": len(scans), "findings": total})
    db.commit()
    return {"scans_processed": len(scans), "findings_upserted": total}
