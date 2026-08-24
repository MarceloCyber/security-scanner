from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Report
from services.audit_service import record_audit
from services.report_service import generate_report, render_report_pdf
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


@router.post("/reports/{report_type}")
def create_report(report_type: str, request: Request, period_days: int = 30, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    try:
        report = generate_report(db, context.organization.id, context.user.id, report_type, period_days)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    record_audit(db, context, "report_generated", "report", report.id, request, {"type": report_type, "period_days": period_days})
    db.commit()
    db.refresh(report)
    return {"id": report.id, "report_type": report.report_type, "payload": report.payload, "created_at": report.created_at.isoformat()}


@router.get("/reports")
def list_reports(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    reports = db.query(Report).filter(Report.organization_id == context.organization.id).order_by(Report.created_at.desc()).limit(100).all()
    return {"reports": [{"id": report.id, "report_type": report.report_type, "period_days": report.period_days, "status": report.status, "created_at": report.created_at.isoformat()} for report in reports]}


@router.delete("/reports/{report_id}")
def delete_report(report_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.organization_id == context.organization.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    record_audit(db, context, "report_deleted", "report", report.id, request, {"type": report.report_type})
    db.delete(report)
    db.commit()
    return {"deleted": True, "id": report_id}


@router.get("/reports/{report_id}")
def report_detail(report_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.organization_id == context.organization.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": report.id, "report_type": report.report_type, "payload": report.payload, "created_at": report.created_at.isoformat()}


@router.get("/reports/{report_id}/pdf")
def report_pdf(report_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id, Report.organization_id == context.organization.id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return Response(render_report_pdf(report), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=iron-ai-{report.report_type}-{report.id}.pdf"})
