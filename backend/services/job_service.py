"""Durable database queue used by dedicated worker processes."""

from datetime import datetime
from typing import Optional

from sqlalchemy.orm import Session

from models.saas import ScanJob

ALLOWED_JOB_TYPES = {"web_security_scan", "authenticated_web_scan", "security_snapshot", "executive_report", "technical_report"}


def enqueue_job(db: Session, organization_id: int, user_id: int, job_type: str, asset_id: Optional[int] = None) -> ScanJob:
    if job_type not in ALLOWED_JOB_TYPES:
        raise ValueError("Unsupported job type")
    job = ScanJob(organization_id=organization_id, asset_id=asset_id, scanner_type=job_type, status="queued", progress=0, created_by=user_id)
    db.add(job)
    db.flush()
    return job


def claim_next_job(db: Session) -> Optional[ScanJob]:
    query = db.query(ScanJob).filter(ScanJob.status == "queued").order_by(ScanJob.created_at.asc())
    if db.bind.dialect.name == "postgresql":
        query = query.with_for_update(skip_locked=True)
    job = query.first()
    if not job:
        return None
    job.status = "running"
    job.progress = 5
    job.started_at = datetime.utcnow()
    db.commit()
    db.refresh(job)
    return job
