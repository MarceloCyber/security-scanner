import time
from datetime import datetime, timedelta

from database import SessionLocal
from models.saas import Organization, ScanJob
from services.job_service import enqueue_job
from services.heartbeat_service import beat


def schedule_due_jobs():
    db = SessionLocal()
    queued = 0
    try:
        beat(db, "scheduler")
        since = datetime.utcnow() - timedelta(hours=24)
        organizations = db.query(Organization).filter(Organization.status == "active").all()
        for organization in organizations:
            recent = db.query(ScanJob).filter(ScanJob.organization_id == organization.id, ScanJob.scanner_type == "security_snapshot", ScanJob.created_at >= since, ScanJob.status.in_(["queued", "running", "completed"])).first()
            if not recent:
                enqueue_job(db, organization.id, None, "security_snapshot")
                queued += 1
        db.commit()
        return queued
    finally:
        db.close()


def main():
    while True:
        schedule_due_jobs()
        time.sleep(300)


if __name__ == "__main__":
    main()
