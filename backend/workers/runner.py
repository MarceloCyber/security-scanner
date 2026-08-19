import argparse
import time
from datetime import datetime

from database import SessionLocal
from models.saas import ScanJob
from risk.engine import create_snapshot
from services.job_service import claim_next_job
from services.report_service import generate_report
from services.web_scan_service import execute_web_scan
from services.heartbeat_service import beat


def process_one() -> bool:
    db = SessionLocal()
    try:
        beat(db, "worker")
        db.commit()
        job = claim_next_job(db)
        if not job:
            return False
        try:
            if job.scanner_type in {"web_security_scan", "authenticated_web_scan"}:
                execute_web_scan(db, job)
            elif job.scanner_type == "security_snapshot":
                create_snapshot(db, job.organization_id)
            elif job.scanner_type in {"executive_report", "technical_report"}:
                generate_report(db, job.organization_id, job.created_by, job.scanner_type.replace("_report", ""), 30)
            else:
                raise ValueError("Unsupported queued job")
            job.status = "completed"
            job.progress = 100
            job.completed_at = datetime.utcnow()
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)[:2000]
            job.completed_at = datetime.utcnow()
        db.commit()
        return True
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    while True:
        worked = process_one()
        if args.once:
            break
        if not worked:
            time.sleep(2)


if __name__ == "__main__":
    main()
