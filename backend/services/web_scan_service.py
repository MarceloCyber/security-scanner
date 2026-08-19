"""Execute and persist an authorized production-safe web scan."""

from datetime import datetime

from database import SessionLocal
from models.saas import Asset, AuthenticatedScanProfile, Finding, ScanJob
from models.user import User
from risk.engine import create_snapshot, refresh_finding_scores
from scanners.web_security_scanner import WebSecurityScanner
from services.finding_service import persist_scan_findings
from services.credential_vault import CredentialVault


def execute_web_scan(db, job: ScanJob) -> None:
    asset = db.query(Asset).filter(Asset.id == job.asset_id, Asset.organization_id == job.organization_id).first()
    user = db.query(User).filter(User.id == job.created_by).first()
    if not asset or not user:
        raise ValueError("Asset or requesting user no longer exists")
    target = asset.url or asset.hostname or asset.name
    auth_headers = None
    source = "web_security_scanner"
    profile = None
    if job.scanner_type == "authenticated_web_scan":
        profile = db.query(AuthenticatedScanProfile).filter(AuthenticatedScanProfile.organization_id == job.organization_id, AuthenticatedScanProfile.asset_id == asset.id).first()
        if not profile:
            raise ValueError("Authenticated scan profile is unavailable")
        secret = CredentialVault().decrypt(profile.encrypted_value)
        if profile.auth_type == "bearer":
            auth_headers = {"Authorization": f"Bearer {secret}"}
        elif profile.auth_type == "cookie":
            auth_headers = {"Cookie": secret}
        elif profile.auth_type == "api_key" and profile.header_name:
            auth_headers = {profile.header_name: secret}
        else:
            raise ValueError("Authenticated scan profile is invalid")
        source = "authenticated_web_scanner"
        profile.last_used_at = datetime.utcnow()
    result = WebSecurityScanner(target, auth_headers=auth_headers).scan()
    job.progress = 70
    db.flush()
    persisted = persist_scan_findings(db, user, result, source, asset.name, job.id)
    current_ids = {finding.id for finding in persisted if finding.id}
    previous = db.query(Finding).filter(
        Finding.organization_id == job.organization_id,
        Finding.asset_id == asset.id,
        Finding.scanner_source == source,
        Finding.status.in_(["open", "in_progress"]),
    ).all()
    for finding in previous:
        if finding.id not in current_ids:
            finding.status = "resolved"
            finding.resolved_at = datetime.utcnow()

    metadata = dict(asset.metadata_json or {})
    metadata.update({
        "last_scan": result["scanned_at"],
        "last_scan_status": result["http"]["status"],
        "last_response_ms": result["http"]["response_time_ms"],
        "ip_addresses": result["network"]["ip_addresses"],
        "tls": result.get("tls"),
        "technologies": result.get("technologies", []),
        "scan_mode": result["scan_mode"],
    })
    asset.metadata_json = metadata
    asset.url = result["final_url"]
    asset.hostname = result["network"]["hostname"]
    asset.ip_address = (result["network"]["ip_addresses"] or [None])[0]
    asset.last_seen_at = datetime.utcnow()
    refresh_finding_scores(db, job.organization_id)
    snapshot = create_snapshot(db, job.organization_id)
    job.result_json = {
        "target": result["target"],
        "final_url": result["final_url"],
        "http_status": result["http"]["status"],
        "response_time_ms": result["http"]["response_time_ms"],
        "findings_total": len(persisted),
        "ip_addresses": result["network"]["ip_addresses"],
        "tls": result.get("tls"),
        "snapshot_score": snapshot.score,
        "scan_mode": result["scan_mode"],
    }


def run_web_scan_job(job_id: int) -> None:
    db = SessionLocal()
    try:
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        if not job or job.status not in {"queued", "running"}:
            return
        job.status = "running"
        job.progress = 10
        job.started_at = job.started_at or datetime.utcnow()
        db.commit()
        try:
            execute_web_scan(db, job)
            job.status = "completed"
            job.progress = 100
        except Exception as exc:
            job.status = "failed"
            job.error = str(exc)[:2000]
        job.completed_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
