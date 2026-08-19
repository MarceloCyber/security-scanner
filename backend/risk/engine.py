"""Transparent, deterministic risk and organization score calculations."""

from datetime import datetime
from typing import Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from models.saas import Asset, Finding, SecuritySnapshot

SEVERITY_BASE = {"informational": 5, "low": 20, "medium": 40, "high": 65, "critical": 82}
CRITICALITY_FACTOR = {"low": 0, "medium": 5, "high": 10, "critical": 15}
CONFIDENCE_FACTOR = {"low": 0, "medium": 4, "high": 8, "confirmed": 12}


def calculate_finding_risk(finding: Finding, asset: Optional[Asset] = None) -> tuple[int, dict]:
    severity = SEVERITY_BASE.get((finding.severity or "medium").lower(), 40)
    exposure = 12 if asset and asset.internet_exposed else 0
    criticality = CRITICALITY_FACTOR.get((asset.criticality if asset else "medium").lower(), 5)
    confidence = CONFIDENCE_FACTOR.get((finding.confidence or "medium").lower(), 4)
    exploitability = 8 if finding.cve else 0
    age_days = max(0, (datetime.utcnow() - (finding.first_seen_at or datetime.utcnow())).days)
    age = min(8, age_days // 30)
    recurrence = min(5, max(0, (finding.occurrence_count or 1) - 1))
    factors = {"severity": severity, "internet_exposure": exposure, "asset_criticality": criticality, "confidence": confidence, "exploitability": exploitability, "age": age, "recurrence": recurrence}
    score = min(100, max(0, sum(factors.values())))
    return score, factors


def refresh_finding_scores(db: Session, organization_id: int) -> None:
    findings = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.status.notin_(["false_positive"])).all()
    assets = {asset.id: asset for asset in db.query(Asset).filter(Asset.organization_id == organization_id).all()}
    for finding in findings:
        finding.risk_score, finding.risk_factors = calculate_finding_risk(finding, assets.get(finding.asset_id))
    db.flush()


def organization_security_score(db: Session, organization_id: int) -> dict:
    refresh_finding_scores(db, organization_id)
    findings = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.status == "open").all()
    assets = db.query(Asset).filter(Asset.organization_id == organization_id).all()
    counts = {severity: sum(1 for f in findings if f.severity == severity) for severity in ("critical", "high", "medium", "low")}
    penalty = sum(min(35, f.risk_score or 0) for f in findings)
    coverage_bonus = min(10, len(assets))
    score = min(100, max(0, 100 - penalty + coverage_bonus))
    return {"score": score, "findings": counts, "assets_total": len(assets), "assets_exposed": sum(1 for asset in assets if asset.internet_exposed)}


def create_snapshot(db: Session, organization_id: int) -> SecuritySnapshot:
    summary = organization_security_score(db, organization_id)
    snapshot = SecuritySnapshot(organization_id=organization_id, score=summary["score"], critical_findings=summary["findings"]["critical"], high_findings=summary["findings"]["high"], medium_findings=summary["findings"]["medium"], low_findings=summary["findings"]["low"], assets_total=summary["assets_total"], assets_exposed=summary["assets_exposed"])
    db.add(snapshot)
    db.flush()
    return snapshot
