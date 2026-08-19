"""Normalize legacy scanner output into the platform finding contract."""

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session

from models.saas import Asset, Finding, Organization, OrganizationMember
from models.user import User

SEVERITIES = {"informational", "low", "medium", "high", "critical"}
SEVERITY_ALIASES = {"info": "informational", "informative": "informational", "warning": "medium"}
CONFIDENCES = {"low", "medium", "high", "confirmed"}


def normalize_severity(value: Any) -> str:
    value = str(value or "medium").strip().lower()
    value = SEVERITY_ALIASES.get(value, value)
    return value if value in SEVERITIES else "medium"


def normalize_confidence(value: Any) -> str:
    value = str(value or "medium").strip().lower()
    return value if value in CONFIDENCES else "medium"


def _as_findings(results: Any) -> list[dict]:
    if not isinstance(results, dict):
        return []
    candidates = results.get("findings") or results.get("vulnerabilities") or results.get("issues") or results.get("results") or []
    if isinstance(candidates, dict):
        candidates = candidates.get("findings") or candidates.get("vulnerabilities") or []
    return [item for item in candidates if isinstance(item, dict)] if isinstance(candidates, list) else []


def _value(item: dict, *keys: str, default=None):
    for key in keys:
        if item.get(key) not in (None, ""):
            return item[key]
    return default


def finding_fingerprint(organization_id: int, asset_id: Optional[int], scanner_source: str, item: dict) -> str:
    identity = {
        "organization_id": organization_id,
        "asset_id": asset_id,
        "source": scanner_source,
        "category": _value(item, "category", "type", "name", default="unknown"),
        "location": _value(item, "location", "endpoint", "file", "file_path", "line", "port", default=""),
        "identifier": _value(item, "cve", "cwe", "rule_id", "code", "description", default=""),
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True, default=str).encode()).hexdigest()


def get_default_organization(db: Session, user: User) -> Optional[Organization]:
    membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).order_by(OrganizationMember.created_at.asc()).first()
    return db.query(Organization).filter(Organization.id == membership.organization_id).first() if membership else None


def get_or_create_asset(db: Session, organization_id: int, target: str, asset_type: str = "web_application") -> Asset:
    target = (target or "unknown").strip()[:255]
    asset = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.name == target).first()
    if asset:
        asset.last_seen_at = datetime.utcnow()
        return asset
    asset = Asset(organization_id=organization_id, type=asset_type, name=target, url=target if target.startswith("http") else None)
    db.add(asset)
    db.flush()
    return asset


def persist_scan_findings(db: Session, user: User, results: Any, scanner_source: str, target: str, scan_job_id: Optional[int] = None) -> list[Finding]:
    organization = get_default_organization(db, user)
    if not organization:
        return []
    asset = get_or_create_asset(db, organization.id, target)
    persisted = []
    for item in _as_findings(results):
        severity = normalize_severity(_value(item, "severity", "level", default="medium"))
        confidence = normalize_confidence(_value(item, "confidence", default="medium"))
        fingerprint = finding_fingerprint(organization.id, asset.id, scanner_source, item)
        finding = db.query(Finding).filter(Finding.organization_id == organization.id, Finding.fingerprint == fingerprint).first()
        now = datetime.utcnow()
        if finding:
            finding.last_seen_at = now
            finding.occurrence_count = (finding.occurrence_count or 0) + 1
            finding.evidence = str(_value(item, "evidence", "details", "description", default=finding.evidence or ""))[:10000]
            if finding.status in {"resolved", "false_positive"}:
                finding.status = "open"
        else:
            finding = Finding(
                organization_id=organization.id,
                asset_id=asset.id,
                scan_job_id=scan_job_id,
                fingerprint=fingerprint,
                title=str(_value(item, "title", "name", "type", default="Security finding"))[:255],
                description=str(_value(item, "description", "details", default="Resultado normalizado de scanner"))[:10000],
                category=str(_value(item, "category", "type", default="security"))[:80],
                severity=severity,
                confidence=confidence,
                cve=_value(item, "cve"),
                cwe=_value(item, "cwe"),
                cvss_score=str(_value(item, "cvss", "cvss_score", default=""))[:16] or None,
                evidence=str(_value(item, "evidence", "details", default=""))[:10000],
                remediation=str(_value(item, "remediation", "recommendation", "solution", default=""))[:10000],
                scanner_source=scanner_source[:80],
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(finding)
        persisted.append(finding)
    db.flush()
    return persisted
