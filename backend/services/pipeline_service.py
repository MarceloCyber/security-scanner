"""Normalize external security results and consolidate them into Iron AI findings."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import re
from typing import Any

from models.saas import Finding, FindingEvidence
from risk.engine import create_snapshot, refresh_finding_scores

SEVERITIES = {"critical", "high", "medium", "low", "informational"}
SARIF_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "informational"}


def _severity(value: Any, score: Any = None) -> str:
    normalized = str(value or "").lower().strip()
    if normalized in SEVERITIES:
        return normalized
    try:
        numeric = float(score)
        if numeric >= 9:
            return "critical"
        if numeric >= 7:
            return "high"
        if numeric >= 4:
            return "medium"
        if numeric > 0:
            return "low"
    except (TypeError, ValueError):
        pass
    return SARIF_LEVELS.get(normalized, "medium")


def normalize_sarif(document: dict) -> list[dict]:
    """Convert SARIF 2.x results from common scanners into a stable contract."""
    normalized: list[dict] = []
    for run in (document or {}).get("runs", [])[:50]:
        driver = ((run.get("tool") or {}).get("driver") or {})
        tool_name = str(driver.get("name") or "SARIF scanner")[:80]
        rules = {str(rule.get("id")): rule for rule in driver.get("rules", []) if rule.get("id")}
        for result in run.get("results", [])[:1000 - len(normalized)]:
            rule_id = str(result.get("ruleId") or "external-finding")
            rule = rules.get(rule_id, {})
            properties = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
            location = ""
            locations = result.get("locations") or []
            if locations:
                physical = (locations[0].get("physicalLocation") or {})
                artifact = (physical.get("artifactLocation") or {}).get("uri") or ""
                line = (physical.get("region") or {}).get("startLine")
                location = f"{artifact}:{line}" if line else str(artifact)
            message = (result.get("message") or {}).get("text") or (rule.get("fullDescription") or {}).get("text") or rule_id
            title = (rule.get("shortDescription") or {}).get("text") or rule_id
            tags = [str(tag) for tag in properties.get("tags", [])]
            cwe_match = re.search(r"CWE-\d+", " ".join([rule_id, *tags]), re.IGNORECASE)
            fingerprints = result.get("fingerprints") or result.get("partialFingerprints") or {}
            external_fingerprint = next(iter(fingerprints.values()), None)
            score = properties.get("security-severity") or properties.get("cvss")
            normalized.append({
                "title": str(title)[:255],
                "description": str(message)[:8000],
                "category": str(properties.get("category") or rule_id)[:80],
                "severity": _severity(result.get("level"), score),
                "confidence": "confirmed" if result.get("suppressions") is None else "medium",
                "cve": next((tag.upper() for tag in tags if tag.upper().startswith("CVE-")), None),
                "cwe": cwe_match.group(0).upper() if cwe_match else None,
                "cvss_score": str(score)[:16] if score is not None else None,
                "evidence": str(message)[:8000],
                "remediation": str((rule.get("help") or {}).get("text") or properties.get("remediation") or "Revise o finding no scanner de origem e aplique a correção recomendada.")[:8000],
                "location": location[:2048],
                "external_fingerprint": str(external_fingerprint)[:256] if external_fingerprint else None,
                "scanner_source": tool_name,
            })
    return normalized


def normalize_findings(items: list[dict], source: str) -> list[dict]:
    output = []
    for item in items[:1000]:
        if not str(item.get("title") or "").strip():
            continue
        output.append({
            "title": str(item["title"]).strip()[:255],
            "description": str(item.get("description") or "")[:8000],
            "category": str(item.get("category") or "external")[:80],
            "severity": _severity(item.get("severity"), item.get("cvss_score")),
            "confidence": str(item.get("confidence") or "medium")[:20],
            "cve": str(item.get("cve"))[:40] if item.get("cve") else None,
            "cwe": str(item.get("cwe"))[:40] if item.get("cwe") else None,
            "cvss_score": str(item.get("cvss_score"))[:16] if item.get("cvss_score") is not None else None,
            "evidence": str(item.get("evidence") or item.get("description") or "")[:8000],
            "remediation": str(item.get("remediation") or "Investigue e corrija o finding no componente afetado.")[:8000],
            "location": str(item.get("location") or "")[:2048],
            "external_fingerprint": str(item.get("fingerprint") or item.get("external_id") or "")[:256] or None,
            "scanner_source": source[:80],
        })
    return output


def _fingerprint(organization_id: int, asset_id: int, source: str, item: dict) -> str:
    stable = item.get("external_fingerprint") or json.dumps(
        [item.get("title"), item.get("category"), item.get("location")], ensure_ascii=False, sort_keys=True
    )
    return hashlib.sha256(f"{organization_id}|{asset_id}|{source}|{stable}".encode()).hexdigest()


def consolidate_findings(db, organization_id: int, asset_id: int, source: str, items: list[dict], complete_scan: bool = True) -> dict:
    now = datetime.utcnow()
    active_fingerprints = set()
    created = updated = resolved = 0
    for item in items:
        scanner_source = str(item.get("scanner_source") or source)[:80]
        fingerprint = _fingerprint(organization_id, asset_id, scanner_source, item)
        active_fingerprints.add(fingerprint)
        finding = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.fingerprint == fingerprint).first()
        if finding is None:
            finding = Finding(organization_id=organization_id, asset_id=asset_id, fingerprint=fingerprint, title=item["title"])
            db.add(finding)
            db.flush()
            created += 1
        else:
            finding.occurrence_count = (finding.occurrence_count or 0) + 1
            updated += 1
        finding.title = item["title"]
        finding.description = item.get("description")
        finding.category = item.get("category")
        finding.severity = item.get("severity", "medium")
        finding.confidence = item.get("confidence", "medium")
        finding.cve = item.get("cve")
        finding.cwe = item.get("cwe")
        finding.cvss_score = item.get("cvss_score")
        finding.evidence = item.get("evidence")
        finding.remediation = item.get("remediation")
        finding.scanner_source = scanner_source
        finding.last_seen_at = now
        if finding.status == "resolved":
            finding.status = "open"
            finding.resolved_at = None
        if item.get("evidence"):
            db.add(FindingEvidence(organization_id=organization_id, finding_id=finding.id, content=item["evidence"], location=item.get("location") or None))

    if complete_scan:
        previous = db.query(Finding).filter(
            Finding.organization_id == organization_id,
            Finding.asset_id == asset_id,
            Finding.scanner_source == source,
            Finding.status.in_(["open", "in_progress"]),
        ).all()
        for finding in previous:
            if finding.fingerprint not in active_fingerprints:
                finding.status = "resolved"
                finding.resolved_at = now
                resolved += 1

    refresh_finding_scores(db, organization_id)
    snapshot = create_snapshot(db, organization_id)
    return {"created": created, "updated": updated, "resolved": resolved, "total_received": len(items), "security_score": snapshot.score}


def evaluate_gate(db, organization_id: int, asset_id: int | None, fail_on: str, max_allowed: int = 0) -> dict:
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    threshold = rank.get(fail_on, 3)
    query = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.status.in_(["open", "in_progress"]))
    if asset_id is not None:
        query = query.filter(Finding.asset_id == asset_id)
    findings = [finding for finding in query.all() if rank.get(finding.severity, 0) >= threshold]
    findings.sort(key=lambda finding: (rank.get(finding.severity, 0), finding.risk_score or 0), reverse=True)
    return {
        "passed": len(findings) <= max_allowed,
        "policy": {"fail_on": fail_on, "max_allowed": max_allowed},
        "violations": len(findings),
        "blocking_findings": [{"id": f.id, "title": f.title, "severity": f.severity, "risk_score": f.risk_score} for f in findings[:50]],
    }
