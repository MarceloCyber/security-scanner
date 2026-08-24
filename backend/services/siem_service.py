"""Internal bridge from trusted Iron AI telemetry to the native SIEM."""

import hashlib
import json
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError

from models.saas import SecurityAlertSubscription, SiemAlertDelivery, SiemEvent, SiemIncident, SiemRule, SecurityEvent


def _value(event: dict, field: str):
    if field.startswith("payload."):
        value = event.get("payload") or {}
        for part in field.split(".")[1:]:
            value = value.get(part) if isinstance(value, dict) else None
        return value
    return event.get(field)


def _matches(event: dict, conditions: dict) -> bool:
    group = conditions.get("all") or conditions.get("any") or []
    results = []
    for condition in group:
        current, expected, operator = _value(event, condition["field"]), condition["value"], condition["operator"]
        try:
            if operator == "equals": result = current == expected
            elif operator == "contains": result = str(expected).lower() in str(current or "").lower()
            elif operator == "in": result = current in expected
            elif operator == "gte": result = float(current) >= float(expected)
            else: result = float(current) <= float(expected)
        except (TypeError, ValueError):
            result = False
        results.append(result)
    return all(results) if conditions.get("all") else any(results)


def _queue_alerts(db, incident: SiemIncident):
    subscriptions = db.query(SecurityAlertSubscription).filter(SecurityAlertSubscription.organization_id == incident.organization_id, SecurityAlertSubscription.enabled.is_(True)).all()
    ranks = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    for subscription in subscriptions:
        if ranks.get(incident.severity, 0) < ranks.get(subscription.minimum_severity, 3):
            continue
        db.add(SiemAlertDelivery(organization_id=incident.organization_id, subscription_id=subscription.id, incident_id=incident.id))
        try:
            with db.begin_nested(): db.flush()
        except IntegrityError:
            continue


def mirror_security_event(db, event: SecurityEvent) -> SiemEvent:
    """Persist a real internal security event and evaluate current SIEM rules."""
    payload = event.evidence_json or {}
    data = {"event_type": event.event_type, "severity": event.severity, "source_ip": event.source_ip,
            "action": event.event_type, "outcome": "detected", "message": event.description, "payload": payload}
    fingerprint = hashlib.sha256(json.dumps({"organization_id": event.organization_id, "event_id": event.id}, sort_keys=True).encode()).hexdigest()
    siem_event = SiemEvent(organization_id=event.organization_id, asset_id=event.asset_id, event_type=event.event_type, severity=event.severity,
                           occurred_at=event.last_seen_at or datetime.utcnow(), source_ip=event.source_ip, action=event.event_type,
                           outcome="detected", message=event.description, payload=payload, fingerprint=fingerprint, matched_rule_ids=[])
    db.add(siem_event)
    db.flush()
    rules = db.query(SiemRule).filter(SiemRule.organization_id == event.organization_id, SiemRule.enabled.is_(True)).all()
    matched = [rule for rule in rules if _matches(data, rule.conditions)]
    siem_event.matched_rule_ids = [rule.id for rule in matched]
    for rule in matched:
        incident = db.query(SiemIncident).filter(SiemIncident.organization_id == event.organization_id, SiemIncident.rule_id == rule.id,
            SiemIncident.status.in_(["open", "investigating"]), SiemIncident.last_seen_at >= datetime.utcnow() - timedelta(minutes=15)).first()
        if incident:
            incident.last_seen_at = datetime.utcnow(); incident.event_id = siem_event.id
        else:
            incident = SiemIncident(organization_id=event.organization_id, rule_id=rule.id, event_id=siem_event.id, title=rule.name,
                description=rule.description or f"A regra {rule.name} detectou um evento real do Monitoramento.", severity=rule.severity)
            db.add(incident); db.flush(); _queue_alerts(db, incident)
    return siem_event
