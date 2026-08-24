"""Native SIEM ingestion, detection rules and incident investigation API."""

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, SecurityAlertSubscription, SiemAlertDelivery, SiemEvent, SiemIncident, SiemRule, SiemSource
from services.audit_service import record_audit
from services.rate_limit import rate_limit_backend
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter(prefix="/siem")
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
SEVERITY_RANK = {name: index for index, name in enumerate(("informational", "low", "medium", "high", "critical"))}
OPERATORS = {"equals", "contains", "in", "gte", "lte"}


class SourceCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    source_type: str = Field(default="generic", min_length=2, max_length=40)
    asset_id: int | None = None


class RuleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "high"
    conditions: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    description: str | None = Field(default=None, max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    conditions: dict[str, Any] | None = None
    enabled: bool | None = None


class EventInput(BaseModel):
    event_type: str = Field(min_length=1, max_length=80)
    severity: str = Field(default="informational", max_length=20)
    occurred_at: datetime | None = None
    source_ip: str | None = Field(default=None, max_length=64)
    user_name: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=120)
    outcome: str | None = Field(default=None, max_length=40)
    message: str | None = Field(default=None, max_length=5000)
    payload: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    events: list[EventInput] = Field(min_length=1, max_length=500)


class IncidentUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]
    resolution: str | None = Field(default=None, max_length=4000)
    assigned_to: int | None = None


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _source(raw_key: str, db: Session) -> SiemSource:
    if not raw_key.startswith("isiem_") or len(raw_key) < 40:
        raise HTTPException(status_code=401, detail="Chave do SIEM inválida")
    source = db.query(SiemSource).filter(SiemSource.key_hash == _hash_key(raw_key), SiemSource.revoked_at.is_(None)).first()
    if not source:
        raise HTTPException(status_code=401, detail="Chave do SIEM inválida ou revogada")
    allowed, _, _ = rate_limit_backend.hit(f"siem-source:{source.id}", limit=600, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Limite de ingestão do SIEM excedido")
    source.last_seen_at = datetime.utcnow()
    return source


def _source_dict(item: SiemSource) -> dict:
    return {"id": item.id, "name": item.name, "source_type": item.source_type, "asset_id": item.asset_id, "key_prefix": item.key_prefix,
            "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None, "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None,
            "created_at": item.created_at.isoformat()}


def _rule_dict(item: SiemRule) -> dict:
    return {"id": item.id, "name": item.name, "description": item.description, "severity": item.severity, "conditions": item.conditions,
            "enabled": item.enabled, "created_at": item.created_at.isoformat(), "updated_at": item.updated_at.isoformat()}


def _incident_dict(item: SiemIncident) -> dict:
    return {"id": item.id, "rule_id": item.rule_id, "event_id": item.event_id, "title": item.title, "description": item.description,
            "severity": item.severity, "status": item.status, "assigned_to": item.assigned_to, "resolution": item.resolution,
            "first_seen_at": item.first_seen_at.isoformat(), "last_seen_at": item.last_seen_at.isoformat(),
            "resolved_at": item.resolved_at.isoformat() if item.resolved_at else None}


def _validate_conditions(conditions: dict[str, Any]) -> dict[str, Any]:
    groups = conditions.get("all") or conditions.get("any")
    if not isinstance(groups, list) or not groups or len(groups) > 20:
        raise HTTPException(status_code=422, detail="A regra precisa ter uma lista all ou any com condições")
    key = "all" if conditions.get("all") else "any"
    normalized = []
    allowed_fields = {"event_type", "severity", "source_ip", "user_name", "action", "outcome", "message", "payload"}
    for condition in groups:
        field = condition.get("field") if isinstance(condition, dict) else None
        if not isinstance(condition, dict) or (field not in allowed_fields and not (isinstance(field, str) and field.startswith("payload."))) or condition.get("operator") not in OPERATORS or "value" not in condition:
            raise HTTPException(status_code=422, detail="Condição de regra inválida")
        if len(json.dumps(condition, ensure_ascii=False)) > 2000:
            raise HTTPException(status_code=422, detail="Condição de regra muito grande")
        normalized.append({"field": condition["field"], "operator": condition["operator"], "value": condition["value"]})
    return {key: normalized}


def _field_value(event: dict, field: str):
    if field.startswith("payload."):
        value: Any = event.get("payload") or {}
        for part in field.split(".")[1:]:
            value = value.get(part) if isinstance(value, dict) else None
        return value
    return event.get(field)


def _matches(event: dict, conditions: dict) -> bool:
    groups = conditions.get("all") or conditions.get("any") or []
    results = []
    for condition in groups:
        current = _field_value(event, condition["field"])
        expected = condition["value"]
        operator = condition["operator"]
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


def _fingerprint(source_id: int, event: dict) -> str:
    stable = {key: event.get(key) for key in ("event_type", "source_ip", "user_name", "action", "outcome", "message")}
    stable["source_id"] = source_id
    return hashlib.sha256(json.dumps(stable, sort_keys=True, ensure_ascii=False, default=str).encode()).hexdigest()


def _queue_incident_alerts(db: Session, incident: SiemIncident):
    subscriptions = db.query(SecurityAlertSubscription).filter(SecurityAlertSubscription.organization_id == incident.organization_id, SecurityAlertSubscription.enabled.is_(True)).all()
    for subscription in subscriptions:
        if SEVERITY_RANK.get(incident.severity, 0) < SEVERITY_RANK.get(subscription.minimum_severity, 3):
            continue
        delivery = SiemAlertDelivery(organization_id=incident.organization_id, subscription_id=subscription.id, incident_id=incident.id)
        db.add(delivery)
        try:
            with db.begin_nested(): db.flush()
        except IntegrityError:
            continue


def _ingest(source: SiemSource, item: EventInput, db: Session) -> tuple[SiemEvent, list[SiemIncident]]:
    event_data = item.model_dump()
    severity = item.severity.lower() if item.severity.lower() in SEVERITIES else "informational"
    occurred = item.occurred_at or datetime.utcnow()
    fingerprint = _fingerprint(source.id, event_data)
    rules = db.query(SiemRule).filter(SiemRule.organization_id == source.organization_id, SiemRule.enabled.is_(True)).all()
    matched = [rule for rule in rules if _matches({**event_data, "severity": severity}, rule.conditions)]
    event = SiemEvent(organization_id=source.organization_id, source_id=source.id, asset_id=source.asset_id, event_type=item.event_type,
                      severity=severity, occurred_at=occurred, source_ip=item.source_ip, user_name=item.user_name, action=item.action,
                      outcome=item.outcome, message=item.message, payload=item.payload, fingerprint=fingerprint, matched_rule_ids=[rule.id for rule in matched])
    db.add(event)
    db.flush()
    incidents = []
    for rule in matched:
        existing = db.query(SiemIncident).filter(SiemIncident.organization_id == source.organization_id, SiemIncident.rule_id == rule.id,
            SiemIncident.status.in_(["open", "investigating"]), SiemIncident.last_seen_at >= datetime.utcnow() - timedelta(minutes=15)).first()
        if existing:
            existing.last_seen_at = datetime.utcnow()
            existing.event_id = event.id
            incident = existing
        else:
            incident = SiemIncident(organization_id=source.organization_id, rule_id=rule.id, event_id=event.id, title=rule.name,
                description=rule.description or f"A regra {rule.name} detectou um evento compatível.", severity=rule.severity)
            db.add(incident)
            db.flush()
            _queue_incident_alerts(db, incident)
        incidents.append(incident)
    return event, incidents


@router.post("/sources")
def create_source(payload: SourceCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    if payload.asset_id and not db.query(Asset.id).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first():
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    raw_key = "isiem_" + secrets.token_urlsafe(36)
    item = SiemSource(organization_id=context.organization.id, asset_id=payload.asset_id, name=payload.name.strip(), source_type=payload.source_type.strip().lower(),
                      key_prefix=raw_key[:18], key_hash=_hash_key(raw_key), created_by=context.user.id)
    db.add(item); db.flush()
    record_audit(db, context, "siem_source_created", "siem_source", item.id, request, {"name": item.name, "source_type": item.source_type})
    db.commit()
    return {**_source_dict(item), "key": raw_key, "warning": "Copie a chave agora; ela não será exibida novamente."}


@router.get("/sources")
def list_sources(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return {"sources": [_source_dict(item) for item in db.query(SiemSource).filter(SiemSource.organization_id == context.organization.id).order_by(SiemSource.created_at.desc()).all()]}


@router.delete("/sources/{source_id}")
def revoke_source(source_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    item = db.query(SiemSource).filter(SiemSource.id == source_id, SiemSource.organization_id == context.organization.id).first()
    if not item: raise HTTPException(status_code=404, detail="Fonte SIEM não encontrada")
    item.revoked_at = datetime.utcnow()
    record_audit(db, context, "siem_source_revoked", "siem_source", item.id, request, {})
    db.commit()
    return {"revoked": True}


@router.post("/ingest")
def ingest(payload: EventBatch, request: Request, raw_key: str = Header(default="", alias="X-Iron-AI-SIEM-Key"), db: Session = Depends(get_db)):
    source = _source(raw_key, db)
    if len(json.dumps(payload.model_dump(), ensure_ascii=False, default=str)) > 1_500_000:
        raise HTTPException(status_code=413, detail="Lote SIEM excede o limite de tamanho")
    events = []; incidents = []
    for item in payload.events:
        event, opened = _ingest(source, item, db); events.append(event); incidents.extend(opened)
    db.commit()
    return {"accepted": len(events), "event_ids": [item.id for item in events], "incident_ids": sorted({item.id for item in incidents})}


@router.post("/rules")
def create_rule(payload: RuleCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    conditions = _validate_conditions(payload.conditions)
    item = SiemRule(organization_id=context.organization.id, name=payload.name.strip(), description=payload.description, severity=payload.severity, conditions=conditions, enabled=payload.enabled, created_by=context.user.id)
    db.add(item); db.flush(); record_audit(db, context, "siem_rule_created", "siem_rule", item.id, request, {"name": item.name}); db.commit()
    return _rule_dict(item)


@router.get("/rules")
def list_rules(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return {"rules": [_rule_dict(item) for item in db.query(SiemRule).filter(SiemRule.organization_id == context.organization.id).order_by(SiemRule.created_at.desc()).all()]}


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: int, payload: RuleUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    item = db.query(SiemRule).filter(SiemRule.id == rule_id, SiemRule.organization_id == context.organization.id).first()
    if not item: raise HTTPException(status_code=404, detail="Regra SIEM não encontrada")
    values = payload.model_dump(exclude_unset=True)
    if "conditions" in values: values["conditions"] = _validate_conditions(values["conditions"])
    for key, value in values.items(): setattr(item, key, value)
    record_audit(db, context, "siem_rule_updated", "siem_rule", item.id, request, {}); db.commit()
    return _rule_dict(item)


@router.get("/events")
def list_events(limit: int = 100, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    limit = min(max(limit, 1), 500)
    items = db.query(SiemEvent).filter(SiemEvent.organization_id == context.organization.id).order_by(SiemEvent.received_at.desc()).limit(limit).all()
    return {"events": [{"id": item.id, "source_id": item.source_id, "asset_id": item.asset_id, "event_type": item.event_type, "severity": item.severity,
        "occurred_at": item.occurred_at.isoformat(), "received_at": item.received_at.isoformat(), "source_ip": item.source_ip, "user_name": item.user_name,
        "action": item.action, "outcome": item.outcome, "message": item.message, "payload": item.payload, "matched_rule_ids": item.matched_rule_ids} for item in items]}


@router.get("/incidents")
def list_incidents(status_filter: str | None = None, limit: int = 100, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    query = db.query(SiemIncident).filter(SiemIncident.organization_id == context.organization.id)
    if status_filter: query = query.filter(SiemIncident.status == status_filter)
    items = query.order_by(SiemIncident.last_seen_at.desc()).limit(min(max(limit, 1), 500)).all()
    return {"incidents": [_incident_dict(item) for item in items]}


@router.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, payload: IncidentUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    item = db.query(SiemIncident).filter(SiemIncident.id == incident_id, SiemIncident.organization_id == context.organization.id).first()
    if not item: raise HTTPException(status_code=404, detail="Incidente SIEM não encontrado")
    item.status = payload.status; item.resolution = payload.resolution; item.assigned_to = payload.assigned_to
    item.resolved_at = datetime.utcnow() if payload.status in {"resolved", "false_positive"} else None
    record_audit(db, context, "siem_incident_updated", "siem_incident", item.id, request, {"status": item.status}); db.commit()
    return _incident_dict(item)


@router.get("/overview")
def overview(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    incidents = db.query(SiemIncident).filter(SiemIncident.organization_id == context.organization.id).all()
    events_24h = db.query(SiemEvent).filter(SiemEvent.organization_id == context.organization.id, SiemEvent.received_at >= datetime.utcnow() - timedelta(hours=24)).count()
    return {"sources": db.query(SiemSource).filter(SiemSource.organization_id == context.organization.id, SiemSource.revoked_at.is_(None)).count(),
            "rules": db.query(SiemRule).filter(SiemRule.organization_id == context.organization.id, SiemRule.enabled.is_(True)).count(),
            "events_24h": events_24h, "open_incidents": sum(item.status in {"open", "investigating"} for item in incidents),
            "critical_incidents": sum(item.status in {"open", "investigating"} and item.severity == "critical" for item in incidents)}
