"""Realtime defensive telemetry, incident triage and approved WAF containment."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import secrets
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models.saas import (
    Asset, AuditLog, ContainmentAction, Integration, IntegrationCredential,
    Organization, SecurityEvent, SecuritySensor,
)
from services.audit_service import record_audit
from services.credential_vault import CredentialVault
from services.rate_limit import rate_limit_backend
from services.security_monitoring_service import classify_telemetry, correlate_event, is_blockable_ip
from services.tenant import TenantContext, get_tenant_context, require_roles
from services.plan_policy import REALTIME_MONITORING_PLANS, normalize_plan

router = APIRouter(prefix="/security-monitoring")
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


class SensorCreate(BaseModel):
    asset_id: int
    name: str = Field(min_length=2, max_length=120)
    expires_in_days: int = Field(default=365, ge=1, le=730)


class TelemetryItem(BaseModel):
    signal: Optional[str] = Field(default=None, max_length=50)
    source_ip: Optional[str] = Field(default=None, max_length=64)
    method: Optional[str] = Field(default=None, max_length=12)
    path: Optional[str] = Field(default=None, max_length=2048)
    status_code: Optional[int] = Field(default=None, ge=100, le=599)
    request_count: int = Field(default=1, ge=1, le=1_000_000)
    window_seconds: int = Field(default=60, ge=1, le=3600)
    distinct_paths: int = Field(default=0, ge=0, le=1_000_000)
    user_agent: Optional[str] = Field(default=None, max_length=512)
    source: Optional[str] = Field(default="reverse_proxy", max_length=80)


class TelemetryBatch(BaseModel):
    events: list[TelemetryItem] = Field(min_length=1, max_length=100)


class EventStatusUpdate(BaseModel):
    status: Literal["open", "investigating", "resolved", "false_positive"]


class CloudflareConnect(BaseModel):
    zone_id: str = Field(pattern=r"^[a-fA-F0-9]{32}$")
    api_token: str = Field(min_length=20, max_length=500)


@dataclass(frozen=True)
class SensorContext:
    organization: Organization
    sensor: SecuritySensor


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _vault() -> CredentialVault:
    try:
        return CredentialVault()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def get_sensor_context(raw_key: str = Header(default="", alias="X-Iron-AI-Sensor-Key"), db: Session = Depends(get_db)) -> SensorContext:
    if not raw_key.startswith("iais_") or len(raw_key) < 40:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chave de sensor inválida")
    sensor = db.query(SecuritySensor).filter(SecuritySensor.key_hash == _hash_key(raw_key), SecuritySensor.revoked_at.is_(None)).first()
    now = datetime.utcnow()
    if not sensor or (sensor.expires_at and sensor.expires_at <= now):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Chave de sensor inválida ou expirada")
    allowed, _, _ = rate_limit_backend.hit(f"security-sensor:{sensor.id}", limit=120, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Limite de telemetria excedido")
    organization = db.query(Organization).filter(Organization.id == sensor.organization_id, Organization.status == "active").first()
    if not organization:
        raise HTTPException(status_code=403, detail="Organização indisponível")
    sensor.last_seen_at = now
    return SensorContext(organization=organization, sensor=sensor)


def _cloudflare_connection(db: Session, organization_id: int):
    integration = db.query(Integration).filter(
        Integration.organization_id == organization_id,
        Integration.provider == "cloudflare_waf",
        Integration.status == "connected",
    ).first()
    if not integration:
        raise HTTPException(status_code=409, detail="Conecte o Cloudflare WAF antes de bloquear uma origem")
    credential = db.query(IntegrationCredential).filter(
        IntegrationCredential.organization_id == organization_id,
        IntegrationCredential.integration_id == integration.id,
    ).first()
    if not credential:
        raise HTTPException(status_code=409, detail="Credencial do Cloudflare indisponível")
    return integration, _vault().decrypt(credential.encrypted_secret)


def _event_dict(event: SecurityEvent, asset_name: str | None = None, containment_action_id: int | None = None) -> dict:
    return {
        "id": event.id, "asset_id": event.asset_id, "asset_name": asset_name,
        "event_type": event.event_type, "severity": event.severity, "title": event.title,
        "description": event.description, "remediation": event.remediation,
        "source_ip": event.source_ip, "method": event.method, "path": event.request_path,
        "status_code": event.status_code, "request_count": event.request_count,
        "evidence": event.evidence_json or {}, "status": event.status,
        "containment_status": event.containment_status, "occurrence_count": event.occurrence_count,
        "containment_action_id": containment_action_id,
        "first_seen_at": event.first_seen_at.isoformat(), "last_seen_at": event.last_seen_at.isoformat(),
    }


def _require_realtime_plan(plan: str) -> None:
    if normalize_plan(plan) not in REALTIME_MONITORING_PLANS:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "professional_required",
                "message": "Monitoramento em tempo real e contenção WAF estão disponíveis a partir do plano Professional.",
                "required_plans": ["professional", "enterprise"],
                "upgrade_url": "/pricing.html",
            },
        )


@router.post("/sensors")
def create_sensor(payload: SensorCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado")
    raw_key = "iais_" + secrets.token_urlsafe(36)
    sensor = SecuritySensor(
        organization_id=context.organization.id, asset_id=asset.id, name=payload.name.strip(),
        key_prefix=raw_key[:18], key_hash=_hash_key(raw_key), created_by=context.user.id,
        expires_at=datetime.utcnow() + timedelta(days=payload.expires_in_days),
    )
    db.add(sensor)
    db.flush()
    record_audit(db, context, "security_sensor_created", "security_sensor", sensor.id, request, {"asset_id": asset.id, "name": sensor.name})
    db.commit()
    return {"id": sensor.id, "key": raw_key, "key_prefix": sensor.key_prefix, "expires_at": sensor.expires_at.isoformat(), "warning": "Copie agora. A chave não será exibida novamente."}


@router.get("/sensors")
def list_sensors(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    sensors = db.query(SecuritySensor).filter(SecuritySensor.organization_id == context.organization.id).order_by(SecuritySensor.created_at.desc()).all()
    return {"sensors": [{"id": item.id, "asset_id": item.asset_id, "name": item.name, "key_prefix": item.key_prefix, "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None, "expires_at": item.expires_at.isoformat() if item.expires_at else None, "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None} for item in sensors]}


@router.delete("/sensors/{sensor_id}")
def revoke_sensor(sensor_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    sensor = db.query(SecuritySensor).filter(SecuritySensor.id == sensor_id, SecuritySensor.organization_id == context.organization.id).first()
    if not sensor:
        raise HTTPException(status_code=404, detail="Sensor não encontrado")
    sensor.revoked_at = sensor.revoked_at or datetime.utcnow()
    record_audit(db, context, "security_sensor_revoked", "security_sensor", sensor.id, request)
    db.commit()
    return {"revoked": True}


@router.post("/ingest")
def ingest_telemetry(payload: TelemetryBatch, request: Request, context: SensorContext = Depends(get_sensor_context), db: Session = Depends(get_db)):
    _require_realtime_plan(context.organization.plan)
    asset = db.query(Asset).filter(Asset.id == context.sensor.asset_id, Asset.organization_id == context.organization.id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo do sensor não encontrado")
    detected = []
    for item in payload.events:
        classification = classify_telemetry(item.model_dump())
        if classification:
            detected.append(correlate_event(db, context.organization.id, asset.id, context.sensor.id, classification))
    if detected:
        db.add(AuditLog(
            organization_id=context.organization.id, action="security_events_ingested", resource_type="security_sensor",
            resource_id=str(context.sensor.id), ip_address=request.client.host if request and request.client else None,
            user_agent=(request.headers.get("user-agent", "")[:512] if request else None), metadata_json={"received": len(payload.events), "detected": len(detected)},
        ))
    db.commit()
    return {"received": len(payload.events), "detected": len(detected), "event_ids": sorted({event.id for event in detected})}


@router.get("/overview")
def monitoring_overview(since_id: int = 0, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    query = db.query(SecurityEvent, Asset.name).join(Asset, Asset.id == SecurityEvent.asset_id).filter(SecurityEvent.organization_id == context.organization.id)
    if since_id > 0:
        query = query.filter(SecurityEvent.id > since_id)
    rows = query.order_by(SecurityEvent.last_seen_at.desc()).limit(100).all()
    open_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.organization_id == context.organization.id, SecurityEvent.status.in_(["open", "investigating"])).scalar() or 0
    critical_count = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.organization_id == context.organization.id, SecurityEvent.status.in_(["open", "investigating"]), SecurityEvent.severity == "critical").scalar() or 0
    since = datetime.utcnow() - timedelta(hours=24)
    last_24h = db.query(func.count(SecurityEvent.id)).filter(SecurityEvent.organization_id == context.organization.id, SecurityEvent.last_seen_at >= since).scalar() or 0
    active_sensors = db.query(func.count(SecuritySensor.id)).filter(SecuritySensor.organization_id == context.organization.id, SecuritySensor.revoked_at.is_(None), SecuritySensor.last_seen_at >= datetime.utcnow() - timedelta(minutes=5)).scalar() or 0
    active_blocks = db.query(func.count(ContainmentAction.id)).filter(ContainmentAction.organization_id == context.organization.id, ContainmentAction.status == "executed").scalar() or 0
    waf = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == "cloudflare_waf", Integration.status == "connected").first()
    actions = db.query(ContainmentAction).filter(ContainmentAction.organization_id == context.organization.id, ContainmentAction.status == "executed").all()
    action_by_event = {item.security_event_id: item.id for item in actions if item.security_event_id}
    events = [_event_dict(event, asset_name, action_by_event.get(event.id)) for event, asset_name in rows]
    return {"events": events, "metrics": {"open": open_count, "critical": critical_count, "last_24h": last_24h, "active_sensors": active_sensors, "active_blocks": active_blocks}, "cloudflare_connected": bool(waf), "latest_id": max([event["id"] for event in events], default=since_id)}


@router.patch("/events/{event_id}")
def update_event(event_id: int, payload: EventStatusUpdate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id, SecurityEvent.organization_id == context.organization.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    event.status = payload.status
    event.resolved_at = datetime.utcnow() if payload.status in {"resolved", "false_positive"} else None
    record_audit(db, context, "security_event_status_changed", "security_event", event.id, request, {"status": payload.status})
    db.commit()
    return _event_dict(event)


@router.post("/cloudflare/connect")
def connect_cloudflare(payload: CloudflareConnect, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    try:
        response = requests.get(f"{CLOUDFLARE_API}/zones/{payload.zone_id}", headers={"Authorization": f"Bearer {payload.api_token}"}, timeout=12)
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Não foi possível validar o Cloudflare") from exc
    if response.status_code >= 300 or not data.get("success"):
        raise HTTPException(status_code=400, detail="Token ou Zone ID do Cloudflare inválido, ou sem permissão")
    zone = data.get("result") or {}
    integration = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == "cloudflare_waf").first()
    if not integration:
        integration = Integration(organization_id=context.organization.id, provider="cloudflare_waf")
        db.add(integration)
        db.flush()
    integration.status = "connected"
    integration.configuration = {"zone_id": payload.zone_id, "zone_name": str(zone.get("name") or "")[:255]}
    encrypted = _vault().encrypt(payload.api_token)
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id).first()
    if credential:
        credential.encrypted_secret = encrypted
        credential.secret_hint = payload.api_token[-4:]
    else:
        db.add(IntegrationCredential(organization_id=context.organization.id, integration_id=integration.id, encrypted_secret=encrypted, secret_hint=payload.api_token[-4:]))
    record_audit(db, context, "cloudflare_waf_connected", "integration", integration.id, request, {"zone_id": payload.zone_id, "zone_name": zone.get("name")})
    db.commit()
    return {"connected": True, "zone_name": zone.get("name")}


@router.post("/events/{event_id}/contain")
def contain_event(event_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id, SecurityEvent.organization_id == context.organization.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    if not is_blockable_ip(event.source_ip):
        raise HTTPException(status_code=400, detail="O evento não possui um IP público bloqueável")
    existing = db.query(ContainmentAction).filter(ContainmentAction.organization_id == context.organization.id, ContainmentAction.security_event_id == event.id, ContainmentAction.status == "executed").first()
    if existing:
        return {"success": True, "action_id": existing.id, "status": "executed", "already_contained": True}
    integration, token = _cloudflare_connection(db, context.organization.id)
    zone_id = (integration.configuration or {}).get("zone_id")
    action = ContainmentAction(organization_id=context.organization.id, security_event_id=event.id, provider="cloudflare", action_type="block_ip", target=event.source_ip, approved_by=context.user.id)
    db.add(action)
    db.flush()
    try:
        response = requests.post(
            f"{CLOUDFLARE_API}/zones/{zone_id}/firewall/access_rules/rules",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"mode": "block", "configuration": {"target": "ip", "value": event.source_ip}, "notes": f"Iron AI event {event.id}"}, timeout=12,
        )
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        action.status = "failed"; action.error = "Cloudflare indisponível"; db.commit()
        raise HTTPException(status_code=502, detail="Não foi possível executar o bloqueio no Cloudflare") from exc
    if response.status_code >= 300 or not data.get("success"):
        action.status = "failed"; action.error = str(data.get("errors") or "Cloudflare rejeitou a regra")[:2000]; db.commit()
        raise HTTPException(status_code=502, detail="O Cloudflare rejeitou a regra de bloqueio")
    result = data.get("result") or {}
    action.status = "executed"; action.external_id = result.get("id"); action.executed_at = datetime.utcnow(); action.response_json = {"mode": result.get("mode"), "scope": result.get("scope")}
    event.containment_status = "blocked"
    record_audit(db, context, "attack_source_blocked", "security_event", event.id, request, {"source_ip": event.source_ip, "provider": "cloudflare", "action_id": action.id})
    db.commit()
    return {"success": True, "action_id": action.id, "status": action.status, "source_ip": event.source_ip}


@router.delete("/containment/{action_id}")
def release_containment(action_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id, ContainmentAction.organization_id == context.organization.id, ContainmentAction.status == "executed").first()
    if not action or not action.external_id:
        raise HTTPException(status_code=404, detail="Bloqueio ativo não encontrado")
    integration, token = _cloudflare_connection(db, context.organization.id)
    zone_id = (integration.configuration or {}).get("zone_id")
    try:
        response = requests.delete(f"{CLOUDFLARE_API}/zones/{zone_id}/firewall/access_rules/rules/{action.external_id}", headers={"Authorization": f"Bearer {token}"}, timeout=12)
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Não foi possível remover o bloqueio no Cloudflare") from exc
    if response.status_code >= 300 or not data.get("success"):
        raise HTTPException(status_code=502, detail="O Cloudflare não confirmou a remoção do bloqueio")
    action.status = "released"; action.released_at = datetime.utcnow()
    event = db.query(SecurityEvent).filter(SecurityEvent.id == action.security_event_id, SecurityEvent.organization_id == context.organization.id).first()
    if event: event.containment_status = "released"
    record_audit(db, context, "attack_source_unblocked", "containment_action", action.id, request, {"source_ip": action.target, "provider": "cloudflare"})
    db.commit()
    return {"released": True}
