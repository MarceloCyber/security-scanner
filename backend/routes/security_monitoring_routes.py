"""Realtime defensive telemetry, incident triage and approved WAF containment."""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import secrets
from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from database import get_db
from models.saas import (
    Asset, AuditLog, ContainmentAction, ContainmentTest, Integration, IntegrationCredential,
    Organization, SecurityEvent, SecuritySensor,
    SensorEnrollment,
)
from services.audit_service import record_audit
from services.credential_vault import CredentialVault
from services.rate_limit import rate_limit_backend
from services.security_monitoring_service import classify_telemetry, correlate_event, is_blockable_ip, safe_source_ip
from services.tenant import TenantContext, get_tenant_context, require_roles
from services.plan_policy import REALTIME_MONITORING_PLANS, normalize_plan

router = APIRouter(prefix="/security-monitoring")
CLOUDFLARE_API = "https://api.cloudflare.com/client/v4"


class SensorCreate(BaseModel):
    asset_id: int
    name: str = Field(min_length=2, max_length=120)
    expires_in_days: int = Field(default=365, ge=1, le=730)


class SensorEnrollmentCreate(BaseModel):
    asset_id: int
    name: str = Field(min_length=2, max_length=120)
    expires_in_minutes: int = Field(default=15, ge=5, le=30)


class SensorEnrollmentRedeem(BaseModel):
    token: str = Field(min_length=30, max_length=300)


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
    zone_id: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{32}$")
    domain: Optional[str] = Field(default=None, min_length=3, max_length=255, pattern=r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
    api_token: str = Field(min_length=20, max_length=500)


class SensorActionResult(BaseModel):
    status: Literal["executed", "released", "failed"]
    firewall_backend: Optional[Literal["nftables", "iptables", "ip6tables"]] = None
    detail: Optional[str] = Field(default=None, max_length=1000)


class ContainmentTestCreate(BaseModel):
    asset_id: int


class ManualContainmentCreate(BaseModel):
    asset_id: int
    ip_address: str = Field(min_length=3, max_length=64)
    reason: str = Field(min_length=5, max_length=500)


@dataclass(frozen=True)
class SensorContext:
    organization: Organization
    sensor: SecuritySensor


def _hash_key(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _sensor_installer_path() -> Path:
    return Path(__file__).resolve().parents[2] / "scripts" / "iron_ai_sensor.py"


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


def _event_dict(event: SecurityEvent, asset_name: str | None = None, containment_action_id: int | None = None, containment_provider: str | None = None, containment_available: bool | None = None) -> dict:
    return {
        "id": event.id, "asset_id": event.asset_id, "asset_name": asset_name,
        "event_type": event.event_type, "severity": event.severity, "title": event.title,
        "description": event.description, "remediation": event.remediation,
        "source_ip": event.source_ip, "method": event.method, "path": event.request_path,
        "status_code": event.status_code, "request_count": event.request_count,
        "evidence": event.evidence_json or {}, "status": event.status,
        "containment_status": event.containment_status, "occurrence_count": event.occurrence_count,
        "containment_action_id": containment_action_id,
        "containment_provider": containment_provider,
        "containment_available": containment_available,
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


def _containment_ready(db: Session, organization_id: int, asset_id: int) -> bool:
    cloudflare = db.query(Integration.id).filter(
        Integration.organization_id == organization_id,
        Integration.provider == "cloudflare_waf",
        Integration.status == "connected",
    ).first()
    host_firewall = db.query(SecuritySensor.id).filter(
        SecuritySensor.organization_id == organization_id,
        SecuritySensor.asset_id == asset_id,
        SecuritySensor.revoked_at.is_(None),
        SecuritySensor.containment_enabled.is_(True),
        SecuritySensor.last_seen_at >= datetime.utcnow() - timedelta(minutes=5),
    ).first()
    return bool(cloudflare or host_firewall)


def _test_page(title: str, message: str, *, success: bool, status_code: int = 200) -> HTMLResponse:
    color = "#6ee7b7" if success else "#fda4af"
    icon = "✓" if success else "!"
    html = f"""<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>{title}</title><style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0812;color:#f4efff;font-family:Inter,system-ui,sans-serif;padding:24px;box-sizing:border-box}}main{{width:min(440px,100%);padding:34px;border:1px solid #302640;border-radius:24px;background:linear-gradient(145deg,#1b1527,#100c18);box-shadow:0 24px 80px #0008;text-align:center}}i{{display:grid;place-items:center;width:62px;height:62px;margin:0 auto 18px;border-radius:20px;background:{color}18;color:{color};font:700 30px system-ui}}h1{{font-size:23px;margin:0 0 10px}}p{{color:#afa5bf;line-height:1.6;margin:0}}small{{display:block;color:#786f88;margin-top:20px}}</style></head><body><main><i>{icon}</i><h1>{title}</h1><p>{message}</p><small>Você já pode fechar esta página e voltar à Iron AI.</small></main></body></html>"""
    return HTMLResponse(html, status_code=status_code, headers={"Cache-Control": "no-store, max-age=0"})


def _request_source_ip(request: Request) -> str | None:
    """Resolve the public visitor address while trusting forwarding only from a local/private edge proxy."""
    direct = safe_source_ip(request.client.host if request and request.client else None)
    if is_blockable_ip(direct):
        return direct
    if request and direct and not is_blockable_ip(direct):
        forwarded = request.headers.get("x-forwarded-for", "")
        for candidate in reversed([item.strip() for item in forwarded.split(",") if item.strip()]):
            normalized = safe_source_ip(candidate)
            if is_blockable_ip(normalized):
                return normalized
    return direct


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


@router.post("/sensors/enrollment")
def create_sensor_enrollment(payload: SensorEnrollmentCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    asset = db.query(Asset).filter(Asset.id == payload.asset_id, Asset.organization_id == context.organization.id, Asset.status != "inactive").first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado ou inativo")
    raw_token = "ienroll_" + secrets.token_urlsafe(36)
    enrollment = SensorEnrollment(
        organization_id=context.organization.id, asset_id=asset.id, sensor_name=payload.name.strip(),
        token_hash=_hash_key(raw_token), created_by=context.user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=payload.expires_in_minutes),
    )
    db.add(enrollment)
    db.flush()
    record_audit(db, context, "security_sensor_enrollment_created", "sensor_enrollment", enrollment.id, request, {"asset_id": asset.id, "name": enrollment.sensor_name})
    db.commit()
    installer_hash = hashlib.sha256(_sensor_installer_path().read_bytes()).hexdigest()
    return {"token": raw_token, "expires_at": enrollment.expires_at.isoformat(), "sensor_name": enrollment.sensor_name, "asset_name": asset.name, "installer_sha256": installer_hash, "warning": "Use este comando uma única vez. O token expira automaticamente."}


@router.post("/sensors/enroll")
def redeem_sensor_enrollment(payload: SensorEnrollmentRedeem, request: Request, db: Session = Depends(get_db)):
    client_host = request.client.host if request and request.client else "unknown"
    allowed, _, _ = rate_limit_backend.hit(f"sensor-enrollment:{client_host}", limit=10, window_seconds=60)
    if not allowed:
        raise HTTPException(status_code=429, detail="Muitas tentativas de instalação. Aguarde e tente novamente.")
    enrollment = db.query(SensorEnrollment).filter(SensorEnrollment.token_hash == _hash_key(payload.token), SensorEnrollment.used_at.is_(None)).first()
    now = datetime.utcnow()
    if not enrollment or enrollment.expires_at <= now:
        raise HTTPException(status_code=401, detail="Token de instalação inválido, expirado ou já utilizado")
    organization = db.query(Organization).filter(Organization.id == enrollment.organization_id, Organization.status == "active").first()
    asset = db.query(Asset).filter(Asset.id == enrollment.asset_id, Asset.organization_id == enrollment.organization_id, Asset.status != "inactive").first()
    if not organization or not asset:
        raise HTTPException(status_code=409, detail="Ativo ou organização indisponível")
    enrollment.used_at = now
    raw_key = "iais_" + secrets.token_urlsafe(36)
    sensor = SecuritySensor(
        organization_id=enrollment.organization_id, asset_id=enrollment.asset_id, name=enrollment.sensor_name,
        key_prefix=raw_key[:18], key_hash=_hash_key(raw_key), created_by=enrollment.created_by,
        expires_at=now + timedelta(days=365),
    )
    db.add(sensor)
    db.commit()
    return {"key": raw_key, "sensor_name": sensor.name, "asset_name": asset.name, "expires_at": sensor.expires_at.isoformat(), "warning": "A chave foi emitida uma única vez e deve ser armazenada apenas no servidor do ativo."}


@router.get("/installer", include_in_schema=False)
def sensor_installer():
    path = _sensor_installer_path()
    if not path.is_file():
        raise HTTPException(status_code=503, detail="Instalador indisponível")
    return PlainTextResponse(path.read_text(encoding="utf-8"), media_type="text/x-python; charset=utf-8")


@router.get("/sensors")
def list_sensors(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    sensors = db.query(SecuritySensor).filter(SecuritySensor.organization_id == context.organization.id).order_by(SecuritySensor.created_at.desc()).all()
    return {"sensors": [{"id": item.id, "asset_id": item.asset_id, "name": item.name, "key_prefix": item.key_prefix, "last_seen_at": item.last_seen_at.isoformat() if item.last_seen_at else None, "expires_at": item.expires_at.isoformat() if item.expires_at else None, "revoked_at": item.revoked_at.isoformat() if item.revoked_at else None, "containment_enabled": bool(item.containment_enabled), "agent_version": item.agent_version} for item in sensors]}


@router.get("/sensor-actions")
def sensor_actions(
    context: SensorContext = Depends(get_sensor_context),
    capabilities: str = Header(default="", alias="X-Iron-AI-Capabilities"),
    agent_version: str = Header(default="", alias="X-Iron-AI-Agent-Version"),
    db: Session = Depends(get_db),
):
    """Return only typed containment actions assigned to this authenticated sensor."""
    context.sensor.containment_enabled = "host_firewall" in {item.strip() for item in capabilities.split(",")}
    context.sensor.agent_version = agent_version[:40] or context.sensor.agent_version
    now = datetime.utcnow()
    expired = db.query(ContainmentAction).filter(
        ContainmentAction.sensor_id == context.sensor.id,
        ContainmentAction.provider == "host_firewall",
        ContainmentAction.status == "executed",
        ContainmentAction.expires_at.isnot(None),
        ContainmentAction.expires_at <= now,
    ).all()
    for item in expired:
        item.status = "release_pending"
    actions = db.query(ContainmentAction).filter(
        ContainmentAction.sensor_id == context.sensor.id,
        ContainmentAction.organization_id == context.organization.id,
        ContainmentAction.provider == "host_firewall",
        ContainmentAction.status.in_(["approved", "executed", "release_pending"]),
    ).order_by(ContainmentAction.created_at.asc()).limit(20).all()
    db.commit()
    return {"actions": [{
        "id": item.id,
        "operation": "unblock_ip" if item.status == "release_pending" else "block_ip",
        "ip": item.target,
        "duration_seconds": max(60, int((item.expires_at - now).total_seconds())) if item.expires_at and item.status != "release_pending" else None,
        "report_required": item.status != "executed",
    } for item in actions]}


@router.post("/sensor-actions/{action_id}/result")
def report_sensor_action(action_id: int, payload: SensorActionResult, request: Request, context: SensorContext = Depends(get_sensor_context), db: Session = Depends(get_db)):
    action = db.query(ContainmentAction).filter(
        ContainmentAction.id == action_id,
        ContainmentAction.sensor_id == context.sensor.id,
        ContainmentAction.organization_id == context.organization.id,
        ContainmentAction.provider == "host_firewall",
    ).first()
    if not action or action.status not in {"approved", "release_pending"}:
        raise HTTPException(status_code=404, detail="Ação de contenção não encontrada ou já concluída")
    expected = "released" if action.status == "release_pending" else "executed"
    if payload.status not in {expected, "failed"}:
        raise HTTPException(status_code=409, detail="Resultado incompatível com a ação solicitada")
    now = datetime.utcnow()
    was_release = action.status == "release_pending"
    action.status = "release_pending" if payload.status == "failed" and was_release else payload.status
    action.error = payload.detail if payload.status == "failed" else None
    action.response_json = {"firewall_backend": payload.firewall_backend, "detail": payload.detail}
    if payload.status == "executed":
        action.executed_at = now
    elif payload.status == "released":
        action.released_at = now
    event = db.query(SecurityEvent).filter(SecurityEvent.id == action.security_event_id, SecurityEvent.organization_id == context.organization.id).first()
    if event:
        active = db.query(func.count(ContainmentAction.id)).filter(
            ContainmentAction.security_event_id == event.id,
            ContainmentAction.status.in_(["approved", "executed", "release_pending"]),
        ).scalar() or 0
        event.containment_status = "blocked" if payload.status == "executed" or was_release or active > 0 else "not_contained"
    db.add(AuditLog(
        organization_id=context.organization.id,
        action=f"host_firewall_{payload.status}",
        resource_type="containment_action",
        resource_id=str(action.id),
        ip_address=request.client.host if request and request.client else None,
        user_agent=(request.headers.get("user-agent", "")[:512] if request else None),
        metadata_json={"target": action.target, "sensor_id": context.sensor.id, "backend": payload.firewall_backend},
    ))
    db.commit()
    return {"accepted": True, "status": action.status}


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


@router.post("/containment-tests")
def create_containment_test(payload: ContainmentTestCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    """Create a short-lived public link that records only the visitor IP for an approved test."""
    _require_realtime_plan(context.user.subscription_plan)
    asset = db.query(Asset).filter(
        Asset.id == payload.asset_id,
        Asset.organization_id == context.organization.id,
        Asset.status != "inactive",
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado ou inativo")
    if not _containment_ready(db, context.organization.id, asset.id):
        raise HTTPException(status_code=409, detail="Ative o Cloudflare ou o firewall do servidor antes de iniciar o teste")
    raw_token = "ict_" + secrets.token_urlsafe(36)
    item = ContainmentTest(
        organization_id=context.organization.id,
        asset_id=asset.id,
        token_hash=_hash_key(raw_token),
        created_by=context.user.id,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    db.add(item)
    db.flush()
    record_audit(db, context, "containment_test_created", "containment_test", item.id, request, {"asset_id": asset.id})
    db.commit()
    return {
        "id": item.id,
        "path": f"/api/security-monitoring/containment-tests/open/{raw_token}",
        "expires_at": item.expires_at.isoformat(),
    }


@router.get("/containment-tests/status/{test_id}")
def containment_test_status(test_id: int, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    item = db.query(ContainmentTest).filter(
        ContainmentTest.id == test_id,
        ContainmentTest.organization_id == context.organization.id,
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Teste não encontrado")
    return {
        "id": item.id,
        "status": "detected" if item.security_event_id else "expired" if item.expires_at <= datetime.utcnow() else "waiting",
        "source_ip": item.source_ip,
        "event_id": item.security_event_id,
        "expires_at": item.expires_at.isoformat(),
    }


@router.get("/containment-tests/open/{raw_token}", response_class=HTMLResponse, include_in_schema=False)
def open_containment_test(raw_token: str, request: Request, db: Session = Depends(get_db)):
    source_ip = _request_source_ip(request)
    allowed, _, _ = rate_limit_backend.hit(f"containment-test:{source_ip or 'unknown'}", limit=10, window_seconds=60)
    if not allowed:
        return _test_page("Muitas tentativas", "Aguarde um minuto antes de tentar novamente.", success=False, status_code=429)
    if not raw_token.startswith("ict_") or len(raw_token) < 40:
        return _test_page("Link inválido", "Gere um novo teste pela plataforma.", success=False, status_code=404)
    item = db.query(ContainmentTest).filter(ContainmentTest.token_hash == _hash_key(raw_token)).first()
    if not item:
        return _test_page("Link inválido", "Este teste não existe ou já foi removido.", success=False, status_code=404)
    if item.security_event_id:
        return _test_page("Teste recebido", "A conexão já foi identificada com segurança.", success=True)
    if item.expires_at <= datetime.utcnow():
        return _test_page("Link expirado", "O link dura 10 minutos. Gere outro na plataforma.", success=False, status_code=410)
    if not is_blockable_ip(source_ip):
        return _test_page("Conexão não bloqueável", "Abra o link usando um IP público, como o 4G/5G do celular. Endereços internos e de infraestrutura são protegidos.", success=False, status_code=400)
    organization = db.query(Organization).filter(Organization.id == item.organization_id, Organization.status == "active").first()
    asset = db.query(Asset).filter(Asset.id == item.asset_id, Asset.organization_id == item.organization_id, Asset.status != "inactive").first()
    if not organization or not asset or normalize_plan(organization.plan) not in REALTIME_MONITORING_PLANS:
        return _test_page("Teste indisponível", "O ativo ou a assinatura não está disponível para este teste.", success=False, status_code=409)
    detected = classify_telemetry({
        "signal": "reconnaissance",
        "source_ip": source_ip,
        "method": "GET",
        "path": "/iron-ai/assisted-containment-test",
        "status_code": 200,
        "source": "assisted_test",
    })
    event = correlate_event(db, organization.id, asset.id, None, detected)
    event.title = "Teste autorizado de bloqueio"
    event.description = f"Teste autorizado iniciado pelo administrador a partir do IP {source_ip}. Nenhum ataque foi executado."
    event.remediation = "Confira o IP de teste e aprove o bloqueio somente se ele pertencer à conexão usada no teste."
    item.opened_at = datetime.utcnow()
    item.source_ip = source_ip
    item.security_event_id = event.id
    db.add(AuditLog(
        organization_id=organization.id,
        action="containment_test_detected",
        resource_type="containment_test",
        resource_id=str(item.id),
        ip_address=source_ip,
        user_agent=(request.headers.get("user-agent", "")[:512] if request else None),
        metadata_json={"asset_id": asset.id, "security_event_id": event.id},
    ))
    db.commit()
    return _test_page("Teste recebido", "A Iron AI identificou esta conexão. Volte ao painel para conferir o IP e aprovar o bloqueio.", success=True)


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
    host_firewalls = db.query(func.count(SecuritySensor.id)).filter(SecuritySensor.organization_id == context.organization.id, SecuritySensor.revoked_at.is_(None), SecuritySensor.containment_enabled.is_(True), SecuritySensor.last_seen_at >= datetime.utcnow() - timedelta(minutes=5)).scalar() or 0
    active_blocks = db.query(func.count(ContainmentAction.id)).filter(ContainmentAction.organization_id == context.organization.id, ContainmentAction.status == "executed").scalar() or 0
    waf = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == "cloudflare_waf", Integration.status == "connected").first()
    actions = db.query(ContainmentAction).filter(ContainmentAction.organization_id == context.organization.id, ContainmentAction.status.in_(["approved", "executed", "release_pending"])).order_by(ContainmentAction.created_at.asc()).all()
    action_by_event = {item.security_event_id: item for item in actions if item.security_event_id}
    host_firewall_assets = {
        asset_id for (asset_id,) in db.query(SecuritySensor.asset_id).filter(
            SecuritySensor.organization_id == context.organization.id,
            SecuritySensor.revoked_at.is_(None),
            SecuritySensor.containment_enabled.is_(True),
            SecuritySensor.last_seen_at >= datetime.utcnow() - timedelta(minutes=5),
        ).all()
    }
    events = [_event_dict(
        event,
        asset_name,
        action_by_event[event.id].id if event.id in action_by_event else None,
        action_by_event[event.id].provider if event.id in action_by_event else None,
        bool(waf or event.asset_id in host_firewall_assets),
    ) for event, asset_name in rows]
    return {"events": events, "metrics": {"open": open_count, "critical": critical_count, "last_24h": last_24h, "active_sensors": active_sensors, "host_firewalls": host_firewalls, "active_blocks": active_blocks}, "cloudflare_connected": bool(waf), "host_firewall_ready": host_firewalls > 0, "latest_id": max([event["id"] for event in events], default=since_id)}


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
    if not payload.zone_id and not payload.domain:
        raise HTTPException(status_code=422, detail="Informe o domínio protegido ou o Zone ID")
    domain = (payload.domain or "").strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        headers = {"Authorization": f"Bearer {payload.api_token}"}
        if payload.zone_id:
            response = requests.get(f"{CLOUDFLARE_API}/zones/{payload.zone_id}", headers=headers, timeout=12)
        else:
            response = requests.get(f"{CLOUDFLARE_API}/zones", headers=headers, params={"name": domain, "status": "active", "per_page": 1}, timeout=12)
        data = response.json()
    except (requests.RequestException, ValueError) as exc:
        raise HTTPException(status_code=502, detail="Não foi possível validar o Cloudflare") from exc
    if response.status_code >= 300 or not data.get("success"):
        raise HTTPException(status_code=400, detail="Token inválido ou sem permissão de leitura da zona no Cloudflare")
    result = data.get("result") or ([] if not payload.zone_id else {})
    zone = result if payload.zone_id else (result[0] if result else {})
    if not zone.get("id"):
        raise HTTPException(status_code=404, detail="O domínio não foi encontrado entre as zonas ativas permitidas para esse token")
    zone_id = str(zone["id"])
    integration = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == "cloudflare_waf").first()
    if not integration:
        integration = Integration(organization_id=context.organization.id, provider="cloudflare_waf")
        db.add(integration)
        db.flush()
    integration.status = "connected"
    integration.configuration = {"zone_id": zone_id, "zone_name": str(zone.get("name") or domain)[:255]}
    encrypted = _vault().encrypt(payload.api_token)
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id).first()
    if credential:
        credential.encrypted_secret = encrypted
        credential.secret_hint = payload.api_token[-4:]
    else:
        db.add(IntegrationCredential(organization_id=context.organization.id, integration_id=integration.id, encrypted_secret=encrypted, secret_hint=payload.api_token[-4:]))
    record_audit(db, context, "cloudflare_waf_connected", "integration", integration.id, request, {"zone_id": zone_id, "zone_name": zone.get("name") or domain})
    db.commit()
    return {"connected": True, "zone_name": zone.get("name")}


@router.post("/events/{event_id}/contain")
def contain_event(event_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id, SecurityEvent.organization_id == context.organization.id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Evento não encontrado")
    if event.status in {"resolved", "false_positive"}:
        raise HTTPException(status_code=409, detail="Reabra o incidente antes de bloquear a origem")
    if not is_blockable_ip(event.source_ip):
        raise HTTPException(status_code=400, detail="O evento não possui um IP público bloqueável")
    active_actions = db.query(ContainmentAction).filter(
        ContainmentAction.organization_id == context.organization.id,
        ContainmentAction.security_event_id == event.id,
        ContainmentAction.status.in_(["approved", "executed", "release_pending"]),
    ).all()
    existing_providers = {item.provider for item in active_actions}
    integration = db.query(Integration).filter(
        Integration.organization_id == context.organization.id,
        Integration.provider == "cloudflare_waf",
        Integration.status == "connected",
    ).first()
    sensor = db.query(SecuritySensor).filter(
        SecuritySensor.organization_id == context.organization.id,
        SecuritySensor.asset_id == event.asset_id,
        SecuritySensor.revoked_at.is_(None),
        SecuritySensor.containment_enabled.is_(True),
        SecuritySensor.last_seen_at >= datetime.utcnow() - timedelta(minutes=5),
    ).order_by(SecuritySensor.last_seen_at.desc()).first()
    if not integration and not sensor and not active_actions:
        raise HTTPException(status_code=409, detail="Conecte o Cloudflare ou ative o firewall do sensor deste servidor antes de bloquear")

    created = []
    errors = []
    if sensor and "host_firewall" not in existing_providers:
        host_action = ContainmentAction(
            organization_id=context.organization.id, security_event_id=event.id, sensor_id=sensor.id,
            provider="host_firewall", action_type="block_ip", target=event.source_ip,
            status="approved", approved_by=context.user.id,
            expires_at=datetime.utcnow() + timedelta(hours=24),
        )
        db.add(host_action)
        db.flush()
        created.append(host_action)
        record_audit(db, context, "host_firewall_block_approved", "containment_action", host_action.id, request, {"source_ip": event.source_ip, "sensor_id": sensor.id, "duration_hours": 24})

    if integration and "cloudflare" not in existing_providers:
        cloudflare_action = ContainmentAction(organization_id=context.organization.id, security_event_id=event.id, provider="cloudflare", action_type="block_ip", target=event.source_ip, approved_by=context.user.id)
        db.add(cloudflare_action)
        db.flush()
        try:
            _, token = _cloudflare_connection(db, context.organization.id)
            zone_id = (integration.configuration or {}).get("zone_id")
            response = requests.post(
                f"{CLOUDFLARE_API}/zones/{zone_id}/firewall/access_rules/rules",
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"mode": "block", "configuration": {"target": "ip", "value": event.source_ip}, "notes": f"Iron AI event {event.id}"}, timeout=12,
            )
            data = response.json()
            if response.status_code >= 300 or not data.get("success"):
                raise ValueError(str(data.get("errors") or "Cloudflare rejeitou a regra"))
            result = data.get("result") or {}
            cloudflare_action.status = "executed"; cloudflare_action.external_id = result.get("id"); cloudflare_action.executed_at = datetime.utcnow(); cloudflare_action.response_json = {"mode": result.get("mode"), "scope": result.get("scope")}
            created.append(cloudflare_action)
            record_audit(db, context, "attack_source_blocked", "security_event", event.id, request, {"source_ip": event.source_ip, "provider": "cloudflare", "action_id": cloudflare_action.id})
        except (requests.RequestException, ValueError) as exc:
            cloudflare_action.status = "failed"; cloudflare_action.error = str(exc)[:2000]
            errors.append("Cloudflare não confirmou o bloqueio")

    all_actions = active_actions + created
    if not all_actions and errors:
        db.commit()
        raise HTTPException(status_code=502, detail=errors[0])
    event.containment_status = "blocked" if any(item.status == "executed" for item in all_actions) else "pending"
    db.commit()
    primary = next((item for item in reversed(all_actions) if item.status == "executed"), all_actions[-1])
    return {
        "success": True, "action_id": primary.id, "status": primary.status, "source_ip": event.source_ip,
        "already_contained": not created and bool(active_actions),
        "coverage": [{"provider": item.provider, "status": item.status, "action_id": item.id} for item in all_actions],
        "warnings": errors,
    }


@router.post("/containment/manual")
def manual_containment(payload: ManualContainmentCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    """Create an auditable operator-requested event and apply the normal approved containment path."""
    _require_realtime_plan(context.user.subscription_plan)
    source_ip = safe_source_ip(payload.ip_address)
    if not is_blockable_ip(source_ip):
        raise HTTPException(status_code=400, detail="Informe um IP público válido. IPs privados, reservados e redes de infraestrutura não podem ser bloqueados")
    asset = db.query(Asset).filter(
        Asset.id == payload.asset_id,
        Asset.organization_id == context.organization.id,
        Asset.status != "inactive",
    ).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Ativo não encontrado ou inativo")
    if not _containment_ready(db, context.organization.id, asset.id):
        raise HTTPException(status_code=409, detail="Ative o Cloudflare ou o firewall do servidor antes de bloquear")
    detected = classify_telemetry({
        "signal": "unauthorized_access",
        "source_ip": source_ip,
        "request_count": 1,
        "source": "manual_approval",
    })
    event = correlate_event(db, context.organization.id, asset.id, None, detected)
    event.title = "Bloqueio manual aprovado"
    event.description = f"Bloqueio solicitado por {context.user.username}: {payload.reason.strip()}"
    event.remediation = "Revise a evidência e remova o bloqueio quando a origem deixar de representar risco."
    event.evidence_json = {"source": "manual_approval", "reason": payload.reason.strip(), "requested_by": context.user.id}
    record_audit(db, context, "manual_containment_requested", "security_event", event.id, request, {"asset_id": asset.id, "source_ip": source_ip, "reason": payload.reason.strip()})
    db.flush()
    result = contain_event(event.id, request=request, context=context, db=db)
    return {**result, "event_id": event.id}


@router.delete("/containment/{action_id}")
def release_containment(action_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    _require_realtime_plan(context.user.subscription_plan)
    action = db.query(ContainmentAction).filter(ContainmentAction.id == action_id, ContainmentAction.organization_id == context.organization.id, ContainmentAction.status == "executed").first()
    if not action:
        raise HTTPException(status_code=404, detail="Bloqueio ativo não encontrado")
    if action.provider == "host_firewall":
        action.status = "release_pending"
        record_audit(db, context, "host_firewall_release_approved", "containment_action", action.id, request, {"source_ip": action.target, "sensor_id": action.sensor_id})
        db.commit()
        return {"released": False, "status": "release_pending", "message": "Remoção enviada ao sensor"}
    if not action.external_id:
        raise HTTPException(status_code=404, detail="Identificador do bloqueio no Cloudflare não encontrado")
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
    if event:
        remaining = db.query(func.count(ContainmentAction.id)).filter(ContainmentAction.security_event_id == event.id, ContainmentAction.id != action.id, ContainmentAction.status.in_(["approved", "executed", "release_pending"])).scalar() or 0
        event.containment_status = "blocked" if remaining else "released"
    record_audit(db, context, "attack_source_unblocked", "containment_action", action.id, request, {"source_ip": action.target, "provider": "cloudflare"})
    db.commit()
    return {"released": True}


@router.delete("/events/{event_id}/containment")
def release_event_containment(event_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    """Remove every active blocking layer for an event with one human confirmation."""
    _require_realtime_plan(context.user.subscription_plan)
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id,
        SecurityEvent.organization_id == context.organization.id,
    ).first()
    if not event:
        raise HTTPException(status_code=404, detail="Incidente não encontrado")
    actions = db.query(ContainmentAction).filter(
        ContainmentAction.organization_id == context.organization.id,
        ContainmentAction.security_event_id == event.id,
        ContainmentAction.status.in_(["approved", "executed"]),
    ).order_by(ContainmentAction.created_at.asc()).all()
    if not actions:
        raise HTTPException(status_code=404, detail="Nenhuma camada de bloqueio ativa foi encontrada")
    results = []
    errors = []
    for action in actions:
        if action.provider == "host_firewall" and action.status == "approved":
            action.status = "released"
            action.released_at = datetime.utcnow()
            record_audit(db, context, "host_firewall_pending_block_cancelled", "containment_action", action.id, request, {"source_ip": action.target, "sensor_id": action.sensor_id})
            db.commit()
            results.append({"provider": action.provider, "status": "released"})
            continue
        try:
            result = release_containment(action.id, request=request, context=context, db=db)
            results.append({"provider": action.provider, "status": result["status"]})
        except HTTPException as exc:
            errors.append(f"{action.provider}: {exc.detail}")
    if not results:
        raise HTTPException(status_code=502, detail="Não foi possível remover as camadas de bloqueio")
    remaining = db.query(func.count(ContainmentAction.id)).filter(
        ContainmentAction.organization_id == context.organization.id,
        ContainmentAction.security_event_id == event.id,
        ContainmentAction.status.in_(["approved", "executed", "release_pending"]),
    ).scalar() or 0
    event.containment_status = "blocked" if remaining else "released"
    db.commit()
    pending = any(item["status"] == "release_pending" for item in results)
    return {"released": not errors and not pending, "pending": pending, "layers": results, "warnings": errors}
