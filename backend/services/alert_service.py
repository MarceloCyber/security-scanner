"""Durable, non-blocking security alert delivery."""

from datetime import datetime
import re

import requests
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from models.saas import SecurityAlertDelivery, SecurityAlertSubscription, SecurityEvent, SiemAlertDelivery, SiemIncident
from services.credential_vault import CredentialVault
from utils.email_service import email_service

SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ALLOWED_CHANNELS = {"email", "slack", "teams", "pagerduty"}
ALLOWED_SEVERITIES = set(SEVERITY_RANK)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_target(channel: str, target: str) -> str:
    value = target.strip()
    if channel == "email" and not EMAIL_RE.match(value):
        raise ValueError("Informe um e-mail válido")
    if channel in {"slack", "teams"} and not value.startswith("https://"):
        raise ValueError("O webhook precisa usar HTTPS")
    if channel == "pagerduty" and not 20 <= len(value) <= 300:
        raise ValueError("Informe uma routing key válida do PagerDuty")
    if channel not in ALLOWED_CHANNELS:
        raise ValueError("Canal de alerta não permitido")
    return value


def _vault() -> CredentialVault:
    return CredentialVault()


def queue_security_alerts(db: Session, event: SecurityEvent) -> int:
    queued = 0
    subscriptions = db.query(SecurityAlertSubscription).filter(
        SecurityAlertSubscription.organization_id == event.organization_id,
        SecurityAlertSubscription.enabled.is_(True),
    ).all()
    for subscription in subscriptions:
        if SEVERITY_RANK.get(event.severity, 0) < SEVERITY_RANK.get(subscription.minimum_severity, 3):
            continue
        dedupe_key = f"event:{event.id}:{event.occurrence_count}"
        existing = db.query(SecurityAlertDelivery.id).filter(
            SecurityAlertDelivery.subscription_id == subscription.id,
            SecurityAlertDelivery.dedupe_key == dedupe_key,
        ).first()
        if existing:
            continue
        delivery = SecurityAlertDelivery(
            organization_id=event.organization_id,
            subscription_id=subscription.id,
            security_event_id=event.id,
            dedupe_key=dedupe_key,
            status="queued",
        )
        db.add(delivery)
        try:
            with db.begin_nested():
                db.flush()
            queued += 1
        except IntegrityError:
            continue
    return queued


def _event_payload(db: Session, delivery: SecurityAlertDelivery) -> dict:
    event = db.query(SecurityEvent).filter(SecurityEvent.id == delivery.security_event_id).first()
    if not event:
        raise ValueError("Evento de segurança não encontrado")
    return {
        "id": event.id,
        "severity": event.severity,
        "title": event.title,
        "description": event.description,
        "source_ip": event.source_ip,
        "path": event.request_path,
        "request_count": event.request_count,
        "detected_at": event.last_seen_at.isoformat(),
    }


def _send(subscription: SecurityAlertSubscription, payload: dict) -> None:
    target = _vault().decrypt(subscription.target_encrypted)
    title = f"Iron AI · {payload['severity'].upper()} · {payload['title']}"
    text = f"{payload['description']}\nIP: {payload['source_ip'] or 'não informado'}\nCaminho: {payload['path'] or 'não informado'}\nEvento: #{payload['id']}"
    if subscription.channel == "email":
        if not email_service.send_email(target, title, f"<h2>{payload['title']}</h2><p>{payload['description']}</p><p>IP: {payload['source_ip'] or 'não informado'}<br>Evento: #{payload['id']}</p>", text):
            raise RuntimeError("SMTP não confirmou o envio")
    elif subscription.channel == "pagerduty":
        response = requests.post("https://events.pagerduty.com/v2/enqueue", json={"routing_key": target, "event_action": "trigger", "payload": {"summary": title, "source": "iron-ai", "severity": "critical" if payload["severity"] == "critical" else "error", "custom_details": payload}}, timeout=12)
        if response.status_code >= 300:
            raise RuntimeError("PagerDuty rejeitou o alerta")
    else:
        body = {"text": f"**{title}**\n{text}"} if subscription.channel == "teams" else {"text": f"*{title}*\n{text}"}
        response = requests.post(target, json=body, timeout=12)
        if response.status_code >= 300:
            raise RuntimeError(f"Webhook {subscription.channel} rejeitou o alerta")


def deliver_pending_alerts(db: Session, limit: int = 20) -> int:
    deliveries = db.query(SecurityAlertDelivery).filter(
        SecurityAlertDelivery.status.in_(["queued", "retry"]),
        SecurityAlertDelivery.attempts < 5,
    ).order_by(SecurityAlertDelivery.created_at.asc()).limit(limit).all()
    sent = 0
    for delivery in deliveries:
        subscription = db.query(SecurityAlertSubscription).filter(SecurityAlertSubscription.id == delivery.subscription_id, SecurityAlertSubscription.enabled.is_(True)).first()
        if not subscription:
            delivery.status = "failed"
            delivery.error = "Assinatura desativada"
            continue
        delivery.attempts += 1
        try:
            _send(subscription, _event_payload(db, delivery))
            delivery.status = "sent"
            delivery.sent_at = datetime.utcnow()
            subscription.last_sent_at = delivery.sent_at
            subscription.last_error = None
            sent += 1
        except Exception as exc:
            delivery.status = "retry" if delivery.attempts < 5 else "failed"
            delivery.error = str(exc)[:1000]
            subscription.last_error = delivery.error
    db.commit()
    return sent


def deliver_pending_siem_alerts(db: Session, limit: int = 20) -> int:
    """Deliver native SIEM incidents through the same configured channels."""
    deliveries = db.query(SiemAlertDelivery).filter(SiemAlertDelivery.status == "queued", SiemAlertDelivery.attempts < 5).order_by(SiemAlertDelivery.created_at.asc()).limit(limit).all()
    sent = 0
    for delivery in deliveries:
        subscription = db.query(SecurityAlertSubscription).filter(SecurityAlertSubscription.id == delivery.subscription_id, SecurityAlertSubscription.enabled.is_(True)).first()
        incident = db.query(SiemIncident).filter(SiemIncident.id == delivery.incident_id).first()
        if not subscription or not incident:
            delivery.status = "failed"; delivery.error = "Assinatura ou incidente indisponível"; continue
        delivery.attempts += 1
        payload = {"id": incident.id, "severity": incident.severity, "title": incident.title, "description": incident.description,
                   "source_ip": "não informado", "path": "SIEM", "request_count": 1, "detected_at": incident.last_seen_at.isoformat()}
        try:
            _send(subscription, payload)
            delivery.status = "sent"; delivery.sent_at = datetime.utcnow(); subscription.last_sent_at = delivery.sent_at; subscription.last_error = None; sent += 1
        except Exception as exc:
            delivery.status = "retry" if delivery.attempts < 5 else "failed"; delivery.error = str(exc)[:1000]; subscription.last_error = delivery.error
    db.commit()
    return sent
