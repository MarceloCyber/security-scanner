from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models.saas import Asset, Organization, SecurityEvent, SiemIncident, SiemRule
from routes.siem_routes import _matches, _validate_conditions
from services.siem_service import mirror_security_event


def test_siem_rule_matches_nested_payload_and_all_conditions():
    conditions = _validate_conditions({"all": [
        {"field": "event_type", "operator": "equals", "value": "authentication"},
        {"field": "outcome", "operator": "equals", "value": "failure"},
        {"field": "payload.failed_attempts", "operator": "gte", "value": 5},
    ]})
    assert _matches({"event_type": "authentication", "outcome": "failure", "payload": {"failed_attempts": 7}}, conditions)
    assert not _matches({"event_type": "authentication", "outcome": "success", "payload": {"failed_attempts": 7}}, conditions)


def test_siem_rule_validation_rejects_unsupported_fields():
    try:
        _validate_conditions({"all": [{"field": "command", "operator": "equals", "value": "rm"}]})
    except Exception as error:
        assert "Condição" in str(error.detail)
    else:
        raise AssertionError("unsupported SIEM condition was accepted")


def test_real_monitoring_event_is_mirrored_and_opens_siem_incident():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    organization = Organization(name="SIEM Org", slug="siem-org")
    db.add(organization)
    db.flush()
    asset = Asset(organization_id=organization.id, type="domain", name="app.example")
    db.add(asset)
    db.flush()
    db.add(SiemRule(organization_id=organization.id, name="Falha real", severity="high", conditions={"all": [{"field": "event_type", "operator": "equals", "value": "web_scan"}]}))
    event = SecurityEvent(organization_id=organization.id, asset_id=asset.id, fingerprint="real-event", event_type="web_scan", severity="high", title="Scan detectado", description="Telemetria real", remediation="Investigar", last_seen_at=datetime.utcnow())
    db.add(event)
    db.commit()
    mirrored = mirror_security_event(db, event)
    db.commit()
    assert mirrored.id is not None
    assert mirrored.matched_rule_ids
    assert db.query(SiemIncident).filter(SiemIncident.organization_id == organization.id).count() == 1
