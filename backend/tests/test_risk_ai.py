from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ai.service import IronAIService
from database import Base
from models.saas import Asset, Finding, Organization, OrganizationMember
from models.user import User
from risk.engine import calculate_finding_risk, organization_security_score
from services.tenant import TenantContext


def _context():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    user = User(username="ai-user", email="ai-user@example.com", hashed_password="not-used")
    db.add(user)
    db.flush()
    org = Organization(name="AI Org", slug="ai-org")
    db.add(org)
    db.flush()
    membership = OrganizationMember(organization_id=org.id, user_id=user.id, role="analyst")
    db.add(membership)
    db.commit()
    return db, TenantContext(user=user, organization=org, membership=membership)


def test_risk_score_is_deterministic_and_exposure_increases_it():
    db, context = _context()
    internal = Asset(organization_id=context.organization.id, type="server", name="internal", criticality="high", internet_exposed=False)
    external = Asset(organization_id=context.organization.id, type="server", name="external", criticality="high", internet_exposed=True)
    db.add_all([internal, external])
    db.flush()
    first = Finding(organization_id=context.organization.id, asset_id=internal.id, fingerprint="a", title="test", severity="high", confidence="confirmed", first_seen_at=datetime.utcnow() - timedelta(days=60))
    second = Finding(organization_id=context.organization.id, asset_id=external.id, fingerprint="b", title="test", severity="high", confidence="confirmed", first_seen_at=first.first_seen_at)
    db.add_all([first, second])
    db.flush()
    score_a, factors_a = calculate_finding_risk(first, internal)
    score_b, factors_b = calculate_finding_risk(second, external)
    assert score_b > score_a
    assert factors_b["internet_exposure"] > factors_a["internet_exposure"]
    assert calculate_finding_risk(second, external) == (score_b, factors_b)


def test_iron_ai_only_uses_current_tenant_facts():
    db, context = _context()
    db.add(Finding(organization_id=context.organization.id, fingerprint="only-this-tenant", title="Exposed API", severity="high", risk_score=75, remediation="Restrict access"))
    db.commit()
    response = IronAIService().answer(db, context, "Qual meu maior risco?")
    assert "Exposed API" not in response["summary"]
    assert response["facts"]["findings"][0]["title"] == "Exposed API"
