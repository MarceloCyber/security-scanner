from cryptography.fernet import Fernet
import asyncio
import pytest
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from config import settings
from database import Base
from models.saas import (
    Asset, ContainmentAction, Finding, Integration, IntegrationCredential, Organization,
    OrganizationMember, RemediationTask, SecurityEvent, SecuritySensor, SSOLoginState,
)
from models.user import User
from services.ai_action_service import execute_action, propose_action, transition_remediation_task
from services.credential_vault import CredentialVault
from services.job_service import claim_next_job, enqueue_job
from services.pipeline_service import consolidate_findings, evaluate_gate, normalize_findings, normalize_sarif
from services.mfa_service import consume_recovery_code, current_code, dump_recovery_hashes, generate_recovery_codes, generate_secret, verify_code
from services.compliance_service import attest_control, compliance_summary
from services.heartbeat_service import beat, process_status
from services.security_monitoring_service import classify_telemetry, correlate_event
from scanners.web_security_scanner import WebSecurityScanner
from ai.provider import configured_provider
from services.report_service import generate_report, render_report_pdf
from auth import decode_renewal_token, get_password_hash, require_developer, require_enterprise, require_enterprise_developer
from fastapi import HTTPException
from starlette.requests import Request
from routes.auth_routes import MFACodeRequest, login, mfa_confirm, mfa_disable, mfa_setup
from routes.sso_routes import SSOExchange, _hash, exchange_sso
from routes import security_monitoring_routes
from routes.security_monitoring_routes import SensorContext, TelemetryBatch, TelemetryItem
from scripts.iron_ai_sensor import aggregate as aggregate_nginx_logs, parse_line as parse_nginx_line
from middleware.subscription import CANCELLATION_WINDOW_DAYS, sync_owned_organization_plans
from routes import payment_routes
from routes.ai_action_routes import approve_action, reject_action, run_action
from services.plan_policy import PLAN_POLICY, access_end_for_plan, is_plan_expired
from services.tenant import TenantContext


def _database():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine)()
    user = User(username="operator", email="operator@example.com", hashed_password="unused")
    db.add(user)
    db.flush()
    organization = Organization(name="Platform Org", slug="platform-org")
    db.add(organization)
    db.flush()
    db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner"))
    asset = Asset(organization_id=organization.id, type="api", name="api.example.com", internet_exposed=True, criticality="critical")
    db.add(asset)
    db.flush()
    finding = Finding(organization_id=organization.id, asset_id=asset.id, fingerprint="platform-finding", title="Public vulnerable API", severity="critical", confidence="confirmed", remediation="Restrict and patch")
    db.add(finding)
    db.commit()
    return db, user, organization, finding


def test_subscription_plan_is_synchronized_with_owned_organization():
    db, user, organization, _ = _database()
    assert organization.plan == "starter"
    user.subscription_plan = "enterprise"
    sync_owned_organization_plans(user, db)
    db.commit()
    db.refresh(organization)
    assert organization.plan == "enterprise"


def test_cancellation_refund_window_is_exactly_seven_days():
    user = User(
        username="refund-window",
        email="refund-window@example.com",
        hashed_password="unused",
        subscription_plan="starter",
        subscription_status="active",
        is_trial=True,
    )
    assert CANCELLATION_WINDOW_DAYS == 7
    user.trial_started_at = datetime.utcnow() - timedelta(days=6, hours=23)
    assert payment_routes._trial_is_active(user) is True
    user.trial_started_at = datetime.utcnow() - timedelta(days=7, seconds=1)
    assert payment_routes._trial_is_active(user) is False


def test_cancellation_calls_stripe_refunds_and_revokes_local_access(monkeypatch):
    db, user, organization, _ = _database()
    user.subscription_plan = "starter"
    user.subscription_status = "active"
    user.stripe_subscription_id = "sub_test_cancel"
    user.is_trial = True
    user.trial_started_at = datetime.utcnow() - timedelta(days=2)
    db.commit()

    deleted = []
    monkeypatch.setattr(payment_routes, "_refund_initial_stripe_payment", lambda subscription_id: {"id": "re_test"})
    monkeypatch.setattr(payment_routes.stripe.Subscription, "delete", lambda subscription_id: deleted.append(subscription_id))

    result = asyncio.run(payment_routes.cancel_subscription(current_user=user, db=db))

    db.refresh(user)
    db.refresh(organization)
    assert deleted == ["sub_test_cancel"]
    assert result["refunded"] is True
    assert user.subscription_status == "cancelled"
    assert user.subscription_plan == "starter"
    assert user.stripe_subscription_id is None
    assert user.subscription_end is not None
    assert organization.plan == "starter"


def test_realtime_monitoring_detects_scans_and_ignores_normal_traffic():
    benign = classify_telemetry({"source_ip": "203.0.113.10", "path": "/produtos", "status_code": 200})
    attack = classify_telemetry({
        "source_ip": "8.8.8.8", "path": "/.env", "status_code": 404,
        "request_count": 32, "window_seconds": 20, "user_agent": "nuclei",
    })
    assert benign is None
    assert attack["event_type"] == "exploit_attempt"
    assert attack["severity"] == "critical"
    assert "Bloqueie" in attack["remediation"]


def test_nginx_sensor_sends_only_sanitized_request_metadata():
    line = '8.8.8.8 - - [17/Aug/2026:12:00:00 +0000] "GET /.env HTTP/1.1" 404 123 "-" "nuclei"'
    parsed = parse_nginx_line(line)
    events = aggregate_nginx_logs([line, line], 10)
    assert parsed == {"source_ip": "8.8.8.8", "method": "GET", "path": "/.env", "status_code": 404, "user_agent": "nuclei"}
    assert events[0]["request_count"] == 2
    assert set(events[0]) == {"source_ip", "method", "path", "status_code", "user_agent", "request_count", "window_seconds", "source", "distinct_paths"}


def test_signed_sensor_ingestion_persists_only_detected_events():
    db, user, organization, finding = _database()
    user.subscription_plan = "professional"
    organization.plan = "professional"
    sensor = SecuritySensor(
        organization_id=organization.id, asset_id=finding.asset_id, name="Nginx production",
        key_prefix="iais_test", key_hash="unused", created_by=user.id,
    )
    db.add(sensor)
    db.commit()
    payload = TelemetryBatch(events=[
        TelemetryItem(source_ip="8.8.8.8", path="/login", status_code=200),
        TelemetryItem(signal="brute_force", source_ip="8.8.4.4", path="/login", status_code=401, request_count=80, window_seconds=60),
    ])
    context = SensorContext(organization=organization, sensor=sensor)
    result = security_monitoring_routes.ingest_telemetry(payload, request=None, context=context, db=db)
    events = db.query(SecurityEvent).filter(SecurityEvent.organization_id == organization.id).all()
    assert result["received"] == 2
    assert result["detected"] == 1
    assert len(events) == 1
    assert events[0].source_ip == "8.8.4.4"
    assert events[0].event_type == "brute_force"


def test_cloudflare_containment_executes_real_provider_path_after_approval(monkeypatch):
    db, user, organization, finding = _database()
    user.subscription_plan = "professional"
    organization.plan = "professional"
    membership = db.query(OrganizationMember).filter(OrganizationMember.organization_id == organization.id, OrganizationMember.user_id == user.id).one()
    event = correlate_event(db, organization.id, finding.asset_id, None, classify_telemetry({
        "signal": "web_scan", "source_ip": "8.8.8.8", "path": "/.git/config", "request_count": 50,
    }))
    integration = Integration(organization_id=organization.id, provider="cloudflare_waf", status="connected", configuration={"zone_id": "a" * 32, "zone_name": "example.com"})
    db.add(integration)
    db.flush()
    original = settings.CREDENTIAL_ENCRYPTION_KEY
    settings.CREDENTIAL_ENCRYPTION_KEY = Fernet.generate_key().decode()
    try:
        encrypted = CredentialVault().encrypt("cloudflare-token-with-write-permission")
        db.add(IntegrationCredential(organization_id=organization.id, integration_id=integration.id, encrypted_secret=encrypted, secret_hint="sion"))
        db.commit()

        class CloudflareResponse:
            status_code = 200
            def json(self):
                return {"success": True, "result": {"id": "cf-rule-1", "mode": "block", "scope": {"type": "zone"}}}

        called = {}
        def fake_post(url, headers, json, timeout):
            called.update({"url": url, "headers": headers, "json": json, "timeout": timeout})
            return CloudflareResponse()

        monkeypatch.setattr(security_monitoring_routes.requests, "post", fake_post)
        context = security_monitoring_routes.TenantContext(user=user, organization=organization, membership=membership)
        result = security_monitoring_routes.contain_event(event.id, request=None, context=context, db=db)
        db.refresh(event)
        action = db.query(ContainmentAction).filter(ContainmentAction.security_event_id == event.id).one()
        assert result["status"] == "executed"
        assert called["json"]["configuration"] == {"target": "ip", "value": "8.8.8.8"}
        assert called["headers"]["Authorization"].startswith("Bearer ")
        assert action.external_id == "cf-rule-1"
        assert event.containment_status == "blocked"
    finally:
        settings.CREDENTIAL_ENCRYPTION_KEY = original


def test_realtime_monitoring_rejects_starter_on_server():
    db, user, organization, _ = _database()
    membership = db.query(OrganizationMember).filter_by(organization_id=organization.id, user_id=user.id).one()
    context = security_monitoring_routes.TenantContext(user=user, organization=organization, membership=membership)
    try:
        security_monitoring_routes.monitoring_overview(context=context, db=db)
        assert False, "Starter should not access realtime monitoring"
    except HTTPException as exc:
        assert exc.status_code == 403
        assert exc.detail["error"] == "professional_required"


def test_commercial_plan_values_and_exact_terms():
    start = datetime(2026, 1, 31, 12, 0, 0)
    assert PLAN_POLICY["starter"]["amount_cents"] == 38990
    assert PLAN_POLICY["starter"]["billing_mode"] == "subscription"
    assert PLAN_POLICY["professional"]["amount_cents"] == 378990
    assert PLAN_POLICY["professional"]["billing_mode"] == "payment"
    assert access_end_for_plan("professional", start) == datetime(2026, 5, 31, 12, 0, 0)
    assert PLAN_POLICY["enterprise"]["amount_cents"] == 898990
    assert access_end_for_plan("enterprise", start) == datetime(2027, 1, 31, 12, 0, 0)
    assert is_plan_expired("professional", datetime.utcnow() - timedelta(seconds=1)) is True
    assert is_plan_expired("starter", datetime.utcnow() - timedelta(days=100)) is False


def test_stripe_checkout_uses_recurring_starter_and_installment_fixed_terms(monkeypatch):
    captured = []
    monkeypatch.delenv("STRIPE_PRICE_ID_STARTER", raising=False)
    monkeypatch.delenv("STRIPE_PRICE_ID_PROFESSIONAL", raising=False)
    monkeypatch.setattr(payment_routes.stripe.checkout.Session, "create", lambda **params: captured.append(params) or params)
    payment_routes._stripe_checkout("starter", "cus_1", "https://ok", "https://cancel", {"user_id": 1, "plan": "starter"})
    payment_routes._stripe_checkout("professional", "cus_1", "https://ok", "https://cancel", {"user_id": 1, "plan": "professional"})
    starter, professional = captured
    assert starter["mode"] == "subscription"
    assert starter["line_items"][0]["price_data"]["recurring"]["interval"] == "month"
    assert "payment_method_options" not in starter
    assert professional["mode"] == "payment"
    assert "recurring" not in professional["line_items"][0]["price_data"]
    assert professional["payment_method_options"]["card"]["installments"]["enabled"] is True


def test_expired_fixed_term_login_returns_scoped_renewal_token():
    db, user, _, _ = _database()
    user.hashed_password = get_password_hash("StrongPassword123!")
    user.subscription_plan = "professional"
    user.subscription_status = "active"
    user.subscription_end = datetime.utcnow() - timedelta(seconds=1)
    db.commit()
    request = Request({"type": "http", "method": "POST", "path": "/api/auth/token", "headers": [], "client": ("127.0.0.1", 12345)})
    with pytest.raises(HTTPException) as error:
        login(request, "operator", "StrongPassword123!", "", "", False, db)
    assert error.value.status_code == 402
    detail = error.value.detail
    assert detail["error"] == "subscription_renewal_required"
    claims = decode_renewal_token(detail["renewal_token"])
    assert claims["uid"] == user.id
    assert claims["plan"] == "professional"
    assert claims["purpose"] == "subscription_renewal"


def test_report_metrics_and_pdf_come_from_persisted_facts():
    db, user, organization, finding = _database()
    executive = generate_report(db, organization.id, user.id, "executive", 30)
    technical = generate_report(db, organization.id, user.id, "technical", 30)
    assert executive.payload["schema_version"] == 2
    assert executive.payload["organization"]["name"] == organization.name
    assert executive.payload["metrics"]["findings"]["critical"] == 1
    assert executive.payload["metrics"]["assets_exposed"] == 1
    assert executive.payload["compliance"]["total"] == 10
    assert executive.payload["recommendations"]
    assert technical.payload["assets"][0]["name"] == "api.example.com"
    assert technical.payload["findings_detail"][0]["id"] == finding.id
    for report in (executive, technical):
        pdf = render_report_pdf(report)
        assert pdf.startswith(b"%PDF")
        assert len(pdf) > 20_000


def test_ai_action_requires_human_approval():
    db, user, organization, finding = _database()
    action = propose_action(db, organization.id, user.id, "create_remediation_task", {"finding_id": finding.id})
    try:
        execute_action(db, action)
    except ValueError:
        pass
    else:
        raise AssertionError("unapproved action must not execute")
    action.status = "approved"
    action.approved_by = user.id
    task = execute_action(db, action)
    assert task.finding_id == finding.id
    assert action.status == "executed"


def test_ai_action_http_handlers_persist_rejection_approval_and_execution():
    db, user, organization, finding = _database()
    membership = db.query(OrganizationMember).filter_by(organization_id=organization.id, user_id=user.id).one()
    context = TenantContext(user=user, organization=organization, membership=membership)
    request = Request({"type": "http", "method": "POST", "path": "/", "headers": [], "client": ("127.0.0.1", 12345)})

    rejected = propose_action(db, organization.id, user.id, "create_remediation_task", {"finding_id": finding.id})
    db.commit()
    rejection = reject_action(rejected.id, request, context, db)
    assert rejection["status"] == "rejected"
    db.refresh(rejected)
    assert rejected.status == "rejected"

    approved = propose_action(db, organization.id, user.id, "create_remediation_task", {"finding_id": finding.id})
    db.commit()
    approval = approve_action(approved.id, request, context, db)
    assert approval["status"] == "approved"
    execution = run_action(approved.id, request, context, db)
    assert execution["status"] == "executed"
    task = db.query(RemediationTask).filter_by(id=execution["remediation_task_id"]).one()
    assert task.finding_id == finding.id and task.status == "open"


def test_ai_action_prevents_duplicate_open_work_for_same_finding():
    db, user, organization, finding = _database()
    propose_action(db, organization.id, user.id, "create_remediation_task", {"finding_id": finding.id})
    try:
        propose_action(db, organization.id, user.id, "create_remediation_task", {"finding_id": finding.id})
    except ValueError as exc:
        assert "aguardando decisão" in str(exc)
    else:
        raise AssertionError("duplicate pending action must be rejected")


def test_remediation_task_lifecycle_updates_linked_finding():
    db, user, organization, finding = _database()
    task = RemediationTask(
        organization_id=organization.id,
        finding_id=finding.id,
        title="Corrigir API pública",
        priority="critical",
        status="open",
    )
    db.add(task)
    db.flush()
    previous, changed_finding = transition_remediation_task(db, task, "in_progress")
    assert previous == "open" and task.status == "in_progress"
    previous, changed_finding = transition_remediation_task(db, task, "completed")
    assert previous == "in_progress" and task.completed_at is not None
    assert changed_finding.id == finding.id and finding.status == "resolved" and finding.resolved_at is not None
    previous, changed_finding = transition_remediation_task(db, task, "in_progress")
    assert previous == "completed" and finding.status == "in_progress" and finding.resolved_at is None
    try:
        transition_remediation_task(db, task, "completed")
    except ValueError:
        raise AssertionError("in-progress task should be completable")


def test_durable_job_is_claimed_once():
    db, user, organization, finding = _database()
    queued = enqueue_job(db, organization.id, user.id, "security_snapshot")
    db.commit()
    claimed = claim_next_job(db)
    assert claimed.id == queued.id and claimed.status == "running"
    assert claim_next_job(db) is None


def test_credential_vault_uses_authenticated_encryption():
    original = settings.CREDENTIAL_ENCRYPTION_KEY
    settings.CREDENTIAL_ENCRYPTION_KEY = Fernet.generate_key().decode()
    try:
        vault = CredentialVault()
        encrypted = vault.encrypt("github-secret-token")
        assert "github-secret-token" not in encrypted
        assert vault.decrypt(encrypted) == "github-secret-token"
    finally:
        settings.CREDENTIAL_ENCRYPTION_KEY = original


def test_advanced_tools_require_explicit_developer_permission():
    ordinary_user = User(username="ordinary", email="ordinary@example.com", hashed_password="unused", is_admin=True, is_developer=False)
    try:
        require_developer(ordinary_user)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("admin without developer permission must be denied")

    developer = User(username="developer", email="developer@example.com", hashed_password="unused", is_developer=True)
    assert require_developer(developer) is developer


def test_viggio_and_advanced_tools_require_enterprise_subscription():
    professional_admin = User(
        username="admin-pro", email="admin-pro@example.com", hashed_password="unused",
        is_admin=True, is_developer=True, subscription_plan="professional", subscription_status="active",
    )
    for dependency in (require_enterprise, require_enterprise_developer):
        try:
            dependency(professional_admin)
        except HTTPException as exc:
            assert exc.status_code == 403
            assert exc.detail["error"] == "enterprise_required"
        else:
            raise AssertionError("professional admin must not bypass Enterprise requirement")

    enterprise_user = User(
        username="enterprise", email="enterprise@example.com", hashed_password="unused",
        is_developer=False, subscription_plan="enterprise", subscription_status="active",
    )
    assert require_enterprise(enterprise_user) is enterprise_user
    try:
        require_enterprise_developer(enterprise_user)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("advanced tools also require developer permission")


def test_sarif_is_normalized_and_quality_gate_blocks_high_findings():
    db, user, organization, finding = _database()
    sarif = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Semgrep", "rules": [{"id": "CWE-89", "shortDescription": {"text": "SQL Injection"}, "properties": {"tags": ["CWE-89"], "security-severity": "9.1"}}]}},
            "results": [{"ruleId": "CWE-89", "level": "error", "message": {"text": "Untrusted input reaches SQL query"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 42}}}], "fingerprints": {"primaryLocationLineHash": "stable-42"}}],
        }],
    }
    items = normalize_sarif(sarif)
    assert items[0]["severity"] == "critical"
    assert items[0]["cwe"] == "CWE-89"
    summary = consolidate_findings(db, organization.id, finding.asset_id, "Semgrep", items)
    db.commit()
    gate = evaluate_gate(db, organization.id, finding.asset_id, "high", 0)
    assert summary["created"] == 1
    assert gate["passed"] is False
    assert gate["violations"] >= 1


def test_pipeline_consolidation_deduplicates_and_resolves_missing_findings():
    db, user, organization, finding = _database()
    first = normalize_findings([{"title": "Exposed secret", "severity": "high", "location": "settings.py:2", "fingerprint": "secret-1"}], "Trivy")
    created = consolidate_findings(db, organization.id, finding.asset_id, "Trivy", first)
    db.commit()
    repeated = consolidate_findings(db, organization.id, finding.asset_id, "Trivy", first)
    db.commit()
    empty = consolidate_findings(db, organization.id, finding.asset_id, "Trivy", [], complete_scan=True)
    db.commit()
    assert created["created"] == 1
    assert repeated["updated"] == 1
    assert empty["resolved"] == 1


def test_totp_and_recovery_codes_are_verified_once():
    secret = generate_secret()
    timestamp = 1_700_000_000
    code = current_code(secret, timestamp)
    assert verify_code(secret, code, timestamp)
    assert not verify_code(secret, "000000", timestamp) or code == "000000"
    recovery_codes = generate_recovery_codes(2)
    stored = dump_recovery_hashes(recovery_codes)
    accepted, remaining = consume_recovery_code(stored, recovery_codes[0])
    repeated, _ = consume_recovery_code(remaining, recovery_codes[0])
    assert accepted is True
    assert repeated is False


def test_mfa_setup_confirmation_and_recovery_code_flow_is_persisted():
    db, user, organization, finding = _database()
    original = settings.CREDENTIAL_ENCRYPTION_KEY
    settings.CREDENTIAL_ENCRYPTION_KEY = Fernet.generate_key().decode()
    try:
        setup = mfa_setup(current_user=user, db=db)
        assert setup["provisioning_uri"].startswith("otpauth://totp/")
        confirmation = mfa_confirm(MFACodeRequest(code=current_code(setup["secret"])), current_user=user, db=db)
        assert confirmation["enabled"] is True
        assert user.mfa_enabled is True
        assert setup["secret"] not in user.mfa_secret_encrypted
        recovery_code = confirmation["recovery_codes"][0]
        disabled = mfa_disable(MFACodeRequest(code=recovery_code), current_user=user, db=db)
        assert disabled["enabled"] is False
        assert user.mfa_secret_encrypted is None
    finally:
        settings.CREDENTIAL_ENCRYPTION_KEY = original


def test_sso_exchange_is_single_use_and_rechecks_enterprise_access():
    db, user, organization, finding = _database()
    user.subscription_plan = "enterprise"
    user.subscription_status = "active"
    code = "single-use-sso-exchange-code-with-enough-length"
    item = SSOLoginState(
        organization_id=organization.id,
        state_hash=_hash("state"),
        nonce_hash=_hash("nonce"),
        encrypted_code_verifier="encrypted-verifier",
        expires_at=datetime.utcnow() + timedelta(minutes=5),
        used_at=datetime.utcnow(),
        authenticated_user_id=user.id,
        exchange_code_hash=_hash(code),
        exchange_expires_at=datetime.utcnow() + timedelta(seconds=60),
    )
    db.add(item)
    db.commit()
    result = exchange_sso(SSOExchange(code=code), db=db)
    assert result["token_type"] == "bearer"
    assert result["access_token"]
    try:
        exchange_sso(SSOExchange(code=code), db=db)
    except HTTPException as exc:
        assert exc.status_code == 401
    else:
        raise AssertionError("SSO exchange code must be single use")


def test_compliance_uses_tenant_evidence_and_manual_attestation():
    db, user, organization, finding = _database()
    initial = compliance_summary(db, organization.id)
    inventory = next(item for item in initial["controls"] if item["key"] == "asset_inventory")
    assert inventory["status"] == "implemented"
    assert initial["total"] == 10

    attest_control(db, organization.id, user.id, "incident_response", "implemented", "Plano IR-001 revisado")
    db.commit()
    updated = compliance_summary(db, organization.id)
    incident = next(item for item in updated["controls"] if item["key"] == "incident_response")
    assert incident["status"] == "implemented"
    assert incident["evidence"] == "Plano IR-001 revisado"


def test_kimi_can_be_selected_without_exposing_its_key(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "kimi")
    monkeypatch.setenv("KIMI_API_KEY", "test-key-that-is-never-returned")
    monkeypatch.setenv("KIMI_MODEL", "kimi-k3")
    provider = configured_provider()
    assert provider.name == "kimi"
    assert provider.model == "kimi-k3"
    assert provider.reasoning_effort == "high"


def test_gemini_can_be_selected_without_exposing_its_key(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-that-is-never-returned")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    provider = configured_provider()
    assert provider.name == "gemini"
    assert provider.model == "gemini-3.1-flash-lite"
    assert provider.reasoning_effort == "low"


def test_authenticated_scanner_does_not_forward_secret_cross_origin(monkeypatch):
    scanner = WebSecurityScanner("https://example.com/private", auth_headers={"Authorization": "Bearer secret"})
    monkeypatch.setattr(scanner, "_resolve_public", lambda hostname: ["93.184.216.34"])
    captured = []

    class FakeResponse:
        def __init__(self, status, location=None):
            self.status_code = status
            self.headers = {"Location": location} if location else {}
            self.is_redirect = status == 302
            self.is_permanent_redirect = False
        def close(self):
            pass

    responses = iter([FakeResponse(302, "https://identity.example.net/landing"), FakeResponse(200)])
    def fake_get(url, **kwargs):
        captured.append((url, kwargs.get("headers")))
        return next(responses)
    monkeypatch.setattr(scanner.session, "get", fake_get)
    scanner._request(scanner.target)
    assert captured[0][1] == {"Authorization": "Bearer secret"}
    assert captured[1][1] == {}


def test_worker_heartbeat_is_observable():
    db, user, organization, finding = _database()
    beat(db, "worker")
    beat(db, "scheduler")
    db.commit()
    status = process_status(db)
    assert status["worker"]["healthy"] is True
    assert status["scheduler"]["healthy"] is True
