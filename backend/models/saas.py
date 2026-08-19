"""Core SaaS domain models.

These models are additive to the legacy scanner schema.  Existing scanner
tables remain usable while new product data is scoped through memberships.
"""

from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, Integer, JSON, String, Text, UniqueConstraint

from database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(160), nullable=False)
    slug = Column(String(160), nullable=False, unique=True, index=True)
    plan = Column(String(40), nullable=False, default="starter")
    status = Column(String(30), nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_member"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False, default="viewer")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "type", "name", name="uq_asset_org_type_name"),
        Index("ix_assets_org_exposure", "organization_id", "internet_exposed"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String(40), nullable=False)
    name = Column(String(255), nullable=False)
    hostname = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    url = Column(String(2048), nullable=True)
    environment = Column(String(20), nullable=False, default="unknown")
    criticality = Column(String(20), nullable=False, default="medium")
    internet_exposed = Column(Boolean, nullable=False, default=False)
    status = Column(String(20), nullable=False, default="active")
    metadata_json = Column("metadata", JSON, nullable=True)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScanJob(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (Index("ix_scan_jobs_org_status", "organization_id", "status"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scanner_type = Column(String(80), nullable=False)
    status = Column(String(20), nullable=False, default="queued")
    progress = Column(Integer, nullable=False, default=0)
    error = Column(Text, nullable=True)
    result_json = Column("result", JSON, nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("organization_id", "fingerprint", name="uq_finding_org_fingerprint"),
        Index("ix_findings_org_status_severity", "organization_id", "status", "severity"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_job_id = Column(Integer, ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint = Column(String(128), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(80), nullable=True)
    severity = Column(String(20), nullable=False, default="informational")
    confidence = Column(String(20), nullable=False, default="medium")
    status = Column(String(30), nullable=False, default="open")
    risk_score = Column(Integer, nullable=False, default=0)
    risk_factors = Column(JSON, nullable=True)
    cve = Column(String(40), nullable=True)
    cwe = Column(String(40), nullable=True)
    cvss_score = Column(String(16), nullable=True)
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    scanner_source = Column(String(80), nullable=True)
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)


class FindingEvidence(Base):
    __tablename__ = "finding_evidence"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    content = Column(Text, nullable=False)
    location = Column(String(2048), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class RemediationTask(Base):
    __tablename__ = "remediation_tasks"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    priority = Column(String(20), nullable=False, default="medium")
    status = Column(String(30), nullable=False, default="open")
    assigned_to = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    due_date = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_logs_org_created", "organization_id", "created_at"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(80), nullable=False)
    resource_type = Column(String(80), nullable=True)
    resource_id = Column(String(80), nullable=True)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    metadata_json = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class SecuritySnapshot(Base):
    __tablename__ = "security_snapshots"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    score = Column(Integer, nullable=False, default=0)
    critical_findings = Column(Integer, nullable=False, default=0)
    high_findings = Column(Integer, nullable=False, default=0)
    medium_findings = Column(Integer, nullable=False, default=0)
    low_findings = Column(Integer, nullable=False, default=0)
    assets_total = Column(Integer, nullable=False, default=0)
    assets_exposed = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AIConversation(Base):
    __tablename__ = "ai_conversations"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    title = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AIMessage(Base):
    __tablename__ = "ai_messages"

    id = Column(Integer, primary_key=True, index=True)
    conversation_id = Column(Integer, ForeignKey("ai_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False)
    content = Column(Text, nullable=False)
    tool_calls = Column(JSON, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    report_type = Column(String(30), nullable=False)
    period_days = Column(Integer, nullable=False, default=30)
    status = Column(String(20), nullable=False, default="completed")
    payload = Column(JSON, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class Integration(Base):
    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("organization_id", "provider", name="uq_integration_org_provider"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = Column(String(40), nullable=False)
    status = Column(String(30), nullable=False, default="pending")
    configuration = Column(JSON, nullable=True)
    last_synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class IntegrationCredential(Base):
    __tablename__ = "integration_credentials"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    integration_id = Column(Integer, ForeignKey("integrations.id", ondelete="CASCADE"), nullable=False, unique=True)
    encrypted_secret = Column(Text, nullable=False)
    secret_hint = Column(String(20), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AIAction(Base):
    __tablename__ = "ai_actions"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action_type = Column(String(80), nullable=False)
    payload = Column(JSON, nullable=False)
    status = Column(String(20), nullable=False, default="proposed")
    requires_approval = Column(Boolean, nullable=False, default=True)
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    executed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class PipelineApiKey(Base):
    """Hashed, organization-scoped credential for CI/CD ingestion."""

    __tablename__ = "pipeline_api_keys"
    __table_args__ = (Index("ix_pipeline_keys_org_active", "organization_id", "revoked_at"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    key_prefix = Column(String(24), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)
    scopes = Column(JSON, nullable=False, default=lambda: ["findings:write", "gates:read"])
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ComplianceAttestation(Base):
    """Organization evidence for controls that cannot be inferred automatically."""

    __tablename__ = "compliance_attestations"
    __table_args__ = (
        UniqueConstraint("organization_id", "control_key", name="uq_compliance_org_control"),
        Index("ix_compliance_org_status", "organization_id", "status"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    control_key = Column(String(80), nullable=False)
    status = Column(String(20), nullable=False, default="not_started")
    evidence = Column(Text, nullable=True)
    updated_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuthenticatedScanProfile(Base):
    __tablename__ = "authenticated_scan_profiles"
    __table_args__ = (UniqueConstraint("organization_id", "asset_id", name="uq_auth_scan_org_asset"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    auth_type = Column(String(20), nullable=False)
    header_name = Column(String(80), nullable=True)
    encrypted_value = Column(Text, nullable=False)
    secret_hint = Column(String(20), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class ProcessHeartbeat(Base):
    __tablename__ = "process_heartbeats"
    __table_args__ = (UniqueConstraint("process_type", "instance_id", name="uq_process_heartbeat_instance"),)

    id = Column(Integer, primary_key=True, index=True)
    process_type = Column(String(30), nullable=False, index=True)
    instance_id = Column(String(160), nullable=False)
    metadata_json = Column("metadata", JSON, nullable=True)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)


class AuditExport(Base):
    __tablename__ = "audit_exports"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    sha256 = Column(String(64), nullable=False)
    record_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class EnterpriseSSOConfig(Base):
    __tablename__ = "enterprise_sso_configs"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    issuer = Column(String(500), nullable=False)
    client_id = Column(String(300), nullable=False)
    encrypted_client_secret = Column(Text, nullable=False)
    allowed_domains = Column(JSON, nullable=False, default=list)
    require_mfa_claim = Column(Boolean, nullable=False, default=True)
    enabled = Column(Boolean, nullable=False, default=False)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class SSOLoginState(Base):
    __tablename__ = "sso_login_states"

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    state_hash = Column(String(64), nullable=False, unique=True, index=True)
    nonce_hash = Column(String(64), nullable=False)
    encrypted_code_verifier = Column(Text, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)
    authenticated_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    exchange_code_hash = Column(String(64), nullable=True, unique=True, index=True)
    exchange_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class SecuritySensor(Base):
    """Credential used by an asset-side proxy/WAF collector to send telemetry."""

    __tablename__ = "security_sensors"
    __table_args__ = (Index("ix_security_sensors_org_active", "organization_id", "revoked_at"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(120), nullable=False)
    key_prefix = Column(String(24), nullable=False, index=True)
    key_hash = Column(String(64), nullable=False, unique=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class SecurityEvent(Base):
    """Tenant-scoped security signal derived from trusted asset telemetry."""

    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_org_status_seen", "organization_id", "status", "last_seen_at"),
        Index("ix_security_events_org_fingerprint", "organization_id", "fingerprint"),
    )

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    sensor_id = Column(Integer, ForeignKey("security_sensors.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False)
    event_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    source_ip = Column(String(64), nullable=True, index=True)
    method = Column(String(12), nullable=True)
    request_path = Column(String(2048), nullable=True)
    status_code = Column(Integer, nullable=True)
    request_count = Column(Integer, nullable=False, default=1)
    evidence_json = Column("evidence", JSON, nullable=True)
    status = Column(String(24), nullable=False, default="open")
    containment_status = Column(String(24), nullable=False, default="not_contained")
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class ContainmentAction(Base):
    """Auditable WAF action approved by an organization administrator."""

    __tablename__ = "containment_actions"
    __table_args__ = (Index("ix_containment_actions_org_created", "organization_id", "created_at"),)

    id = Column(Integer, primary_key=True, index=True)
    organization_id = Column(Integer, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    security_event_id = Column(Integer, ForeignKey("security_events.id", ondelete="SET NULL"), nullable=True, index=True)
    provider = Column(String(40), nullable=False)
    action_type = Column(String(40), nullable=False)
    target = Column(String(255), nullable=False)
    external_id = Column(String(160), nullable=True)
    status = Column(String(24), nullable=False, default="pending")
    approved_by = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    response_json = Column("response", JSON, nullable=True)
    error = Column(Text, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    released_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
