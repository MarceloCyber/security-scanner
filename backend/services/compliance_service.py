"""Evidence-backed security readiness controls for small and medium businesses.

This is a readiness view, not a legal certification. Automated controls are
computed from tenant data; organizational controls require a named attestation.
"""

from datetime import datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

from models.saas import Asset, AuditLog, ComplianceAttestation, Finding, PipelineApiKey, ScanJob
from models.user import User
from models.saas import OrganizationMember


CONTROL_DEFINITIONS = (
    ("asset_inventory", "Inventário de ativos", "Conhecer sistemas, domínios e APIs tratados pela empresa.", "LGPD · Segurança", True),
    ("continuous_monitoring", "Monitoramento contínuo", "Manter evidência recente de análise dos ativos.", "OWASP · Operação", True),
    ("critical_risk_treatment", "Tratamento de riscos críticos", "Não manter findings críticos sem plano de tratamento.", "OWASP · Risco", True),
    ("privileged_mfa", "MFA em acessos privilegiados", "Proteger contas owner e admin com segundo fator.", "Controle de acesso", True),
    ("audit_trail", "Trilha de auditoria", "Registrar ações administrativas e alterações relevantes.", "LGPD · Prestação de contas", True),
    ("secure_delivery", "Security gate no desenvolvimento", "Integrar análise de segurança ao pipeline de software.", "DevSecOps", True),
    ("incident_response", "Plano de resposta a incidentes", "Documentar responsáveis, comunicação e recuperação.", "LGPD · Incidentes", False),
    ("backup_recovery", "Backup e restauração testados", "Registrar a evidência do último teste de restauração.", "Continuidade", False),
    ("privacy_governance", "Governança de privacidade", "Manter aviso de privacidade, bases legais e canal do titular.", "LGPD", False),
    ("access_review", "Revisão periódica de acessos", "Revisar usuários e privilégios em ciclo definido.", "Controle de acesso", False),
)


def _automated_statuses(db: Session, organization_id: int) -> dict[str, tuple[str, str]]:
    active_assets = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.status == "active").all()
    assets = len(active_assets)
    cutoff = datetime.utcnow() - timedelta(days=30)
    recent_scans = db.query(ScanJob).filter(
        ScanJob.organization_id == organization_id,
        ScanJob.status == "completed",
        ScanJob.completed_at.isnot(None),
        ScanJob.completed_at >= cutoff,
    ).all()
    covered_asset_ids = {job.asset_id for job in recent_scans if job.asset_id is not None}
    covered_assets = len({asset.id for asset in active_assets if asset.id in covered_asset_ids})
    critical = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.status.in_(("open", "in_progress")), Finding.severity == "critical").count()
    privileged = (
        db.query(User)
        .join(OrganizationMember, OrganizationMember.user_id == User.id)
        .filter(OrganizationMember.organization_id == organization_id, OrganizationMember.role.in_(("owner", "admin")))
        .all()
    )
    audit_entries = db.query(AuditLog).filter(AuditLog.organization_id == organization_id).count()
    now = datetime.utcnow()
    pipeline_keys = db.query(PipelineApiKey).filter(
        PipelineApiKey.organization_id == organization_id,
        PipelineApiKey.revoked_at.is_(None),
        or_(PipelineApiKey.expires_at.is_(None), PipelineApiKey.expires_at > now),
    ).count()
    mfa_ready = bool(privileged) and all(bool(user.mfa_enabled) for user in privileged)
    return {
        "asset_inventory": ("implemented" if assets else "not_started", f"{assets} ativo(s) em acompanhamento"),
        "continuous_monitoring": ("implemented" if assets and covered_assets == assets else "in_progress" if covered_assets else "not_started", f"{covered_assets}/{assets} ativo(s) analisado(s) nos últimos 30 dias"),
        "critical_risk_treatment": ("implemented" if critical == 0 and recent_scans else "in_progress" if recent_scans else "not_started", f"{critical} risco(s) crítico(s) aberto(s); {len(recent_scans)} análise(s) recente(s)"),
        "privileged_mfa": ("implemented" if mfa_ready else "in_progress" if privileged else "not_started", f"{sum(bool(user.mfa_enabled) for user in privileged)}/{len(privileged)} conta(s) privilegiada(s) com MFA"),
        "audit_trail": ("implemented" if audit_entries else "not_started", f"{audit_entries} evento(s) auditável(is)"),
        "secure_delivery": ("implemented" if pipeline_keys else "not_started", f"{pipeline_keys} chave(s) de pipeline ativa(s)"),
    }


def compliance_summary(db: Session, organization_id: int) -> dict:
    automated = _automated_statuses(db, organization_id)
    attestations = {item.control_key: item for item in db.query(ComplianceAttestation).filter(ComplianceAttestation.organization_id == organization_id).all()}
    controls = []
    for key, title, description, framework, is_automated in CONTROL_DEFINITIONS:
        if is_automated:
            status, evidence = automated[key]
            reviewed_at = None
        else:
            attestation = attestations.get(key)
            status = attestation.status if attestation else "not_started"
            evidence = attestation.evidence if attestation else None
            reviewed_at = attestation.reviewed_at.isoformat() if attestation and attestation.reviewed_at else None
        controls.append({"key": key, "title": title, "description": description, "framework": framework, "automated": is_automated, "status": status, "evidence": evidence, "reviewed_at": reviewed_at})
    weights = {"not_started": 0, "in_progress": 50, "implemented": 100}
    score = round(sum(weights.get(control["status"], 0) for control in controls) / len(controls))
    return {"score": score, "implemented": sum(control["status"] == "implemented" for control in controls), "total": len(controls), "controls": controls, "disclaimer": "Indicador de prontidão baseado em evidências; não representa certificação nem parecer jurídico."}


def attest_control(db: Session, organization_id: int, user_id: int, control_key: str, status: str, evidence: str | None):
    manual_keys = {item[0] for item in CONTROL_DEFINITIONS if not item[4]}
    if control_key not in manual_keys:
        raise ValueError("Este controle é calculado automaticamente")
    item = db.query(ComplianceAttestation).filter(ComplianceAttestation.organization_id == organization_id, ComplianceAttestation.control_key == control_key).first()
    if item is None:
        item = ComplianceAttestation(organization_id=organization_id, control_key=control_key)
        db.add(item)
    item.status = status
    item.evidence = evidence.strip() if evidence else None
    item.updated_by = user_id
    item.reviewed_at = datetime.utcnow()
    return item
