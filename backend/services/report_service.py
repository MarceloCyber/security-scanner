"""Evidence-backed, organization-scoped security reports."""

from collections import Counter
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from sqlalchemy.orm import Session

from models.saas import (
    Asset, AuditLog, Finding, Integration, Organization, OrganizationMember, RemediationTask, Report, ScanJob,
    SecurityEvent, SecurityPolicy, SecurityPolicyAcknowledgement, SecurityPolicyVersion, SecuritySnapshot,
    SiemEvent, SiemIncident, SiemRule, SiemSource,
)
from models.user import User
from risk.engine import organization_security_score
from services.compliance_service import compliance_summary


PAGE_WIDTH, PAGE_HEIGHT = A4
NAVY = colors.HexColor("#111827")
INK = colors.HexColor("#172033")
MUTED = colors.HexColor("#64748B")
LINE = colors.HexColor("#E2E8F0")
PANEL = colors.HexColor("#F8FAFC")
VIOLET = colors.HexColor("#7C3AED")
LILAC = colors.HexColor("#A78BFA")
SEVERITY_COLORS = {"critical": colors.HexColor("#B91C1C"), "high": colors.HexColor("#EA580C"), "medium": colors.HexColor("#D97706"), "low": colors.HexColor("#2563EB"), "informational": colors.HexColor("#64748B")}
SEVERITY_LABELS = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "informational": "Informativo"}
STATUS_LABELS = {"open": "Aberto", "in_progress": "Em tratamento", "resolved": "Resolvido", "accepted_risk": "Risco aceito", "false_positive": "Falso positivo", "completed": "Concluído", "failed": "Falhou"}
LOGO_PATH = Path(__file__).resolve().parents[2] / "frontend" / "assets" / "ironnet-logo.jpeg"


def _iso(value):
    return value.isoformat() if value else None


def _counter(items, attribute, defaults=()):
    values = Counter((getattr(item, attribute, None) or "unknown").lower() for item in items)
    return {key: values.get(key, 0) for key in (*defaults, *[item for item in values if item not in defaults])}


def _asset_label(asset):
    if not asset:
        return "Ativo não vinculado"
    return asset.name or asset.hostname or asset.url or asset.ip_address or f"Ativo #{asset.id}"


def _recommendations(metrics, compliance, tasks):
    findings = metrics["findings"]
    items = []
    if findings.get("critical", 0):
        items.append({"priority": "Imediata", "title": "Eliminar riscos críticos", "detail": f"Tratar os {findings['critical']} riscos críticos ativos, começando pelos ativos expostos à internet."})
    if findings.get("high", 0):
        items.append({"priority": "Alta", "title": "Reduzir a superfície de alto risco", "detail": f"Definir responsáveis e prazo para os {findings['high']} riscos altos em aberto ou em tratamento."})
    if metrics["assets_exposed"]:
        items.append({"priority": "Alta", "title": "Revisar exposição externa", "detail": f"Validar necessidade, autenticação e proteção dos {metrics['assets_exposed']} ativos acessíveis pela internet."})
    if tasks["overdue"]:
        items.append({"priority": "Alta", "title": "Regularizar remediações vencidas", "detail": f"Replanejar ou concluir {tasks['overdue']} tarefas com prazo ultrapassado."})
    if metrics["scan_jobs"]["failed"]:
        items.append({"priority": "Operacional", "title": "Corrigir falhas de monitoramento", "detail": f"Investigar {metrics['scan_jobs']['failed']} análises que falharam no período para restaurar a cobertura."})
    if compliance["score"] < 80:
        items.append({"priority": "Governança", "title": "Elevar prontidão de controles", "detail": f"O indicador atual é {compliance['score']}%; priorizar controles sem evidência e em andamento."})
    if not items:
        items.append({"priority": "Contínua", "title": "Manter o ciclo de melhoria", "detail": "Preservar o monitoramento recorrente, revisar acessos e validar evidências de conformidade periodicamente."})
    return items[:6]


def generate_report(db: Session, organization_id: int, user_id: int, report_type: str, period_days: int = 30) -> Report:
    if report_type not in {"executive", "technical", "general"}:
        raise ValueError("Unsupported report type")
    period_days = min(max(period_days, 1), 365)
    generated_at = datetime.utcnow()
    since = generated_at - timedelta(days=period_days)
    organization = db.query(Organization).filter(Organization.id == organization_id).first()
    creator = db.query(User).filter(User.id == user_id).first()
    summary = organization_security_score(db, organization_id)
    findings = db.query(Finding).filter(Finding.organization_id == organization_id).order_by(Finding.risk_score.desc(), Finding.first_seen_at.asc()).all()
    assets = db.query(Asset).filter(Asset.organization_id == organization_id).order_by(Asset.criticality.desc(), Asset.name.asc()).all()
    tasks = db.query(RemediationTask).filter(RemediationTask.organization_id == organization_id).all()
    scans = db.query(ScanJob).filter(ScanJob.organization_id == organization_id, ScanJob.created_at >= since).order_by(ScanJob.created_at.desc()).all()
    integrations = db.query(Integration).filter(Integration.organization_id == organization_id).all()
    snapshots = db.query(SecuritySnapshot).filter(SecuritySnapshot.organization_id == organization_id, SecuritySnapshot.created_at >= since).order_by(SecuritySnapshot.created_at.asc()).all()
    compliance = compliance_summary(db, organization_id)
    active_findings = [item for item in findings if item.status in {"open", "in_progress"}]
    assets_by_id = {asset.id: asset for asset in assets}
    severity_counts = _counter(active_findings, "severity", ("critical", "high", "medium", "low", "informational"))
    finding_statuses = _counter(findings, "status", ("open", "in_progress", "resolved", "accepted_risk", "false_positive"))
    task_statuses = _counter(tasks, "status", ("open", "in_progress", "completed", "cancelled"))
    overdue = sum(1 for task in tasks if task.due_date and task.due_date < generated_at and task.status not in {"completed", "cancelled"})
    scan_statuses = _counter(scans, "status", ("completed", "failed", "running", "queued"))
    connected_integrations = [item for item in integrations if item.status == "connected"]
    metrics = {
        "security_score": summary["score"], "findings": severity_counts, "finding_statuses": finding_statuses,
        "active_findings": len(active_findings), "new_findings": sum(1 for item in findings if item.first_seen_at and item.first_seen_at >= since),
        "resolved_findings": sum(1 for item in findings if item.resolved_at and item.resolved_at >= since),
        "assets_total": len(assets), "assets_exposed": sum(1 for item in assets if item.internet_exposed),
        "assets_by_criticality": _counter(assets, "criticality", ("critical", "high", "medium", "low")),
        "scan_jobs": {"total": len(scans), **scan_statuses}, "integrations_connected": len(connected_integrations),
    }
    remediation = {"total": len(tasks), "overdue": overdue, **task_statuses}
    trend = [{"date": _iso(item.created_at), "score": item.score, "critical": item.critical_findings, "high": item.high_findings, "assets": item.assets_total, "exposed": item.assets_exposed} for item in snapshots]
    top_risks = [{
        "id": item.id, "title": item.title, "description": item.description, "severity": item.severity, "status": item.status,
        "risk_score": item.risk_score, "asset_id": item.asset_id, "asset": _asset_label(assets_by_id.get(item.asset_id)),
        "scanner": item.scanner_source, "cve": item.cve, "cwe": item.cwe, "cvss": item.cvss_score, "confidence": item.confidence,
        "first_seen_at": _iso(item.first_seen_at), "last_seen_at": _iso(item.last_seen_at), "occurrence_count": item.occurrence_count,
        "risk_factors": item.risk_factors or {}, "evidence": item.evidence, "remediation": item.remediation,
    } for item in active_findings[:10]]
    narrative = (
        f"A organização apresenta Security Score de {metrics['security_score']}/100, com {metrics['active_findings']} riscos ativos — "
        f"{severity_counts['critical']} críticos e {severity_counts['high']} altos. No período analisado, foram identificados "
        f"{metrics['new_findings']} novos riscos e resolvidos {metrics['resolved_findings']}. A cobertura atual contempla "
        f"{metrics['assets_total']} ativos, dos quais {metrics['assets_exposed']} estão expostos à internet."
    )
    payload = {
        "schema_version": 2, "organization": {"id": organization_id, "name": organization.name if organization else f"Organização {organization_id}"},
        "generated_at": _iso(generated_at), "generated_by": creator.username if creator else f"Usuário {user_id}",
        "period": {"days": period_days, "start": _iso(since), "end": _iso(generated_at)}, "period_days": period_days,
        "metrics": metrics, "remediation": remediation, "compliance": compliance,
        "integrations": [{"provider": item.provider, "status": item.status, "last_synced_at": _iso(item.last_synced_at)} for item in integrations],
        "trend": trend, "executive_summary": narrative, "recommendations": _recommendations(metrics, compliance, remediation), "top_risks": top_risks,
    }
    if report_type in {"technical", "general"}:
        payload["assets"] = [{"id": item.id, "name": _asset_label(item), "type": item.type, "environment": item.environment, "criticality": item.criticality, "internet_exposed": item.internet_exposed, "status": item.status, "last_seen_at": _iso(item.last_seen_at)} for item in assets]
        payload["scan_jobs"] = [{"id": item.id, "asset_id": item.asset_id, "scanner_type": item.scanner_type, "status": item.status, "progress": item.progress, "error": item.error, "created_at": _iso(item.created_at), "completed_at": _iso(item.completed_at)} for item in scans[:200]]
        payload["findings_detail"] = [{
            "id": item.id, "title": item.title, "description": item.description, "severity": item.severity, "status": item.status,
            "risk_score": item.risk_score, "risk_factors": item.risk_factors or {}, "asset_id": item.asset_id,
            "asset": _asset_label(assets_by_id.get(item.asset_id)), "scanner": item.scanner_source, "evidence": item.evidence,
            "cve": item.cve, "cwe": item.cwe, "cvss": item.cvss_score, "confidence": item.confidence,
            "occurrence_count": item.occurrence_count, "first_seen_at": _iso(item.first_seen_at), "last_seen_at": _iso(item.last_seen_at), "remediation": item.remediation,
        } for item in findings[:500]]
    if report_type == "general":
        policies = db.query(SecurityPolicy).filter(SecurityPolicy.organization_id == organization_id).order_by(SecurityPolicy.title.asc()).all()
        policy_ids = [item.id for item in policies]
        versions = db.query(SecurityPolicyVersion).filter(SecurityPolicyVersion.organization_id == organization_id).order_by(SecurityPolicyVersion.policy_id.asc(), SecurityPolicyVersion.version.desc()).all() if policy_ids else []
        acknowledgements = db.query(SecurityPolicyAcknowledgement).filter(SecurityPolicyAcknowledgement.organization_id == organization_id).all()
        sources = db.query(SiemSource).filter(SiemSource.organization_id == organization_id).order_by(SiemSource.created_at.desc()).all()
        rules = db.query(SiemRule).filter(SiemRule.organization_id == organization_id).order_by(SiemRule.created_at.desc()).all()
        siem_events = db.query(SiemEvent).filter(SiemEvent.organization_id == organization_id, SiemEvent.received_at >= since).order_by(SiemEvent.received_at.desc()).limit(500).all()
        incidents = db.query(SiemIncident).filter(SiemIncident.organization_id == organization_id, SiemIncident.created_at >= since).order_by(SiemIncident.created_at.desc()).limit(200).all()
        security_events = db.query(SecurityEvent).filter(SecurityEvent.organization_id == organization_id, SecurityEvent.created_at >= since).order_by(SecurityEvent.created_at.desc()).limit(500).all()
        audit_logs = db.query(AuditLog).filter(AuditLog.organization_id == organization_id, AuditLog.created_at >= since).order_by(AuditLog.created_at.desc()).limit(1000).all()
        members = db.query(OrganizationMember).filter(OrganizationMember.organization_id == organization_id).order_by(OrganizationMember.role.asc()).all()
        versions_by_policy = {}
        for version in versions:
            versions_by_policy.setdefault(version.policy_id, []).append({
                "id": version.id, "version": version.version, "content": version.content,
                "change_summary": version.change_summary, "created_by": version.created_by,
                "approved_by": version.approved_by, "approved_at": _iso(version.approved_at), "created_at": _iso(version.created_at),
            })
        payload["platform_inventory"] = {
            "assets": payload.get("assets", []), "findings": payload.get("findings_detail", []),
            "scan_jobs": payload.get("scan_jobs", []),
            "remediation_tasks": [{"id": item.id, "finding_id": item.finding_id, "title": item.title, "description": item.description, "priority": item.priority, "status": item.status, "assigned_to": item.assigned_to, "due_date": _iso(item.due_date), "created_at": _iso(item.created_at), "completed_at": _iso(item.completed_at)} for item in tasks],
            "snapshots": trend,
            "integrations": payload.get("integrations", []),
            "organization_members": [{"id": item.id, "user_id": item.user_id, "role": item.role, "created_at": _iso(item.created_at)} for item in members],
        }
        payload["governance"] = {"policies": [{"id": item.id, "slug": item.slug, "title": item.title, "description": item.description, "owner_user_id": item.owner_user_id, "status": item.status, "review_interval_days": item.review_interval_days, "next_review_at": _iso(item.next_review_at), "published_version_id": item.published_version_id, "created_by": item.created_by, "created_at": _iso(item.created_at), "updated_at": _iso(item.updated_at), "versions": versions_by_policy.get(item.id, []), "acknowledgements": sum(1 for ack in acknowledgements if ack.policy_id == item.id), "acknowledgement_details": [{"version_id": ack.version_id, "user_id": ack.user_id, "acknowledged_at": _iso(ack.acknowledged_at)} for ack in acknowledgements if ack.policy_id == item.id]} for item in policies]}
        payload["siem"] = {
            "sources": [{"id": item.id, "asset_id": item.asset_id, "name": item.name, "source_type": item.source_type, "key_prefix": item.key_prefix, "config": item.config or {}, "last_seen_at": _iso(item.last_seen_at), "revoked_at": _iso(item.revoked_at), "created_at": _iso(item.created_at)} for item in sources],
            "rules": [{"id": item.id, "name": item.name, "description": item.description, "severity": item.severity, "conditions": item.conditions, "enabled": item.enabled, "created_by": item.created_by, "created_at": _iso(item.created_at), "updated_at": _iso(item.updated_at)} for item in rules],
            "events": [{"id": item.id, "source_id": item.source_id, "asset_id": item.asset_id, "event_type": item.event_type, "severity": item.severity, "occurred_at": _iso(item.occurred_at), "received_at": _iso(item.received_at), "source_ip": item.source_ip, "user_name": item.user_name, "action": item.action, "outcome": item.outcome, "message": item.message, "payload": item.payload, "matched_rule_ids": item.matched_rule_ids} for item in siem_events],
            "incidents": [{"id": item.id, "rule_id": item.rule_id, "event_id": item.event_id, "title": item.title, "description": item.description, "severity": item.severity, "status": item.status, "assigned_to": item.assigned_to, "resolution": item.resolution, "first_seen_at": _iso(item.first_seen_at), "last_seen_at": _iso(item.last_seen_at), "resolved_at": _iso(item.resolved_at), "created_at": _iso(item.created_at)} for item in incidents],
        }
        payload["monitoring"] = [{"id": item.id, "asset_id": item.asset_id, "event_type": item.event_type, "severity": item.severity, "title": item.title, "description": item.description, "source_ip": item.source_ip, "request_path": item.request_path, "status_code": item.status_code, "request_count": item.request_count, "evidence": item.evidence_json, "status": item.status, "containment_status": item.containment_status, "occurrence_count": item.occurrence_count, "first_seen_at": _iso(item.first_seen_at), "last_seen_at": _iso(item.last_seen_at), "created_at": _iso(item.created_at)} for item in security_events]
        payload["audit"] = [{"id": item.id, "user_id": item.user_id, "action": item.action, "resource_type": item.resource_type, "resource_id": item.resource_id, "ip_address": item.ip_address, "metadata": item.metadata_json or {}, "created_at": _iso(item.created_at)} for item in audit_logs]
    report = Report(organization_id=organization_id, created_by=user_id, report_type=report_type, period_days=period_days, payload=payload)
    db.add(report)
    db.flush()
    return report


def _styles():
    base = getSampleStyleSheet()
    return {
        "cover_brand": ParagraphStyle("CoverBrand", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=12, leading=14, textColor=LILAC, spaceAfter=5),
        "cover_title": ParagraphStyle("CoverTitle", parent=base["Title"], fontName="Helvetica-Bold", fontSize=30, leading=34, textColor=NAVY, alignment=TA_LEFT, spaceAfter=10),
        "cover_subtitle": ParagraphStyle("CoverSubtitle", parent=base["Normal"], fontSize=12, leading=18, textColor=MUTED),
        "h1": ParagraphStyle("H1", parent=base["Heading1"], fontName="Helvetica-Bold", fontSize=19, leading=23, textColor=NAVY, spaceBefore=4, spaceAfter=10),
        "h2": ParagraphStyle("H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12, leading=15, textColor=NAVY, spaceBefore=12, spaceAfter=7),
        "h3": ParagraphStyle("H3", parent=base["Heading3"], fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=INK, spaceAfter=4),
        "body": ParagraphStyle("Body", parent=base["BodyText"], fontName="Helvetica", fontSize=8.5, leading=13, textColor=INK, spaceAfter=6),
        "small": ParagraphStyle("Small", parent=base["BodyText"], fontName="Helvetica", fontSize=7, leading=10, textColor=MUTED),
        "label": ParagraphStyle("Label", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=6.5, leading=8, textColor=MUTED),
        "metric": ParagraphStyle("Metric", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=19, leading=21, textColor=NAVY, alignment=TA_CENTER),
        "metric_label": ParagraphStyle("MetricLabel", parent=base["Normal"], fontName="Helvetica", fontSize=6.5, leading=8, textColor=MUTED, alignment=TA_CENTER),
        "table_header": ParagraphStyle("TableHeader", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=colors.white),
        "table": ParagraphStyle("Table", parent=base["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=INK),
        "table_bold": ParagraphStyle("TableBold", parent=base["Normal"], fontName="Helvetica-Bold", fontSize=7, leading=9, textColor=INK),
        "right": ParagraphStyle("Right", parent=base["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=MUTED, alignment=TA_RIGHT),
        "center": ParagraphStyle("Center", parent=base["Normal"], fontName="Helvetica", fontSize=7, leading=9, textColor=MUTED, alignment=TA_CENTER),
    }


def _text(value, style, limit=None):
    value = "—" if value in (None, "") else str(value)
    if limit and len(value) > limit:
        value = value[: limit - 1].rstrip() + "…"
    return Paragraph(escape(value).replace("\n", "<br/>"), style)


def _date(value, include_time=False):
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.strftime("%d/%m/%Y %H:%M") if include_time else parsed.strftime("%d/%m/%Y")
    except (TypeError, ValueError):
        return str(value)


def _header_footer(canvas, document, payload):
    canvas.saveState()
    canvas.setStrokeColor(LINE)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, PAGE_HEIGHT - 14 * mm, PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 14 * mm)
    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(VIOLET)
    canvas.drawString(18 * mm, PAGE_HEIGHT - 10.5 * mm, "IRON AI  /  SECURITY INTELLIGENCE")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(PAGE_WIDTH - 18 * mm, PAGE_HEIGHT - 10.5 * mm, str((payload.get("organization") or {}).get("name", "Organização"))[:55])
    canvas.line(18 * mm, 14 * mm, PAGE_WIDTH - 18 * mm, 14 * mm)
    canvas.drawString(18 * mm, 9.5 * mm, "CONFIDENCIAL · Uso interno")
    canvas.drawRightString(PAGE_WIDTH - 18 * mm, 9.5 * mm, f"Página {document.page}")
    canvas.restoreState()


def _cover(story, report, payload, styles):
    report_name = {"executive": "Relatório Executivo de Segurança", "technical": "Relatório Técnico de Segurança", "general": "Relatório Geral Completo da Plataforma"}.get(report.report_type, "Relatório de Segurança")
    story.append(Spacer(1, 13 * mm))
    if LOGO_PATH.exists():
        logo = Image(str(LOGO_PATH), width=20 * mm, height=20 * mm)
        logo.hAlign = "LEFT"
        story.extend([logo, Spacer(1, 6 * mm)])
    story.extend([Paragraph("IRON AI  /  SECURITY INTELLIGENCE", styles["cover_brand"]), Paragraph(report_name, styles["cover_title"]), Paragraph(escape(str((payload.get("organization") or {}).get("name", "Organização"))), styles["cover_subtitle"]), Spacer(1, 8 * mm), HRFlowable(width="100%", thickness=2, color=VIOLET, spaceAfter=7 * mm)])
    period = payload.get("period") or {}
    cover_data = [[_text("PERÍODO ANALISADO", styles["label"]), _text("EMITIDO EM", styles["label"]), _text("RESPONSÁVEL PELA GERAÇÃO", styles["label"])], [_text(f"{_date(period.get('start'))} a {_date(period.get('end'))}", styles["body"]), _text(_date(payload.get("generated_at"), True) + " UTC", styles["body"]), _text(payload.get("generated_by"), styles["body"])]]
    cover_table = Table(cover_data, colWidths=[58 * mm, 50 * mm, 60 * mm])
    cover_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, 0), 2)]))
    story.extend([cover_table, Spacer(1, 45 * mm)])
    story.append(Table([[_text("CLASSIFICAÇÃO", styles["label"]), _text("CONFIDENCIAL", styles["table_bold"])], [_text("FONTE", styles["label"]), _text("Dados persistidos na plataforma Iron AI no instante da emissão", styles["small"])]], colWidths=[30 * mm, 138 * mm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.4, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 7)])))
    story.append(PageBreak())


def _section(story, title, styles, subtitle=None):
    story.append(Paragraph(title, styles["h1"]))
    if subtitle:
        story.append(Paragraph(subtitle, styles["small"]))
    story.append(HRFlowable(width="100%", thickness=1, color=LINE, spaceAfter=4 * mm))


def _metric_cards(metrics, styles):
    findings = metrics.get("findings") or {}
    cards = [(metrics.get("security_score", 0), "SECURITY SCORE / 100"), (metrics.get("active_findings", sum(findings.values())), "RISCOS ATIVOS"), (findings.get("critical", 0), "CRÍTICOS"), (metrics.get("assets_exposed", 0), "ATIVOS EXPOSTOS")]
    cells = []
    for value, label in cards:
        cells.append(Table([[Paragraph(str(value), styles["metric"])], [Paragraph(label, styles["metric_label"])]], colWidths=[42 * mm], rowHeights=[10 * mm, 6 * mm], style=TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE")])))
    table = Table([cells], colWidths=[42 * mm] * 4, rowHeights=[19 * mm])
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.6, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.5, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 1)]))
    return table


def _severity_table(metrics, styles):
    findings = metrics.get("findings") or {}
    total = max(1, sum(findings.values()))
    rows = [[_text("SEVERIDADE", styles["table_header"]), _text("QUANTIDADE", styles["table_header"]), _text("DISTRIBUIÇÃO", styles["table_header"])]]
    for severity in ("critical", "high", "medium", "low", "informational"):
        count = findings.get(severity, 0)
        bar_width = max(1, round(70 * mm * count / total))
        bar = Table([[""]], colWidths=[bar_width], rowHeights=[3.5 * mm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS[severity])]))
        rows.append([_text(SEVERITY_LABELS[severity], styles["table_bold"]), _text(count, styles["center"]), bar])
    table = Table(rows, colWidths=[38 * mm, 28 * mm, 102 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 6)]))
    return table


def _top_risks_table(risks, styles):
    rows = [[_text("RISCO", styles["table_header"]), _text("ATIVO", styles["table_header"]), _text("SEVERIDADE", styles["table_header"]), _text("SCORE", styles["table_header"]), _text("STATUS", styles["table_header"])]]
    for risk in risks:
        severity = (risk.get("severity") or "informational").lower()
        rows.append([_text(risk.get("title"), styles["table_bold"], 95), _text(risk.get("asset"), styles["table"], 55), _text(SEVERITY_LABELS.get(severity, severity.title()), styles["table"]), _text(risk.get("risk_score", 0), styles["center"]), _text(STATUS_LABELS.get(risk.get("status"), risk.get("status")), styles["table"])])
    if len(rows) == 1:
        rows.append([_text("Nenhum risco ativo registrado.", styles["table"]), "", "", "", ""])
    table = Table(rows, colWidths=[65 * mm, 42 * mm, 24 * mm, 14 * mm, 23 * mm], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]
    if not risks:
        style.append(("SPAN", (0, 1), (-1, 1)))
    table.setStyle(TableStyle(style))
    return table


def _recommendation_table(items, styles):
    rows = [[_text("PRIORIDADE", styles["table_header"]), _text("AÇÃO RECOMENDADA", styles["table_header"]), _text("JUSTIFICATIVA", styles["table_header"])]]
    for item in items:
        rows.append([_text(item.get("priority"), styles["table_bold"]), _text(item.get("title"), styles["table_bold"]), _text(item.get("detail"), styles["table"])])
    table = Table(rows, colWidths=[25 * mm, 52 * mm, 91 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), VIOLET), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 6)]))
    return table


def _render_executive(story, payload, styles):
    metrics, remediation, compliance = payload.get("metrics") or {}, payload.get("remediation") or {}, payload.get("compliance") or {}
    _section(story, "1. Visão executiva", styles, "Leitura consolidada da exposição, evolução e capacidade de tratamento.")
    story.extend([_metric_cards(metrics, styles), Spacer(1, 5 * mm), Paragraph("Síntese do período", styles["h2"]), _text(payload.get("executive_summary"), styles["body"])])
    operational = [[_text("NOVOS RISCOS", styles["label"]), _text("RISCOS RESOLVIDOS", styles["label"]), _text("SCANS CONCLUÍDOS", styles["label"]), _text("PRONTIDÃO DE CONTROLES", styles["label"])], [_text(metrics.get("new_findings", 0), styles["metric"]), _text(metrics.get("resolved_findings", 0), styles["metric"]), _text((metrics.get("scan_jobs") or {}).get("completed", 0), styles["metric"]), _text(f"{compliance.get('score', 0)}%", styles["metric"])]]
    table = Table(operational, colWidths=[42 * mm] * 4)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), PANEL), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 6)]))
    story.extend([table, Paragraph("Distribuição dos riscos ativos", styles["h2"]), _severity_table(metrics, styles)])
    _section(story, "2. Riscos prioritários", styles, "Itens ativos ordenados pelo score de risco calculado pela plataforma.")
    story.extend([_top_risks_table(payload.get("top_risks") or [], styles), Paragraph("Capacidade de remediação", styles["h2"])])
    remediation_rows = [["Tarefas totais", remediation.get("total", 0)], ["Em aberto", remediation.get("open", 0)], ["Em andamento", remediation.get("in_progress", 0)], ["Concluídas", remediation.get("completed", 0)], ["Vencidas", remediation.get("overdue", 0)]]
    story.append(Table([[_text(label, styles["table"]), _text(value, styles["table_bold"])] for label, value in remediation_rows], colWidths=[130 * mm, 38 * mm], style=TableStyle([("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("ALIGN", (1, 0), (1, -1), "RIGHT"), ("PADDING", (0, 0), (-1, -1), 6)])))
    story.extend([Paragraph("Plano recomendado", styles["h2"]), _recommendation_table(payload.get("recommendations") or [], styles)])
    _section(story, "3. Governança e cobertura", styles, "Indicadores operacionais baseados em evidências disponíveis na Iron AI.")
    controls_rows = [[_text("CONTROLE", styles["table_header"]), _text("REFERÊNCIA", styles["table_header"]), _text("STATUS", styles["table_header"]), _text("EVIDÊNCIA", styles["table_header"])]]
    for item in compliance.get("controls") or []:
        controls_rows.append([_text(item.get("title"), styles["table_bold"]), _text(item.get("framework"), styles["table"]), _text({"implemented": "Implementado", "in_progress": "Em andamento", "not_started": "Não iniciado"}.get(item.get("status"), item.get("status")), styles["table"]), _text(item.get("evidence") or "Sem evidência registrada", styles["table"], 140)])
    controls_table = Table(controls_rows, colWidths=[47 * mm, 35 * mm, 27 * mm, 59 * mm], repeatRows=1)
    controls_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.extend([controls_table, Spacer(1, 4 * mm), _text(compliance.get("disclaimer") or "Indicador de prontidão; não representa certificação.", styles["small"])])


def _technical_summary(story, payload, styles):
    metrics = payload.get("metrics") or {}
    _section(story, "1. Escopo e resumo técnico", styles, "Inventário, execução de scanners e achados persistidos no período selecionado.")
    story.extend([_metric_cards(metrics, styles), Spacer(1, 5 * mm)])
    scope = [["Ativos no escopo", metrics.get("assets_total", 0)], ["Ativos expostos", metrics.get("assets_exposed", 0)], ["Scans executados no período", (metrics.get("scan_jobs") or {}).get("total", 0)], ["Scans concluídos", (metrics.get("scan_jobs") or {}).get("completed", 0)], ["Scans com falha", (metrics.get("scan_jobs") or {}).get("failed", 0)], ["Integrações conectadas", metrics.get("integrations_connected", 0)]]
    story.append(Table([[_text(label, styles["table"]), _text(value, styles["table_bold"])] for label, value in scope], colWidths=[130 * mm, 38 * mm], style=TableStyle([("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("ALIGN", (1, 0), (1, -1), "RIGHT"), ("PADDING", (0, 0), (-1, -1), 6)])))
    story.extend([Paragraph("Distribuição por severidade", styles["h2"]), _severity_table(metrics, styles), Paragraph("Metodologia", styles["h2"]), _text("O Security Score e a priorização combinam severidade, exposição à internet, criticidade do ativo, confiança, explorabilidade, idade e recorrência. O relatório representa o estado persistido na plataforma na data de emissão; validação manual pode ser necessária antes de mudanças em produção.", styles["body"])])


def _technical_assets(story, payload, styles):
    _section(story, "2. Inventário de ativos", styles)
    rows = [[_text("ATIVO", styles["table_header"]), _text("TIPO", styles["table_header"]), _text("AMBIENTE", styles["table_header"]), _text("CRITICIDADE", styles["table_header"]), _text("EXPOSIÇÃO", styles["table_header"]), _text("ÚLTIMA VISÃO", styles["table_header"])]]
    for asset in payload.get("assets") or []:
        rows.append([_text(asset.get("name"), styles["table_bold"], 85), _text(asset.get("type"), styles["table"]), _text(asset.get("environment"), styles["table"]), _text(SEVERITY_LABELS.get(asset.get("criticality"), str(asset.get("criticality") or "—").title()), styles["table"]), _text("Internet" if asset.get("internet_exposed") else "Interna", styles["table"]), _text(_date(asset.get("last_seen_at")), styles["table"])])
    if len(rows) == 1:
        rows.append([_text("Nenhum ativo registrado.", styles["table"]), "", "", "", "", ""])
    table = Table(rows, colWidths=[54 * mm, 22 * mm, 24 * mm, 25 * mm, 20 * mm, 23 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.append(table)


def _finding_block(item, index, styles):
    severity = (item.get("severity") or "informational").lower()
    title = f"{index}. {item.get('title') or 'Finding sem título'}"
    meta = [[_text("SEVERIDADE", styles["label"]), _text("RISK SCORE", styles["label"]), _text("STATUS", styles["label"]), _text("ATIVO", styles["label"])], [_text(SEVERITY_LABELS.get(severity, severity.title()), styles["table_bold"]), _text(item.get("risk_score", 0), styles["table_bold"]), _text(STATUS_LABELS.get(item.get("status"), item.get("status")), styles["table"]), _text(item.get("asset"), styles["table_bold"], 75)]]
    identifiers = " · ".join(filter(None, [item.get("cve"), item.get("cwe"), f"CVSS {item.get('cvss')}" if item.get("cvss") else None, item.get("scanner")])) or "Sem identificadores técnicos adicionais"
    content = [Table([[_text(title, styles["h3"]), _text(f"ID #{item.get('id', '—')}", styles["right"])]], colWidths=[140 * mm, 28 * mm], style=TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F1F5F9")), ("BOX", (0, 0), (-1, -1), 0.6, SEVERITY_COLORS.get(severity, MUTED)), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("PADDING", (0, 0), (-1, -1), 6)])), Table(meta, colWidths=[31 * mm, 28 * mm, 37 * mm, 72 * mm], style=TableStyle([("BOX", (0, 0), (-1, -1), 0.4, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)])), Spacer(1, 2 * mm), _text(identifiers, styles["small"])]
    if item.get("description"):
        content.extend([Paragraph("Descrição", styles["h3"]), _text(item.get("description"), styles["body"], 1600)])
    content.extend([Paragraph("Evidência", styles["h3"]), _text(item.get("evidence") or "Nenhuma evidência textual foi persistida para este finding.", styles["body"], 2200), Paragraph("Remediação recomendada", styles["h3"]), _text(item.get("remediation") or "Definir tratamento após validação técnica e análise do ativo afetado.", styles["body"], 1800), _text(f"Primeira observação: {_date(item.get('first_seen_at'), True)} UTC  ·  Última observação: {_date(item.get('last_seen_at'), True)} UTC  ·  Ocorrências: {item.get('occurrence_count') or 1}", styles["small"]), Spacer(1, 4 * mm)])
    return content


def _technical_findings(story, payload, styles):
    _section(story, "3. Achados técnicos", styles, "Detalhamento dos findings ordenados por risco, incluindo evidência e orientação de remediação.")
    findings = payload.get("findings_detail") or []
    if not findings:
        story.append(_text("Nenhum finding foi registrado no escopo deste relatório.", styles["body"]))
    for index, item in enumerate(findings, 1):
        story.extend(_finding_block(item, index, styles))


def _technical_operations(story, payload, styles):
    _section(story, "4. Execução e rastreabilidade", styles)
    rows = [[_text("JOB", styles["table_header"]), _text("SCANNER", styles["table_header"]), _text("ATIVO", styles["table_header"]), _text("STATUS", styles["table_header"]), _text("INÍCIO", styles["table_header"]), _text("CONCLUSÃO / ERRO", styles["table_header"])]]
    for job in payload.get("scan_jobs") or []:
        conclusion = _date(job.get("completed_at"), True) if job.get("completed_at") else (job.get("error") or "—")
        rows.append([_text(f"#{job.get('id')}", styles["table_bold"]), _text(job.get("scanner_type"), styles["table"]), _text(job.get("asset_id") or "—", styles["center"]), _text(STATUS_LABELS.get(job.get("status"), job.get("status")), styles["table"]), _text(_date(job.get("created_at"), True), styles["table"]), _text(conclusion, styles["table"], 120)])
    if len(rows) == 1:
        rows.append([_text("Nenhuma execução registrada no período.", styles["table"]), "", "", "", "", ""])
    table = Table(rows, colWidths=[14 * mm, 35 * mm, 16 * mm, 24 * mm, 31 * mm, 48 * mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 4)]))
    story.extend([table, Paragraph("Observações de uso", styles["h2"]), _text("Este documento é uma fotografia técnica dos registros da plataforma. Evidências devem ser validadas no contexto do ativo antes da aplicação de correções. Ausência de findings não comprova ausência de vulnerabilidades; cobertura depende dos ativos cadastrados, integrações e scanners executados.", styles["body"])])


def _general_governance_and_siem(story, payload, styles):
    governance = payload.get("governance") or {}
    _section(story, "5. Governança, políticas e conformidade", styles)
    policy_rows = [[_text("POLÍTICA", styles["table_header"]), _text("STATUS", styles["table_header"]), _text("VERSÃO PUBLICADA", styles["table_header"]), _text("ACEITES", styles["table_header"]), _text("PRÓXIMA REVISÃO", styles["table_header"])]]
    for policy in governance.get("policies") or []:
        published = next((item for item in policy.get("versions") or [] if item.get("id") == policy.get("published_version_id")), None)
        policy_rows.append([_text(policy.get("title"), styles["table_bold"], 70), _text(policy.get("status"), styles["table"]), _text(published.get("version") if published else "—", styles["center"]), _text(policy.get("acknowledgements", 0), styles["center"]), _text(_date(policy.get("next_review_at")), styles["table"])])
    if len(policy_rows) == 1:
        policy_rows.append([_text("Nenhuma política cadastrada.", styles["table"]), "", "", "", ""])
    policy_table = Table(policy_rows, colWidths=[61 * mm, 25 * mm, 31 * mm, 21 * mm, 31 * mm], repeatRows=1)
    policy_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.extend([policy_table, Paragraph("Detalhes dos itens", styles["h2"])])
    for policy in governance.get("policies") or []:
        story.extend([_text(f"{policy.get('title')} · {policy.get('slug')}", styles["table_bold"]), _text(policy.get("description") or "Sem descrição", styles["small"]), _text(f"Versões: {len(policy.get('versions') or [])} · Intervalo de revisão: {policy.get('review_interval_days') or '—'} dias", styles["small"])])
    siem = payload.get("siem") or {}
    _section(story, "6. SIEM nativo e monitoramento", styles, "Fontes, regras, eventos e incidentes persistidos no período selecionado.")
    siem_rows = [[_text("INDICADOR", styles["table_header"]), _text("QUANTIDADE", styles["table_header"]), _text("DETALHE", styles["table_header"])]]
    siem_rows.extend([[_text(label, styles["table_bold"]), _text(len(siem.get(key) or []), styles["center"]), _text(detail, styles["table"])] for label, key, detail in (("Fontes cadastradas", "sources", "Chaves identificadas apenas pelo prefixo"), ("Regras de detecção", "rules", "Condições declarativas avaliadas"), ("Eventos recebidos", "events", "Eventos normalizados no período"), ("Incidentes", "incidents", "Casos para investigação e resposta"), ("Sinais de monitoramento", "monitoring", "Telemetria defensiva correlacionada"))])
    siem_table = Table(siem_rows, colWidths=[54 * mm, 27 * mm, 88 * mm], repeatRows=1)
    siem_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.extend([siem_table, Paragraph("Incidentes registrados", styles["h2"])])
    incidents = siem.get("incidents") or []
    incident_rows = [[_text("ID", styles["table_header"]), _text("TÍTULO", styles["table_header"]), _text("SEVERIDADE", styles["table_header"]), _text("STATUS", styles["table_header"]), _text("DATA", styles["table_header"])]]
    for incident in incidents[:100]:
        incident_rows.append([_text(f"#{incident.get('id')}", styles["table_bold"]), _text(incident.get("title"), styles["table"], 85), _text(SEVERITY_LABELS.get(incident.get("severity"), incident.get("severity")), styles["table"]), _text(STATUS_LABELS.get(incident.get("status"), incident.get("status")), styles["table"]), _text(_date(incident.get("created_at"), True), styles["table"])])
    if len(incident_rows) == 1:
        incident_rows.append([_text("Nenhum incidente registrado.", styles["table"]), "", "", "", ""])
    incident_table = Table(incident_rows, colWidths=[15 * mm, 73 * mm, 26 * mm, 28 * mm, 27 * mm], repeatRows=1)
    incident_table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL]), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.35, LINE), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("PADDING", (0, 0), (-1, -1), 5)]))
    story.extend([incident_table, Paragraph("Auditoria da plataforma", styles["h2"]), _text(f"{len(payload.get('audit') or [])} registros de auditoria foram incluídos, juntamente com os dados de inventário, riscos, tarefas, integrações, membros e execução persistidos.", styles["body"])])


def render_report_pdf(report: Report) -> bytes:
    output = BytesIO()
    styles = _styles()
    payload = report.payload or {}
    document = SimpleDocTemplate(output, pagesize=A4, rightMargin=21 * mm, leftMargin=21 * mm, topMargin=21 * mm, bottomMargin=20 * mm, title="Iron AI Security Report", author="Iron AI", subject="Relatório de segurança baseado em dados persistidos")
    story = []
    _cover(story, report, payload, styles)
    if report.report_type == "technical":
        _technical_summary(story, payload, styles)
        _technical_assets(story, payload, styles)
        _technical_findings(story, payload, styles)
        _technical_operations(story, payload, styles)
    elif report.report_type == "general":
        _technical_summary(story, payload, styles)
        _technical_assets(story, payload, styles)
        _technical_findings(story, payload, styles)
        _technical_operations(story, payload, styles)
        _general_governance_and_siem(story, payload, styles)
    else:
        _render_executive(story, payload, styles)
    document.build(story, onFirstPage=lambda canvas, doc: _header_footer(canvas, doc, payload), onLaterPages=lambda canvas, doc: _header_footer(canvas, doc, payload))
    return output.getvalue()
