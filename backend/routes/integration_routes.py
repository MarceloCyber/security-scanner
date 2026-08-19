from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
import requests
from sqlalchemy.orm import Session

from database import get_db
from integrations.github_provider import GitHubProvider
from integrations.gitlab_provider import GitLabProvider
from integrations.azure_devops_provider import AzureDevOpsProvider
from integrations.jira_provider import JiraProvider
from models.saas import Asset, Integration, IntegrationCredential
from services.audit_service import record_audit
from services.credential_vault import CredentialVault
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


class GitHubConnect(BaseModel):
    token: str = Field(min_length=20, max_length=500)


class GitLabConnect(BaseModel):
    token: str = Field(min_length=20, max_length=500)
    base_url: str = Field(default="https://gitlab.com", max_length=500)


class AzureDevOpsConnect(BaseModel):
    token: str = Field(min_length=20, max_length=500)
    organization: str = Field(min_length=2, max_length=100)


class JiraConnect(BaseModel):
    token: str = Field(min_length=20, max_length=500)
    base_url: str = Field(max_length=500)
    email: str = Field(min_length=3, max_length=320)
    project_key: str | None = Field(default=None, max_length=30)


class JiraIssueCreate(BaseModel):
    finding_id: int
    project_key: str | None = Field(default=None, max_length=30)


def _vault() -> CredentialVault:
    try:
        return CredentialVault()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))


def _save_connection(db: Session, context: TenantContext, provider: str, token: str, configuration: dict) -> Integration:
    integration = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == provider).first()
    if not integration:
        integration = Integration(organization_id=context.organization.id, provider=provider)
        db.add(integration)
        db.flush()
    integration.status = "connected"
    integration.configuration = configuration
    encrypted = _vault().encrypt(token)
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id).first()
    if credential:
        credential.encrypted_secret = encrypted
        credential.secret_hint = token[-4:]
    else:
        db.add(IntegrationCredential(organization_id=context.organization.id, integration_id=integration.id, encrypted_secret=encrypted, secret_hint=token[-4:]))
    return integration


def _provider(integration: Integration):
    config = integration.configuration or {}
    if integration.provider == "github":
        return GitHubProvider()
    if integration.provider == "gitlab":
        return GitLabProvider(config.get("base_url") or "https://gitlab.com")
    if integration.provider == "azure_devops":
        return AzureDevOpsProvider(config.get("organization") or config.get("account") or "")
    if integration.provider == "jira":
        return JiraProvider(config.get("base_url") or "", config.get("email") or "")
    raise ValueError("Provedor de integração não suportado")


@router.get("/integrations")
def list_integrations(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    integrations = db.query(Integration).filter(Integration.organization_id == context.organization.id).all()
    return {"integrations": [{"id": item.id, "provider": item.provider, "status": item.status, "configuration": item.configuration or {}, "last_synced_at": item.last_synced_at.isoformat() if item.last_synced_at else None} for item in integrations]}


@router.post("/integrations/github/connect")
def connect_github(payload: GitHubConnect, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    try:
        account = GitHubProvider().validate(payload.token)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail="Não foi possível validar a credencial GitHub") from exc
    integration = _save_connection(db, context, "github", payload.token, account)
    record_audit(db, context, "integration_connected", "integration", integration.id, request, {"provider": "github", "account": account.get("account")})
    db.commit()
    return {"id": integration.id, "provider": "github", "status": "connected", "account": account.get("account")}


@router.post("/integrations/gitlab/connect")
def connect_gitlab(payload: GitLabConnect, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    try:
        account = GitLabProvider(payload.base_url).validate(payload.token)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail="Não foi possível validar a credencial GitLab") from exc
    integration = _save_connection(db, context, "gitlab", payload.token, account)
    record_audit(db, context, "integration_connected", "integration", integration.id, request, {"provider": "gitlab", "account": account.get("account")})
    db.commit()
    return {"id": integration.id, "provider": "gitlab", "status": "connected", "account": account.get("account")}


@router.post("/integrations/azure-devops/connect")
def connect_azure_devops(payload: AzureDevOpsConnect, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    try:
        provider = AzureDevOpsProvider(payload.organization)
        account = provider.validate(payload.token)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail="Não foi possível validar o PAT do Azure DevOps") from exc
    account["organization"] = provider.organization
    integration = _save_connection(db, context, "azure_devops", payload.token, account)
    record_audit(db, context, "integration_connected", "integration", integration.id, request, {"provider": "azure_devops", "account": provider.organization})
    db.commit()
    return {"id": integration.id, "provider": "azure_devops", "status": "connected", "account": provider.organization}


@router.post("/integrations/jira/connect")
def connect_jira(payload: JiraConnect, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    try:
        provider = JiraProvider(payload.base_url, payload.email)
        account = provider.validate(payload.token)
        projects = provider.list_projects(payload.token)
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail="Não foi possível validar a integração Jira") from exc
    selected = (payload.project_key or "").upper() or (projects[0]["key"] if projects else None)
    account.update({"project_key": selected, "projects": projects[:100]})
    integration = _save_connection(db, context, "jira", payload.token, account)
    record_audit(db, context, "integration_connected", "integration", integration.id, request, {"provider": "jira", "account": account.get("account"), "project_key": selected})
    db.commit()
    return {"id": integration.id, "provider": "jira", "status": "connected", "account": account.get("account"), "projects": projects}


@router.post("/integrations/{integration_id}/sync")
def sync_integration(integration_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    integration = db.query(Integration).filter(Integration.id == integration_id, Integration.organization_id == context.organization.id).first()
    if not integration or integration.provider not in {"github", "gitlab", "azure_devops", "jira"}:
        raise HTTPException(status_code=404, detail="Integration not found")
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id, IntegrationCredential.organization_id == context.organization.id).first()
    if not credential:
        raise HTTPException(status_code=409, detail="Integration credential unavailable")
    try:
        token = _vault().decrypt(credential.encrypted_secret)
        provider = _provider(integration)
        if integration.provider == "jira":
            projects = provider.list_projects(token)
            config = dict(integration.configuration or {})
            config["projects"] = projects[:100]
            integration.configuration = config
            integration.status = "connected"
            integration.last_synced_at = datetime.utcnow()
            record_audit(db, context, "integration_synced", "integration", integration.id, request, {"provider": "jira", "projects": len(projects)})
            db.commit()
            return {"projects": len(projects), "assets_created": 0}
        repositories = provider.sync_assets(token)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        integration.status = "failed"
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc))
    created = 0
    for repo in repositories:
        asset = db.query(Asset).filter(Asset.organization_id == context.organization.id, Asset.type == "repository", Asset.name == repo["name"]).first()
        if not asset:
            db.add(Asset(organization_id=context.organization.id, type="repository", name=repo["name"], url=repo.get("url"), metadata_json={"private": repo.get("private"), "default_branch": repo.get("default_branch")}))
            created += 1
    integration.status = "connected"
    integration.last_synced_at = datetime.utcnow()
    record_audit(db, context, "integration_synced", "integration", integration.id, request, {"provider": integration.provider, "repositories": len(repositories), "created": created})
    db.commit()
    return {"repositories": len(repositories), "assets_created": created}


@router.post("/integrations/jira/issues")
def create_jira_issue(payload: JiraIssueCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    from models.saas import Finding
    integration = db.query(Integration).filter(Integration.organization_id == context.organization.id, Integration.provider == "jira", Integration.status == "connected").first()
    if not integration:
        raise HTTPException(status_code=409, detail="Conecte o Jira antes de criar tarefas")
    finding = db.query(Finding).filter(Finding.id == payload.finding_id, Finding.organization_id == context.organization.id).first()
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id, IntegrationCredential.organization_id == context.organization.id).first()
    if not finding or not credential:
        raise HTTPException(status_code=404, detail="Finding ou credencial não encontrado")
    project_key = (payload.project_key or (integration.configuration or {}).get("project_key") or "").upper()
    if not project_key:
        raise HTTPException(status_code=400, detail="Selecione um projeto Jira")
    description = f"Finding Iron AI #{finding.id}\nSeveridade: {finding.severity}\nScore: {finding.risk_score}\n\n{finding.description or ''}\n\nCorreção recomendada:\n{finding.remediation or ''}"
    try:
        result = _provider(integration).create_issue(_vault().decrypt(credential.encrypted_secret), project_key, f"[Iron AI] {finding.title}", description)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        raise HTTPException(status_code=502, detail="O Jira recusou a criação da tarefa") from exc
    record_audit(db, context, "jira_issue_created", "finding", finding.id, request, {"jira_key": result.get("key"), "project_key": project_key})
    db.commit()
    return result


@router.delete("/integrations/{integration_id}")
def disconnect_integration(integration_id: int, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    integration = db.query(Integration).filter(Integration.id == integration_id, Integration.organization_id == context.organization.id).first()
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    credential = db.query(IntegrationCredential).filter(IntegrationCredential.integration_id == integration.id, IntegrationCredential.organization_id == context.organization.id).first()
    if credential:
        db.delete(credential)
    integration.status = "disconnected"
    record_audit(db, context, "integration_disconnected", "integration", integration.id, request, {"provider": integration.provider})
    db.commit()
    return {"success": True}
