from datetime import datetime, timedelta
import base64
import hashlib
import os
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from jose import jwt
from pydantic import BaseModel, Field
import requests
from sqlalchemy.orm import Session

from auth import create_renewal_token, create_session_token, require_enterprise, session_hash
from database import get_db
from integrations.http_safety import public_https_base
from models.saas import EnterpriseSSOConfig, Organization, OrganizationMember, SSOLoginState
from models.user import User
from services.audit_service import record_audit
from services.credential_vault import CredentialVault
from services.tenant import TenantContext, get_tenant_context, require_roles
from services.plan_policy import is_plan_expired

router = APIRouter()


class SSOConfigInput(BaseModel):
    issuer: str = Field(max_length=500)
    client_id: str = Field(min_length=3, max_length=300)
    client_secret: str = Field(min_length=8, max_length=2000)
    allowed_domains: list[str] = Field(min_length=1, max_length=20)
    require_mfa_claim: bool = True
    enabled: bool = True


class SSOExchange(BaseModel):
    code: str = Field(min_length=30, max_length=300)


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _discovery(issuer: str) -> dict:
    safe_issuer = public_https_base(issuer)
    response = requests.get(f"{safe_issuer}/.well-known/openid-configuration", headers={"Accept": "application/json"}, timeout=12)
    if response.status_code != 200:
        raise ValueError("Não foi possível carregar a configuração OIDC")
    data = response.json()
    for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        data[key] = public_https_base(data.get(key) or "")
    if (data.get("issuer") or "").rstrip("/") != safe_issuer:
        raise ValueError("Issuer OIDC inconsistente")
    return data


@router.get("/sso/config")
def get_sso_config(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    item = db.query(EnterpriseSSOConfig).filter(EnterpriseSSOConfig.organization_id == context.organization.id).first()
    if not item:
        return {"configured": False, "enabled": False, "organization_slug": context.organization.slug}
    return {"configured": True, "enabled": item.enabled, "issuer": item.issuer, "client_id": item.client_id, "allowed_domains": item.allowed_domains or [], "require_mfa_claim": item.require_mfa_claim, "organization_slug": context.organization.slug}


@router.put("/sso/config")
def configure_sso(payload: SSOConfigInput, request: Request, context: TenantContext = Depends(require_roles("owner", "admin")), db: Session = Depends(get_db)):
    require_enterprise(context.user)
    domains = sorted({item.strip().lower().lstrip("@") for item in payload.allowed_domains if "." in item and "@" not in item})
    if not domains:
        raise HTTPException(status_code=400, detail="Informe ao menos um domínio de email válido")
    try:
        discovery = _discovery(payload.issuer)
        encrypted = CredentialVault().encrypt(payload.client_secret)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail="Não foi possível validar a configuração OIDC") from exc
    item = db.query(EnterpriseSSOConfig).filter(EnterpriseSSOConfig.organization_id == context.organization.id).first()
    if not item:
        item = EnterpriseSSOConfig(organization_id=context.organization.id, created_by=context.user.id)
        db.add(item)
    item.issuer = discovery["issuer"].rstrip("/")
    item.client_id = payload.client_id.strip()
    item.encrypted_client_secret = encrypted
    item.allowed_domains = domains
    item.require_mfa_claim = payload.require_mfa_claim
    item.enabled = payload.enabled
    record_audit(db, context, "enterprise_sso_configured", "sso_config", context.organization.id, request, {"issuer": item.issuer, "domains": domains, "require_mfa_claim": item.require_mfa_claim})
    db.commit()
    return {"configured": True, "enabled": item.enabled, "organization_slug": context.organization.slug}


@router.get("/auth/sso/{organization_slug}/start")
def start_sso(organization_slug: str, db: Session = Depends(get_db)):
    organization = db.query(Organization).filter(Organization.slug == organization_slug, Organization.status == "active").first()
    config = db.query(EnterpriseSSOConfig).filter(EnterpriseSSOConfig.organization_id == organization.id, EnterpriseSSOConfig.enabled.is_(True)).first() if organization else None
    if not config:
        raise HTTPException(status_code=404, detail="SSO não está habilitado para esta organização")
    try:
        discovery = _discovery(config.issuer)
        verifier = secrets.token_urlsafe(64)
        state = secrets.token_urlsafe(40)
        nonce = secrets.token_urlsafe(32)
        encrypted_verifier = CredentialVault().encrypt(verifier)
    except (ValueError, RuntimeError, requests.RequestException) as exc:
        raise HTTPException(status_code=503, detail="SSO temporariamente indisponível") from exc
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    callback = f"{os.getenv('FRONTEND_URL', 'http://localhost:8000').rstrip('/')}/api/auth/sso/callback"
    login_state = SSOLoginState(organization_id=organization.id, state_hash=_hash(state), nonce_hash=_hash(nonce), encrypted_code_verifier=encrypted_verifier, expires_at=datetime.utcnow() + timedelta(minutes=10))
    db.add(login_state)
    db.commit()
    query = urlencode({"client_id": config.client_id, "response_type": "code", "scope": "openid email profile", "redirect_uri": callback, "state": state, "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256"})
    return RedirectResponse(f"{discovery['authorization_endpoint']}?{query}", status_code=302)


@router.get("/auth/sso/callback")
def sso_callback(code: str, state: str, db: Session = Depends(get_db)):
    frontend = os.getenv("FRONTEND_URL", "http://localhost:8000").rstrip("/")
    item = db.query(SSOLoginState).filter(SSOLoginState.state_hash == _hash(state), SSOLoginState.used_at.is_(None)).first()
    if not item or item.expires_at < datetime.utcnow():
        return RedirectResponse(f"{frontend}/index.html?sso_error=expired", status_code=302)
    item.used_at = datetime.utcnow()
    config = db.query(EnterpriseSSOConfig).filter(EnterpriseSSOConfig.organization_id == item.organization_id, EnterpriseSSOConfig.enabled.is_(True)).first()
    try:
        discovery = _discovery(config.issuer)
        callback = f"{frontend}/api/auth/sso/callback"
        client_secret = CredentialVault().decrypt(config.encrypted_client_secret)
        token_data = {"grant_type": "authorization_code", "code": code, "redirect_uri": callback, "client_id": config.client_id, "code_verifier": CredentialVault().decrypt(item.encrypted_code_verifier)}
        auth_methods = discovery.get("token_endpoint_auth_methods_supported") or ["client_secret_basic"]
        token_auth = None
        if "client_secret_post" in auth_methods:
            token_data["client_secret"] = client_secret
        else:
            token_auth = (config.client_id, client_secret)
        token_response = requests.post(discovery["token_endpoint"], data=token_data, auth=token_auth, headers={"Accept": "application/json"}, timeout=15)
        token_response.raise_for_status()
        id_token = token_response.json()["id_token"]
        header = jwt.get_unverified_header(id_token)
        algorithm = str(header.get("alg") or "")
        if algorithm not in {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}:
            raise ValueError("Algoritmo de assinatura OIDC não permitido")
        jwks_response = requests.get(discovery["jwks_uri"], timeout=12)
        jwks_response.raise_for_status()
        key = next(key for key in jwks_response.json().get("keys", []) if key.get("kid") == header.get("kid"))
        if key.get("alg") and key.get("alg") != algorithm:
            raise ValueError("Algoritmo OIDC inconsistente")
        claims = jwt.decode(id_token, key, algorithms=[algorithm], audience=config.client_id, issuer=config.issuer)
        if _hash(str(claims.get("nonce") or "")) != item.nonce_hash:
            raise ValueError("Nonce inválido")
        email = str(claims.get("email") or "").lower()
        if claims.get("email_verified") is False or not any(email.endswith(f"@{domain}") for domain in (config.allowed_domains or [])):
            raise ValueError("Domínio não autorizado")
        amr = claims.get("amr") or []
        acr = str(claims.get("acr") or "").lower()
        if config.require_mfa_claim and not ({"mfa", "otp"} & {str(value).lower() for value in amr}) and "mfa" not in acr:
            raise ValueError("MFA do IdP não comprovado")
        user = db.query(User).join(OrganizationMember, OrganizationMember.user_id == User.id).filter(User.email == email, OrganizationMember.organization_id == item.organization_id).first()
        if not user or user.subscription_plan != "enterprise" or (user.subscription_status != "active" and not is_plan_expired(user.subscription_plan, user.subscription_end)):
            raise ValueError("Usuário não provisionado")
        exchange = secrets.token_urlsafe(48)
        item.authenticated_user_id = user.id
        item.exchange_code_hash = _hash(exchange)
        item.exchange_expires_at = datetime.utcnow() + timedelta(seconds=60)
        db.commit()
        return RedirectResponse(f"{frontend}/index.html?sso_code={exchange}", status_code=302)
    except Exception:
        db.commit()
        return RedirectResponse(f"{frontend}/index.html?sso_error=denied", status_code=302)


@router.post("/auth/sso/exchange")
def exchange_sso(payload: SSOExchange, db: Session = Depends(get_db)):
    item = db.query(SSOLoginState).filter(SSOLoginState.exchange_code_hash == _hash(payload.code), SSOLoginState.authenticated_user_id.isnot(None), SSOLoginState.used_at.isnot(None)).first()
    if not item or not item.exchange_expires_at or item.exchange_expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Código SSO inválido ou expirado")
    user = db.query(User).join(OrganizationMember, OrganizationMember.user_id == User.id).join(Organization, Organization.id == OrganizationMember.organization_id).filter(User.id == item.authenticated_user_id, User.subscription_plan == "enterprise", OrganizationMember.organization_id == item.organization_id, Organization.status == "active").first()
    if not user:
        raise HTTPException(status_code=403, detail="Usuário SSO não está mais autorizado")
    if is_plan_expired(user.subscription_plan, user.subscription_end):
        user.subscription_status = "expired"
        db.commit()
        raise HTTPException(status_code=402, detail={
            "error": "subscription_renewal_required",
            "message": "O período Enterprise terminou. Renove para continuar com o SSO.",
            "plan": "enterprise",
            "expired_at": user.subscription_end.isoformat(),
            "renewal_token": create_renewal_token(user),
        })
    if user.subscription_status != "active":
        raise HTTPException(status_code=403, detail="Usuário SSO não está mais autorizado")
    session_id = secrets.token_urlsafe(32)
    user.active_session_hash = session_hash(session_id)
    user.active_session_last_activity = datetime.utcnow()
    item.exchange_code_hash = None
    item.exchange_expires_at = None
    db.commit()
    return {"access_token": create_session_token(user.username, session_id), "token_type": "bearer", "username": user.username}
