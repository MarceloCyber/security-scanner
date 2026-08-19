"""Create or reset a development-only owner account in the local SQLite DB."""

import argparse
import getpass
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND))
os.environ["APP_ENV"] = "development"
os.environ["DATABASE_URL"] = f"sqlite:///{BACKEND / 'security_scanner.db'}"
os.environ["REDIS_URL"] = ""

from auth import get_password_hash  # noqa: E402
from database import SessionLocal  # noqa: E402
from models.saas import Asset, Finding, Organization, OrganizationMember  # noqa: E402
from models.user import User  # noqa: E402
from risk.engine import create_snapshot  # noqa: E402


def seed_demo_data(db, organization_id: int):
    assets_data = [
        ("api.demo.local", "api", "production", "critical", True),
        ("app.demo.local", "web_application", "production", "high", True),
        ("ironnet/demo-repository", "repository", "development", "medium", False),
    ]
    assets = {}
    for name, asset_type, environment, criticality, exposed in assets_data:
        asset = db.query(Asset).filter(Asset.organization_id == organization_id, Asset.name == name).first()
        if not asset:
            asset = Asset(organization_id=organization_id, name=name, type=asset_type, environment=environment, criticality=criticality, internet_exposed=exposed, metadata_json={"demo": True})
            db.add(asset)
            db.flush()
        assets[name] = asset

    findings_data = [
        ("demo-public-api-auth", "Autenticação insuficiente em API pública", "critical", "confirmed", "api.demo.local", "Restringir o endpoint, exigir autenticação forte e validar autorização por recurso."),
        ("demo-admin-service", "Serviço administrativo exposto à internet", "high", "high", "app.demo.local", "Restringir o acesso por VPN ou allowlist e remover exposição pública desnecessária."),
        ("demo-dependency", "Dependência desatualizada no repositório", "medium", "medium", "ironnet/demo-repository", "Atualizar a dependência e executar os testes de regressão."),
    ]
    for fingerprint, title, severity, confidence, asset_name, remediation in findings_data:
        finding = db.query(Finding).filter(Finding.organization_id == organization_id, Finding.fingerprint == fingerprint).first()
        if not finding:
            db.add(Finding(organization_id=organization_id, asset_id=assets[asset_name].id, fingerprint=fingerprint, title=title, description="Finding de demonstração para validação local da plataforma.", category="demo", severity=severity, confidence=confidence, status="open", evidence="Evidência sintética; não representa um scan real.", remediation=remediation, scanner_source="demo_seed"))
    db.flush()
    create_snapshot(db, organization_id)


def main():
    parser = argparse.ArgumentParser(description="Create/reset a local IronNet test user")
    parser.add_argument("--username", default="localadmin")
    parser.add_argument("--email", default="localadmin@example.com")
    parser.add_argument("--demo-data", action="store_true", help="Create synthetic assets/findings for local UI testing")
    args = parser.parse_args()
    password = getpass.getpass("Senha local (mínimo 8 caracteres): ")
    confirmation = getpass.getpass("Confirme a senha: ")
    if password != confirmation:
        raise SystemExit("As senhas não conferem.")
    if len(password) < 8:
        raise SystemExit("A senha precisa ter pelo menos 8 caracteres.")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == args.username).first()
        if not user:
            user = User(username=args.username, email=args.email, hashed_password=get_password_hash(password))
            db.add(user)
            db.flush()
        else:
            user.email = args.email
            user.hashed_password = get_password_hash(password)
        user.subscription_plan = "enterprise"
        user.subscription_status = "active"
        user.is_admin = True
        user.is_developer = True
        user.scans_limit = -1
        user.access_key_required = False
        user.access_key_hash = None
        user.access_key_used_at = None
        user.active_session_hash = None
        user.active_session_last_activity = None

        membership = db.query(OrganizationMember).filter(OrganizationMember.user_id == user.id).first()
        if not membership:
            organization = Organization(name="Local Test Organization", slug=f"local-test-{user.id}", plan="enterprise")
            db.add(organization)
            db.flush()
            db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner"))
            db.flush()
            organization_id = organization.id
        else:
            organization_id = membership.organization_id
            organization = db.query(Organization).filter(Organization.id == organization_id).first()
            if organization:
                organization.plan = "enterprise"
        if args.demo_data:
            seed_demo_data(db, organization_id)
        db.commit()
        print(f"Usuário local pronto: {user.username}")
        if args.demo_data:
            print("Dados sintéticos de demonstração criados.")
        print("Inicie com: ./start.sh --local")
    finally:
        db.close()


if __name__ == "__main__":
    main()
