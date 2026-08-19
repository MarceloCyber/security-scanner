"""Add Enterprise OpenID Connect SSO configuration and one-time login states."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "012_enterprise_oidc_sso"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[saas.EnterpriseSSOConfig.__table__, saas.SSOLoginState.__table__])
