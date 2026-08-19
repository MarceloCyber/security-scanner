"""Add reporting, integrations and approval-gated AI actions."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "004_platform_operations"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[
        saas.Report.__table__, saas.Integration.__table__,
        saas.IntegrationCredential.__table__, saas.AIAction.__table__,
    ])
