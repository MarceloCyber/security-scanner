"""Add organization-scoped compliance evidence."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "009_compliance_attestations"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[saas.ComplianceAttestation.__table__])
