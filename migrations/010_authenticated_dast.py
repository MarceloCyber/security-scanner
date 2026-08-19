"""Add encrypted profiles for same-origin authenticated web scans."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "010_authenticated_dast"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[saas.AuthenticatedScanProfile.__table__])
