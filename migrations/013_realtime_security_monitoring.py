"""Add tenant-scoped realtime security sensors, events and containment actions."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "013_realtime_security_monitoring"


def upgrade():
    Base.metadata.create_all(
        bind=engine,
        tables=[
            saas.SecuritySensor.__table__,
            saas.SecurityEvent.__table__,
            saas.ContainmentAction.__table__,
        ],
    )
