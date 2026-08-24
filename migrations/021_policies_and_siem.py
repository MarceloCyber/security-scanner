"""Create managed security policies and the native SIEM core."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "021_policies_and_siem"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[
        saas.SecurityPolicy.__table__,
        saas.SecurityPolicyVersion.__table__,
        saas.SecurityPolicyAcknowledgement.__table__,
        saas.SiemSource.__table__,
        saas.SiemRule.__table__,
        saas.SiemEvent.__table__,
        saas.SiemIncident.__table__,
        saas.SiemAlertDelivery.__table__,
    ])
