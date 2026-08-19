"""Add scoped CI/CD credentials for Iron AI Security Gates."""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine  # noqa: E402
from models import saas  # noqa: F401,E402

VERSION = "007_pipeline_api_keys"


def upgrade():
    Base.metadata.create_all(bind=engine, tables=[saas.PipelineApiKey.__table__])
