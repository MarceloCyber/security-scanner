"""Add deterministic risk fields to normalized findings."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "002_risk_fields"


def upgrade():
    with engine.begin() as connection:
        if not inspect(engine).has_table("findings"):
            return
        columns = {column["name"] for column in inspect(engine).get_columns("findings")}
        if "risk_score" not in columns:
            connection.execute(text("ALTER TABLE findings ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0"))
        if "risk_factors" not in columns:
            column_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
            connection.execute(text(f"ALTER TABLE findings ADD COLUMN risk_factors {column_type}"))
