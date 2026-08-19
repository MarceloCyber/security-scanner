"""Persist structured results for real web security scan jobs."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "005_web_scan_jobs"


def upgrade():
    if not inspect(engine).has_table("scan_jobs"):
        return
    columns = {column["name"] for column in inspect(engine).get_columns("scan_jobs")}
    if "result" not in columns:
        column_type = "JSONB" if engine.dialect.name == "postgresql" else "JSON"
        with engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE scan_jobs ADD COLUMN result {column_type}"))
