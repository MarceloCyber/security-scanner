"""Add an explicit developer permission for advanced security tooling."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "006_developer_access"


def upgrade():
    if not inspect(engine).has_table("users"):
        return
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "is_developer" not in columns:
        default = "FALSE" if engine.dialect.name == "postgresql" else "0"
        with engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE users ADD COLUMN is_developer BOOLEAN DEFAULT {default}"))
            connection.execute(text(f"UPDATE users SET is_developer = {default} WHERE is_developer IS NULL"))
