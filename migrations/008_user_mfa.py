"""Add encrypted TOTP multi-factor authentication fields."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "008_user_mfa"


def upgrade():
    if not inspect(engine).has_table("users"):
        return
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "mfa_enabled" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN DEFAULT FALSE"))
        if "mfa_secret_encrypted" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_secret_encrypted TEXT"))
        if "mfa_recovery_codes_hash" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN mfa_recovery_codes_hash TEXT"))
        connection.execute(text("UPDATE users SET mfa_enabled = FALSE WHERE mfa_enabled IS NULL"))
