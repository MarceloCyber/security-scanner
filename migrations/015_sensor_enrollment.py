"""Create one-time enrollment records for guided sensor installation."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "015_sensor_enrollment"


def upgrade():
    if not inspect(engine).has_table("organizations"):
        return
    id_type = "SERIAL" if engine.dialect.name == "postgresql" else "INTEGER"
    with engine.begin() as connection:
        connection.execute(text(f"""
            CREATE TABLE IF NOT EXISTS sensor_enrollments (
                id {id_type} PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                sensor_name VARCHAR(120) NOT NULL,
                token_hash VARCHAR(64) NOT NULL UNIQUE,
                created_by INTEGER,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
            )
        """))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_sensor_enrollments_token ON sensor_enrollments (token_hash)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_sensor_enrollments_expires ON sensor_enrollments (expires_at)"))
