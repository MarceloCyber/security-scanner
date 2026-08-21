"""Add short-lived assisted containment tests."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "017_assisted_containment_tests"


def upgrade():
    if not inspect(engine).has_table("organizations") or not inspect(engine).has_table("security_events"):
        return
    id_type = "SERIAL" if engine.dialect.name == "postgresql" else "INTEGER"
    with engine.begin() as connection:
        connection.execute(text(f"""
            CREATE TABLE IF NOT EXISTS containment_tests (
                id {id_type} PRIMARY KEY,
                organization_id INTEGER NOT NULL,
                asset_id INTEGER NOT NULL,
                token_hash VARCHAR(64) NOT NULL UNIQUE,
                created_by INTEGER,
                expires_at TIMESTAMP NOT NULL,
                opened_at TIMESTAMP,
                source_ip VARCHAR(64),
                security_event_id INTEGER,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
                FOREIGN KEY (security_event_id) REFERENCES security_events(id) ON DELETE SET NULL
            )
        """))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_tests_token ON containment_tests (token_hash)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_tests_org_created ON containment_tests (organization_id, created_at)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_tests_expires ON containment_tests (expires_at)"))
