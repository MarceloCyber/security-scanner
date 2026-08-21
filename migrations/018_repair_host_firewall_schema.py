"""Reconcile host-firewall columns when migration 016 was recorded before completing."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "018_repair_host_firewall_schema"


def _columns(table_name):
    inspector = inspect(engine)
    return {item["name"] for item in inspector.get_columns(table_name)} if inspector.has_table(table_name) else set()


def upgrade():
    sensor_columns = _columns("security_sensors")
    action_columns = _columns("containment_actions")
    if not sensor_columns or not action_columns:
        raise RuntimeError("Realtime monitoring tables are missing; migration 013 must be applied first")
    boolean_type = "BOOLEAN" if engine.dialect.name == "postgresql" else "INTEGER"
    boolean_default = "FALSE" if engine.dialect.name == "postgresql" else "0"
    with engine.begin() as connection:
        if "containment_enabled" not in sensor_columns:
            connection.execute(text(f"ALTER TABLE security_sensors ADD COLUMN containment_enabled {boolean_type} NOT NULL DEFAULT {boolean_default}"))
        if "agent_version" not in sensor_columns:
            connection.execute(text("ALTER TABLE security_sensors ADD COLUMN agent_version VARCHAR(40)"))
        if "sensor_id" not in action_columns:
            connection.execute(text("ALTER TABLE containment_actions ADD COLUMN sensor_id INTEGER REFERENCES security_sensors(id) ON DELETE SET NULL"))
        if "expires_at" not in action_columns:
            connection.execute(text("ALTER TABLE containment_actions ADD COLUMN expires_at TIMESTAMP"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_actions_sensor_status ON containment_actions (sensor_id, status)"))

    repaired_sensors = _columns("security_sensors")
    repaired_actions = _columns("containment_actions")
    missing = {
        "security_sensors": sorted({"containment_enabled", "agent_version"} - repaired_sensors),
        "containment_actions": sorted({"sensor_id", "expires_at"} - repaired_actions),
    }
    if any(missing.values()):
        raise RuntimeError(f"Host-firewall schema reconciliation failed: {missing}")
