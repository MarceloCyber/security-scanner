"""Add restricted host-firewall containment capabilities to sensors and actions."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "016_host_firewall_containment"


def _columns(table):
    return {item["name"] for item in inspect(engine).get_columns(table)}


def upgrade():
    if not inspect(engine).has_table("security_sensors") or not inspect(engine).has_table("containment_actions"):
        return
    sensor_columns = _columns("security_sensors")
    action_columns = _columns("containment_actions")
    boolean_type = "BOOLEAN" if engine.dialect.name == "postgresql" else "INTEGER"
    with engine.begin() as connection:
        if "containment_enabled" not in sensor_columns:
            connection.execute(text(f"ALTER TABLE security_sensors ADD COLUMN containment_enabled {boolean_type} NOT NULL DEFAULT 0"))
        if "agent_version" not in sensor_columns:
            connection.execute(text("ALTER TABLE security_sensors ADD COLUMN agent_version VARCHAR(40)"))
        if "sensor_id" not in action_columns:
            connection.execute(text("ALTER TABLE containment_actions ADD COLUMN sensor_id INTEGER REFERENCES security_sensors(id) ON DELETE SET NULL"))
        if "expires_at" not in action_columns:
            connection.execute(text("ALTER TABLE containment_actions ADD COLUMN expires_at TIMESTAMP"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_containment_actions_sensor_status ON containment_actions (sensor_id, status)"))
