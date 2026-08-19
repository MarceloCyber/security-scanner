"""Track the Stripe Checkout Session that granted the latest entitlement."""

from pathlib import Path
import sys

from sqlalchemy import inspect, text

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import engine  # noqa: E402

VERSION = "014_payment_entitlement_idempotency"


def upgrade():
    if not inspect(engine).has_table("users"):
        return
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    with engine.begin() as connection:
        if "last_stripe_checkout_session_id" not in columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN last_stripe_checkout_session_id VARCHAR"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_last_stripe_checkout_session_id ON users (last_stripe_checkout_session_id)"))
