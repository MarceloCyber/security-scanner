"""Versioned foundation migration; safe to run repeatedly.

The project historically used create_all and ad-hoc ALTER TABLE statements.
This migration gives new SaaS tables an explicit version and leaves legacy
tables untouched.  It is intentionally dependency-light for local installs.
"""

from pathlib import Path
import sys

BACKEND = Path(__file__).resolve().parents[1] / "backend"
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from database import Base, engine, SessionLocal  # noqa: E402
from models import saas  # noqa: F401,E402
from models.user import User  # noqa: E402

VERSION = "001_saas_foundation"


def upgrade():
    # Also creates the legacy users table on a clean development database;
    # existing tables are never dropped or rewritten by this migration.
    Base.metadata.create_all(bind=engine)
    # Backfill a private organization for legacy accounts. This is idempotent
    # and makes the new tenant context usable immediately.
    db = SessionLocal()
    try:
        users = db.query(User).all()
        for user in users:
            membership = db.query(saas.OrganizationMember).filter(saas.OrganizationMember.user_id == user.id).first()
            if membership:
                continue
            slug = f"legacy-{user.id}-{(user.username or 'user').lower().replace(' ', '-')[:80]}"
            organization = saas.Organization(name=f"{user.username or 'User'} organization", slug=slug)
            db.add(organization)
            db.flush()
            db.add(saas.OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner"))
        db.commit()
    finally:
        db.close()
