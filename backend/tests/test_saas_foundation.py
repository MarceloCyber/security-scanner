"""Fast, database-only tests for tenant isolation and the Fase 1 RBAC rules."""

from datetime import datetime

from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database import Base
from models.saas import Asset, Organization, OrganizationMember
from models.user import User
from services.tenant import TenantContext, get_tenant_context, require_roles


def _db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _user(db, username):
    user = User(username=username, email=f"{username}@example.test", hashed_password="not-used")
    db.add(user)
    db.flush()
    return user


def _org(db, name, user, role="owner"):
    organization = Organization(name=name, slug=name.lower().replace(" ", "-"))
    db.add(organization)
    db.flush()
    db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role=role))
    db.commit()
    return organization


def test_context_rejects_cross_tenant_selection():
    db = _db()
    user = _user(db, "alice")
    own = _org(db, "Alice", user)
    other = Organization(name="Other", slug="other")
    db.add(other)
    db.commit()

    context = get_tenant_context(current_user=user, db=db, organization_id=own.id)
    assert context.organization.id == own.id
    try:
        get_tenant_context(current_user=user, db=db, organization_id=other.id)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("cross-tenant selection must be rejected")


def test_asset_queries_are_scoped_by_organization():
    db = _db()
    alice = _user(db, "alice")
    bob = _user(db, "bob")
    first = _org(db, "Alice", alice)
    second = _org(db, "Bob", bob)
    db.add_all([
        Asset(organization_id=first.id, type="domain", name="alice.example"),
        Asset(organization_id=second.id, type="domain", name="bob.example"),
    ])
    db.commit()
    visible = db.query(Asset).filter(Asset.organization_id == first.id).all()
    assert [asset.name for asset in visible] == ["alice.example"]


def test_viewer_cannot_use_write_role_dependency():
    db = _db()
    user = _user(db, "viewer")
    organization = _org(db, "Viewer", user, role="viewer")
    context = TenantContext(user=user, organization=organization, membership=db.query(OrganizationMember).filter_by(user_id=user.id).one())
    dependency = require_roles("owner", "admin", "analyst")
    try:
        dependency(context)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("viewer must not pass a write dependency")
