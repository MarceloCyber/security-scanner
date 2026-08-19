"""Tenant context and centralized RBAC dependencies."""

from dataclasses import dataclass
from typing import Iterable, Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from auth import get_current_user
from database import get_db
from models.saas import Organization, OrganizationMember
from models.user import User

ROLES = {"owner", "admin", "analyst", "viewer"}


@dataclass(frozen=True)
class TenantContext:
    user: User
    organization: Organization
    membership: OrganizationMember


def get_tenant_context(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    organization_id: Optional[int] = Header(default=None, alias="X-Organization-ID"),
) -> TenantContext:
    query = db.query(OrganizationMember).filter(OrganizationMember.user_id == current_user.id)
    if organization_id is not None:
        query = query.filter(OrganizationMember.organization_id == organization_id)
    membership = query.order_by(OrganizationMember.created_at.asc()).first()
    if not membership:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Usuário não pertence a uma organização autorizada")
    organization = db.query(Organization).filter(Organization.id == membership.organization_id, Organization.status == "active").first()
    if not organization:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Organização indisponível")
    return TenantContext(user=current_user, organization=organization, membership=membership)


def require_roles(*allowed_roles: str):
    invalid = set(allowed_roles) - ROLES
    if invalid:
        raise ValueError(f"Papéis inválidos: {sorted(invalid)}")

    def dependency(context: TenantContext = Depends(get_tenant_context)) -> TenantContext:
        if context.membership.role not in allowed_roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Permissão insuficiente")
        return context

    return dependency


def can_manage(context: TenantContext) -> bool:
    return context.membership.role in {"owner", "admin"}
