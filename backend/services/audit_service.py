from typing import Any, Optional

from sqlalchemy.orm import Session

from models.saas import AuditLog
from services.tenant import TenantContext


def record_audit(
    db: Session,
    context: TenantContext,
    action: str,
    resource_type: Optional[str] = None,
    resource_id: Optional[Any] = None,
    request=None,
    metadata: Optional[dict] = None,
) -> AuditLog:
    # Metadata is caller-controlled, so never accept or persist credentials here.
    safe_metadata = metadata or {}
    forbidden = {"password", "token", "secret", "api_key", "authorization", "cookie"}
    safe_metadata = {k: v for k, v in safe_metadata.items() if k.lower() not in forbidden}
    entry = AuditLog(
        organization_id=context.organization.id,
        user_id=context.user.id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        ip_address=request.client.host if request and request.client else None,
        user_agent=(request.headers.get("user-agent", "")[:512] if request else None),
        metadata_json=safe_metadata,
    )
    db.add(entry)
    return entry
