from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from database import get_db
from models.saas import Asset, Organization, OrganizationMember
from schemas.saas import AssetCreate, AssetResponse, OrganizationCreate, OrganizationResponse
from services.audit_service import record_audit
from services.tenant import TenantContext, get_tenant_context, require_roles

router = APIRouter()


def _slugify(value: str) -> str:
    import re
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "organization"


@router.get("/organizations", response_model=list[OrganizationResponse])
def list_organizations(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    memberships = db.query(OrganizationMember).filter(OrganizationMember.user_id == context.user.id).all()
    organization_ids = [membership.organization_id for membership in memberships]
    organizations = {org.id: org for org in db.query(Organization).filter(Organization.id.in_(organization_ids)).all()}
    return [
        {"id": org.id, "name": org.name, "slug": org.slug, "plan": org.plan, "role": membership.role}
        for membership in memberships
        if (org := organizations.get(membership.organization_id)) is not None
    ]


@router.post("/organizations", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(payload: OrganizationCreate, request: Request, context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    base = _slugify(payload.name)
    slug = base
    suffix = 1
    while db.query(Organization).filter(Organization.slug == slug).first():
        suffix += 1
        slug = f"{base}-{suffix}"
    organization = Organization(name=payload.name.strip(), slug=slug, plan=context.organization.plan)
    db.add(organization)
    db.flush()
    db.add(OrganizationMember(organization_id=organization.id, user_id=context.user.id, role="owner"))
    record_audit(db, context, "organization_created", "organization", organization.id, request)
    db.commit()
    db.refresh(organization)
    return {"id": organization.id, "name": organization.name, "slug": organization.slug, "plan": organization.plan, "role": "owner"}


@router.get("/assets", response_model=list[AssetResponse])
def list_assets(context: TenantContext = Depends(get_tenant_context), db: Session = Depends(get_db)):
    return db.query(Asset).filter(Asset.organization_id == context.organization.id).order_by(Asset.updated_at.desc()).limit(500).all()


@router.post("/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(payload: AssetCreate, request: Request, context: TenantContext = Depends(require_roles("owner", "admin", "analyst")), db: Session = Depends(get_db)):
    asset = Asset(organization_id=context.organization.id, metadata_json=payload.metadata, **payload.model_dump(exclude={"metadata"}))
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Este ativo já está cadastrado nesta organização")
    record_audit(db, context, "asset_created", "asset", asset.id, request, {"type": asset.type, "name": asset.name})
    db.commit()
    db.refresh(asset)
    return asset
