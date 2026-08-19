from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=160)


class OrganizationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    slug: str
    plan: str
    role: str


class AssetCreate(BaseModel):
    type: str = Field(pattern=r"^(domain|subdomain|ip_address|server|web_application|api|repository|container|cloud_resource)$")
    name: str = Field(min_length=1, max_length=255)
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    url: Optional[str] = None
    environment: str = Field(default="unknown", pattern=r"^(production|staging|development|unknown)$")
    criticality: str = Field(default="medium", pattern=r"^(low|medium|high|critical)$")
    internet_exposed: bool = False
    metadata: Optional[dict[str, Any]] = None


class AssetResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)
    id: int
    organization_id: int
    type: str
    name: str
    hostname: Optional[str]
    ip_address: Optional[str]
    url: Optional[str]
    environment: str
    criticality: str
    internet_exposed: bool
    status: str
    metadata: Optional[dict[str, Any]] = Field(default=None, validation_alias="metadata_json")
    first_seen_at: datetime
    last_seen_at: datetime


class MemberRoleUpdate(BaseModel):
    role: str = Field(pattern=r"^(owner|admin|analyst|viewer)$")
