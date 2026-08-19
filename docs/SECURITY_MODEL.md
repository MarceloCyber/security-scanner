# Security model

## Tenant isolation

The authenticated user is resolved from the existing JWT/session mechanism. SaaS routes resolve a membership on the server and derive the organization from that membership. The optional `X-Organization-ID` header is only a selector among memberships; it is never trusted as authorization.

## Roles

`owner` and `admin` manage organization data; `analyst` can investigate and create assets; `viewer` is read-only. New permission checks must use `services.tenant.require_roles`.

## Audit

Relevant SaaS changes use `record_audit`. Sensitive keys (`password`, `token`, `secret`, `api_key`, authorization and cookies) are filtered before metadata persistence. Secrets must not be put in URLs, responses or logs.

## Migration safety

`migrations/run.py` records applied versions in `schema_migrations`. The first migration is additive and backfills a private organization for legacy users. Production deployments should run migrations as a release step before starting new application code.

## Remaining hardening

Scanner normalization, deterministic risk scoring, credential vaulting, worker isolation and AI guardrails are implemented for platform routes. Rate limiting uses Redis when configured and a process-local fallback in development. AI actions are allowlisted, proposed first, approved by an owner/admin and only then executed. Existing experimental/offensive tools must not be exposed through the PME workflow without explicit authorization and role checks.
