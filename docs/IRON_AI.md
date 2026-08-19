# Iron AI

The first Iron AI implementation is read-only. It uses an allowlist of tenant-scoped tools in `backend/ai/tool_registry.py` and a local deterministic provider so the product works without an external API key.

Supported endpoints:

- `POST /api/ai/chat`
- `GET /api/ai/security-summary`
- `POST /api/ai/explain-finding/{finding_id}`
- `POST /api/ai/remediation-plan`

The assistant separates persisted facts from recommendations, never runs SQL/shell, never selects another tenant, and stores only redacted conversation content. A future provider can implement `AIProvider` without changing the routes or tenant boundaries.
