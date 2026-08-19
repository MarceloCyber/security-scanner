# Iron AI architecture

The current migration is intentionally incremental. Legacy scanner, payment and monitoring routes remain available while the platform domain is introduced under `backend/models/saas.py`.

```text
Frontend
  -> FastAPI routers
      -> tenant context / RBAC
          -> domain services
              -> SQLAlchemy models
                  -> SQLite (local) / PostgreSQL (production)
```

The platform resources include organizations, memberships, assets, scan jobs, findings, remediation tasks, audit logs, security snapshots, reports, integrations and approval-gated AI actions. Scanner output is normalized into findings. Dedicated worker and scheduler processes consume durable database jobs; Redis is used for shared rate limiting when `REDIS_URL` is configured.

The authenticated product shell is `frontend/platform.html`, with styles and behavior isolated in `frontend/css/platform.css` and `frontend/js/platform.js`. Legacy scanner UX remains reachable from the Advanced Tools link, avoiding a destructive frontend migration.

Deploy migrations before application startup:

```bash
python3 migrations/run.py
```
