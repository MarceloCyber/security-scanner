# Multi-tenancy

The authoritative relationship is `organization_members(organization_id, user_id, role)`. New product resources contain `organization_id` and are queried with that column in every read/write path. The backend, not the frontend, decides access.

Run the initial migration from `security-scanner` with:

```bash
python3 migrations/run.py
```

Then start the existing API as documented in `README.md`. Existing accounts are assigned a private organization by the migration; new accounts receive one during registration.
