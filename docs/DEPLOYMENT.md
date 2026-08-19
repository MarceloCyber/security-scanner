# Deployment

Run database migrations as a release step before starting processes:

```bash
python3 migrations/run.py
```

Production process topology:

```text
api       -> uvicorn main:app
worker    -> python -m workers.runner
scheduler -> python -m workers.scheduler
database  -> PostgreSQL
redis     -> distributed rate limiting
```

Configure `REDIS_URL` for multi-instance rate limiting and `CREDENTIAL_ENCRYPTION_KEY` with a Fernet key before storing integration credentials. Never reuse example placeholders.

For a local test without PostgreSQL:

```bash
./start.sh --local
```
