web: python migrations/run.py && cd backend && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
worker: cd backend && python -m workers.runner
scheduler: cd backend && python -m workers.scheduler
