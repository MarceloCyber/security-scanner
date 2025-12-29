#!/usr/bin/env python3
"""
Entry point for platform deployments.
Imports the actual FastAPI app from backend/main.py
"""
import os

# Import the FastAPI app directly from backend
from backend.main import app

# This allows Railway to run: uvicorn main:app
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
