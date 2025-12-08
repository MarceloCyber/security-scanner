#!/usr/bin/env python3
"""
Entry point for Railway deployment.
Redirects to the actual FastAPI app in backend/main.py
"""
import sys
import os

# Add backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

# Import the FastAPI app
from main import app

# This allows Railway to run: uvicorn main:app
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
