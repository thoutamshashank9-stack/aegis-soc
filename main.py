"""
Root entry point wrapper for Render production deployment.
Allows 'uvicorn main:app --host 0.0.0.0 --port $PORT' to execute either
from the project root or from inside the backend/ directory.
"""
import sys
import os

# Ensure backend directory is in python module search path
backend_dir = os.path.join(os.path.dirname(__file__), "backend")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from backend.main import app  # noqa: F401

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=False)
