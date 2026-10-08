"""
Main FastAPI Application Entry Point.
Production-ready configuration for Render deployment and local development.
- Database initialization (SQLite local fallback / PostgreSQL production)
- Pre-loaded ML models and warm classifier pipeline
- Dynamic CORS middleware respecting FRONTEND_ORIGIN with regex support for *.onrender.com
- Render dynamic PORT binding (host 0.0.0.0)
- Root and API health endpoints (/health, /api/health)
"""
import os
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database.models import init_db
from app.api.routes import router as api_router
from app.services.ml_service import MLClassifierService

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("[System] Initializing database tables...")
    init_db()
    print("[System] Pre-loading ML classifier models...")
    MLClassifierService.load_model()
    print("[System] SOC Threat Detection & Forensic Intelligence Platform online.")
    yield

app = FastAPI(
    title="AI Email Threat Detection, Geolocation & Forensic Intelligence Platform",
    description="Production-grade SOC cybersecurity email analysis platform with ML classification, SPF/DKIM/DMARC validation, IP geolocation, MTA chain reconstruction, and IOC extraction.",
    version="1.0.0",
    lifespan=lifespan
)

# -----------------------------------------------------------------------------
# CORS CONFIGURATION (Localhost + FRONTEND_ORIGIN + *.onrender.com)
# -----------------------------------------------------------------------------
frontend_origin_env = os.getenv("FRONTEND_ORIGIN", "*").strip()

# Always permit standard local development frontend ports
allowed_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]

if frontend_origin_env and frontend_origin_env != "*":
    for orig in frontend_origin_env.split(","):
        cleaned = orig.strip().rstrip("/")
        if cleaned and cleaned not in allowed_origins:
            allowed_origins.append(cleaned)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_origin_regex=r"https://.*\.onrender\.com",
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
else:
    # Allow all origins (allows local dev and any dynamic deployment preview)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_origin_regex=r"https://.*\.onrender\.com",
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Register API routes under /api
app.include_router(api_router)

# -----------------------------------------------------------------------------
# ROOT & CLOUD PLATFORM HEALTH CHECK ENDPOINTS
# -----------------------------------------------------------------------------
@app.get("/")
def root():
    return {
        "message": "AI Email Threat Detection, Geolocation & Forensic Intelligence Platform API",
        "documentation": "/docs",
        "health": "/api/health",
        "status": "online"
    }

@app.get("/health")
def root_health():
    """Direct root health check for Render / Kubernetes load balancers."""
    return {
        "status": "healthy",
        "service": "AI Email Threat Detection & Forensic Intelligence Platform"
    }

# -----------------------------------------------------------------------------
# PRODUCTION STARTUP
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    # Render binds dynamically to the $PORT environment variable; defaults to 8000
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=False)
