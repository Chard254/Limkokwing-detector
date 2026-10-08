import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import Base, engine
from app import models

from app.routes.whatsapp_routes import router as whatsapp_router
from app.routes.scan_routes import router as scan_router


# =====================================================
# Logging
# =====================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)

logger = logging.getLogger(__name__)


# =====================================================
# Database
# =====================================================

Base.metadata.create_all(bind=engine)


# =====================================================
# Application
# =====================================================

app = FastAPI(
    title="Phishing Detection Platform API",
    description="API for detecting phishing links and educating users.",
    version="1.0.0",
)


# =====================================================
# CORS
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================
# Root
# =====================================================

@app.get("/")
def root():
    return {
        "success": True,
        "message": "Phishing Detection Platform API is running.",
    }


# =====================================================
# Health Check
# =====================================================

@app.get("/health")
def health_check():
    return {
        "success": True,
        "status": "healthy",
    }


# =====================================================
# Routers
# =====================================================

app.include_router(scan_router)
app.include_router(whatsapp_router)


# =====================================================
# Startup
# =====================================================

@app.on_event("startup")
async def startup_event():
    logger.info("API startup complete.")


# =====================================================
# Shutdown
# =====================================================

@app.on_event("shutdown")
async def shutdown_event():
    logger.info("API shutdown complete.")