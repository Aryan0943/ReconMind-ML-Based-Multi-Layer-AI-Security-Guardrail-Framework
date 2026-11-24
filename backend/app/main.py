import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database.connection import db_manager
from app.ml.predict import ml_engine
from app.api.scan import router as scan_router
from app.api.logs import router as logs_router
from app.api.dashboard import router as dashboard_router
from app.api.models import router as models_router
from app.api.policies import router as policies_router
from app.api.agent_router import router as agent_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("reconmind")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Connect DB and initialize ML models
    logger.info("Initializing ReconMind AI Security Guardrail Backend...")
    db_manager.connect(uri=settings.MONGODB_URI, db_name=settings.MONGODB_DB_NAME)
    ml_engine.load_models()
    yield
    # Shutdown
    logger.info("Shutting down ReconMind Backend...")

app = FastAPI(
    title="ReconMind AI Security Guardrail API",
    description="ML-Based Multi-Layer AI Security Guardrail Framework for LLM-Powered Applications",
    version=settings.APP_VERSION,
    lifespan=lifespan
)

# Enable CORS for React frontend dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers under /api/v1 prefix
app.include_router(scan_router, prefix="/api/v1")
app.include_router(logs_router, prefix="/api/v1")
app.include_router(dashboard_router, prefix="/api/v1")
app.include_router(models_router, prefix="/api/v1")
app.include_router(policies_router, prefix="/api/v1")
app.include_router(agent_router, prefix="/api/v1")

@app.get("/api/v1/health", tags=["Health"])
def health_check():
    db_status = db_manager.get_status()
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "database": db_status,
        "ml_engine": {
            "loaded": ml_engine.is_loaded,
            "binary_model": ml_engine.binary_pipeline is not None,
            "multiclass_model": ml_engine.multiclass_pipeline is not None
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
