import os
from pathlib import Path
from pydantic_settings import BaseSettings

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    APP_NAME: str = "ReconMind"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    MONGODB_URI: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "reconmind"
    USE_DEV_FALLBACK_DB: bool = True
    
    # Layer ML Thresholds
    INPUT_DEFENSE_THRESHOLD: float = 0.75
    MEMORY_DEFENSE_THRESHOLD: float = 0.70
    RETRIEVAL_DEFENSE_THRESHOLD: float = 0.65
    
    # Model Artifact Paths
    BINARY_MODEL_PATH: str = str(BASE_DIR / "app" / "ml" / "models" / "binary_pipeline.joblib")
    MULTICLASS_MODEL_PATH: str = str(BASE_DIR / "app" / "ml" / "models" / "multiclass_pipeline.joblib")
    MODEL_METADATA_PATH: str = str(BASE_DIR / "app" / "ml" / "models" / "model_metadata.json")
    DATASET_DIR: str = str(BASE_DIR / "datasets")
    
    class Config:
        env_file = ".env"
        extra = "allow"

settings = Settings()
