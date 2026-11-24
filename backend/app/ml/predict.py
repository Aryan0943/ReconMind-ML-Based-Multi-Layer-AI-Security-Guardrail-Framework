import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, Tuple
import joblib

logger = logging.getLogger("reconmind.ml")

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class MLInferenceEngine:
    """
    Production inference engine for ReconMind ML Threat Detection.
    Loads trained scikit-learn binary and multiclass pipelines.
    Provides fast, deterministic predictions with calibrated confidence scores.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(MLInferenceEngine, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self, models_dir: Path = None):
        if self.initialized:
            return
            
        self.models_dir = models_dir or (BASE_DIR / "app" / "ml" / "models")
        self.binary_pipeline = None
        self.multiclass_pipeline = None
        self.metadata = None
        self.is_loaded = False
        self.load_models()
        self.initialized = True

    def load_models(self):
        binary_path = self.models_dir / "binary_pipeline.joblib"
        multiclass_path = self.models_dir / "multiclass_pipeline.joblib"
        metadata_path = self.models_dir / "model_metadata.json"

        if binary_path.exists() and multiclass_path.exists():
            try:
                self.binary_pipeline = joblib.load(binary_path)
                self.multiclass_pipeline = joblib.load(multiclass_path)
                if metadata_path.exists():
                    with open(metadata_path, "r", encoding="utf-8") as f:
                        self.metadata = json.load(f)
                self.is_loaded = True
                logger.info("Successfully loaded ML threat detection pipelines.")
            except Exception as e:
                logger.error(f"Error loading model pipelines: {e}")
                self.is_loaded = False
        else:
            logger.warning("ML models not yet trained or artifacts missing.")
            self.is_loaded = False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Runs binary and multiclass threat classification on input text.
        Returns prediction, threat category, confidence score, probabilities, and latency.
        """
        if not self.is_loaded or self.binary_pipeline is None:
            return {
                "available": False,
                "prediction": "unavailable",
                "category": "unavailable",
                "confidence": 0.0,
                "latency_ms": 0.0,
                "error": "ML detection engine not loaded. Please train models."
            }

        start_time = time.time()
        text_input = [text]

        # 1. Binary prediction
        bin_pred = int(self.binary_pipeline.predict(text_input)[0])
        bin_proba = self.binary_pipeline.predict_proba(text_input)[0]
        # Probability of class 1 (malicious/attack)
        attack_confidence = float(bin_proba[1])

        # 2. Multi-class prediction
        cat_pred = str(self.multiclass_pipeline.predict(text_input)[0])
        cat_proba = self.multiclass_pipeline.predict_proba(text_input)[0]
        classes = self.multiclass_pipeline.classes_
        cat_probabilities = {str(c): float(p) for c, p in zip(classes, cat_proba)}

        latency_ms = (time.time() - start_time) * 1000.0

        is_malicious = bin_pred == 1
        predicted_label = "malicious" if is_malicious else "benign"
        
        # When benign, category is benign unless confidence is borderline
        final_category = cat_pred if is_malicious else "benign"
        confidence = attack_confidence if is_malicious else float(bin_proba[0])

        return {
            "available": True,
            "prediction": predicted_label,
            "category": final_category,
            "confidence": round(confidence, 4),
            "attack_probability": round(attack_confidence, 4),
            "category_probabilities": cat_probabilities,
            "latency_ms": round(latency_ms, 2)
        }

ml_engine = MLInferenceEngine()
