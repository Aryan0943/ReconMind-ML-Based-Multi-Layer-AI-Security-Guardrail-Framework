import os
import time
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import joblib

logger = logging.getLogger("reconmind.ml")

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class MLInferenceEngine:
    """
    Production inference engine for ReconMind ML Threat Detection.
    Loads trained scikit-learn binary and multiclass pipelines.
    Provides fast, deterministic predictions with calibrated confidence scores.

    BUG FIX (C): Correct probability-to-class mapping.
      - Previously: attack_confidence = float(bin_proba[1]) hard-coded index 1 as the
        "malicious" class. This is UNSAFE — scikit-learn's LabelEncoder sorts classes
        alphabetically, so classes_ could be ['benign', 'malicious'] (index 1 = malicious,
        correct) OR ['attack', 'benign'] (index 1 = benign, WRONG), depending on the
        label strings used during training.
      - Now: The actual index of the malicious class is resolved dynamically from
        binary_pipeline.classes_ by searching for a known malicious label token.
        Falls back gracefully if the label is not found.
      - Also fixed: missing/malformed model outputs are handled with explicit safe returns
        rather than allowing AttributeError / IndexError to propagate.
    """

    _instance = None

    # Canonical label tokens we consider "malicious" in the binary pipeline.
    _MALICIOUS_LABEL_TOKENS = {"malicious", "attack", "1", "harmful", "injection"}

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
        self.metadata: Optional[Dict] = None
        self.is_loaded = False
        # Resolved at load time; avoids repeated lookup on every prediction call.
        self._malicious_class_index: int = 1  # Safe default
        self.load_models()
        self.initialized = True

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def load_models(self):
        binary_path = self.models_dir / "binary_pipeline.joblib"
        multiclass_path = self.models_dir / "multiclass_pipeline.joblib"
        metadata_path = self.models_dir / "model_metadata.json"

        if not (binary_path.exists() and multiclass_path.exists()):
            logger.warning("ML models not yet trained or artifacts missing.")
            self.is_loaded = False
            return

        try:
            self.binary_pipeline = joblib.load(binary_path)
            self.multiclass_pipeline = joblib.load(multiclass_path)

            if metadata_path.exists():
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            # Resolve malicious class index (BUG FIX C)
            resolved = self._resolve_malicious_index()
            bin_classes = self._get_binary_classes()
            classes_list = list(bin_classes) if bin_classes is not None else []
            if resolved is not None:
                self._malicious_class_index = resolved
                logger.info(
                    "Resolved malicious class index: %d (classes: %s)",
                    self._malicious_class_index,
                    classes_list
                )
            else:
                # Default to index 1 (most common convention) with a warning
                self._malicious_class_index = 1
                logger.warning(
                    "Could not positively resolve malicious class index from pipeline classes_: %s. "
                    "Defaulting to index 1.",
                    classes_list
                )

            self.is_loaded = True
            logger.info("Successfully loaded ML threat detection pipelines.")
        except Exception as e:
            logger.error("Error loading model pipelines: %s", e)
            self.is_loaded = False

    def _get_binary_classes(self):
        """Retrieve classes_ from the binary pipeline, trying multiple access patterns."""
        if self.binary_pipeline is None:
            return None

        # Method 1: Direct attribute (works on sklearn Pipeline >= 1.4 and bare estimators)
        classes = getattr(self.binary_pipeline, "classes_", None)
        if classes is not None:
            return classes

        # Method 2: Pipeline.steps[-1][1].classes_ (Pipeline stores steps as list of tuples)
        try:
            steps = getattr(self.binary_pipeline, "steps", None)
            if steps:
                classes = getattr(steps[-1][1], "classes_", None)
                if classes is not None:
                    return classes
        except (IndexError, TypeError, AttributeError):
            pass

        # Method 3: Pipeline.named_steps (dict access to the last step)
        try:
            named = getattr(self.binary_pipeline, "named_steps", None)
            if named:
                last_step_name = list(named.keys())[-1]
                classes = getattr(named[last_step_name], "classes_", None)
                if classes is not None:
                    return classes
        except (IndexError, TypeError, AttributeError):
            pass

        # Method 4: Pipeline[-1].classes_ (Pipeline supports indexing in sklearn)
        try:
            classes = getattr(self.binary_pipeline[-1], "classes_", None)
            if classes is not None:
                return classes
        except (IndexError, TypeError, AttributeError):
            pass

        return None

    def _resolve_malicious_index(self) -> Optional[int]:
        """
        Find the index of the malicious class in binary_pipeline.classes_.
        Tries exact match first, then substring match against known label tokens.
        Returns None if resolution fails (caller should default to 1).
        """
        classes = self._get_binary_classes()
        if classes is None:
            return None

        # Convert to strings for safe comparison
        str_classes = [str(c).lower() for c in classes]

        # Exact match first
        for token in self._MALICIOUS_LABEL_TOKENS:
            if token in str_classes:
                return str_classes.index(token)

        # Substring match (e.g. "malicious_attack" or "attack_type")
        for idx, label in enumerate(str_classes):
            for token in self._MALICIOUS_LABEL_TOKENS:
                if token in label:
                    return idx

        # Last resort: if only two classes, assume index 1 is malicious
        if len(str_classes) == 2:
            return 1

        return None

    # ------------------------------------------------------------------
    # Inference
    # ------------------------------------------------------------------

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Runs binary and multiclass threat classification on input text.
        Returns prediction, threat category, confidence score, probabilities, and latency.

        Safe failure contract:
          - Returns available=False if engine not loaded.
          - Returns available=False if any unexpected exception occurs during inference.
          - Never raises; never returns stale / misleading data.
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

        try:
            text_input = [text] if text else [""]

            # --- Binary prediction ---
            bin_pred_raw = self.binary_pipeline.predict(text_input)[0]
            bin_proba = self.binary_pipeline.predict_proba(text_input)[0]

            # BUG FIX C: use dynamically resolved index instead of hard-coded [1]
            malicious_idx = self._malicious_class_index
            if malicious_idx >= len(bin_proba):
                malicious_idx = min(1, len(bin_proba) - 1)
            attack_confidence = float(bin_proba[malicious_idx])

            # Determine if the binary prediction is "malicious"
            # Support both numeric labels (0/1) and string labels ('benign'/'malicious')
            bin_pred_str = str(bin_pred_raw).lower()
            if bin_pred_str in self._MALICIOUS_LABEL_TOKENS:
                is_malicious = True
            elif bin_pred_str in {"0", "benign", "safe"}:
                is_malicious = False
            else:
                # Fall back to probability threshold
                is_malicious = attack_confidence >= 0.5

            # --- Multi-class prediction ---
            cat_pred = str(self.multiclass_pipeline.predict(text_input)[0])
            cat_proba_arr = self.multiclass_pipeline.predict_proba(text_input)[0]
            mc_classes = self.multiclass_pipeline.classes_
            cat_probabilities = {str(c): float(p) for c, p in zip(mc_classes, cat_proba_arr)}

            latency_ms = (time.time() - start_time) * 1000.0

            predicted_label = "malicious" if is_malicious else "benign"
            final_category = cat_pred if is_malicious else "benign"

            # Benign confidence = probability of the benign class (complement)
            if not is_malicious:
                benign_idx = 1 - malicious_idx if len(bin_proba) == 2 else None
                confidence = float(bin_proba[benign_idx]) if benign_idx is not None else (1.0 - attack_confidence)
            else:
                confidence = attack_confidence

            return {
                "available": True,
                "prediction": predicted_label,
                "category": final_category,
                "confidence": round(confidence, 4),
                "attack_probability": round(attack_confidence, 4),
                "category_probabilities": cat_probabilities,
                "latency_ms": round(latency_ms, 2)
            }

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000.0
            logger.error("ML prediction error: %s", e, exc_info=True)
            return {
                "available": False,
                "prediction": "error",
                "category": "error",
                "confidence": 0.0,
                "latency_ms": round(latency_ms, 2),
                "error": f"Prediction failed: {str(e)}"
            }


ml_engine = MLInferenceEngine()
