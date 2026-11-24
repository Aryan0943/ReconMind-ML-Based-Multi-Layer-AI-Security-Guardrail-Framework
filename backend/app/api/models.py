import json
from pathlib import Path
from fastapi import APIRouter
from app.ml.predict import ml_engine

router = APIRouter(prefix="/models", tags=["Model Evaluation & Status"])

BASE_DIR = Path(__file__).resolve().parent.parent.parent

@router.get("/metrics")
def get_model_evaluation_metrics():
    """
    Returns verified evaluation metrics, confusion matrices, and benchmark reports
    from the held-out test split experiments.
    """
    metadata_path = BASE_DIR / "app" / "ml" / "models" / "model_metadata.json"
    binary_comp_path = BASE_DIR / "experiments" / "binary_classification" / "binary_comparison_results.json"
    multi_comp_path = BASE_DIR / "experiments" / "multiclass_classification" / "multiclass_comparison_results.json"
    leakage_path = BASE_DIR / "experiments" / "results" / "dataset_leakage_audit.json"
    jb_analysis_path = BASE_DIR / "experiments" / "results" / "multiclass_jailbreak_analysis.json"
    latency_path = BASE_DIR / "experiments" / "results" / "latency_benchmark_breakdown.json"

    metrics = {}
    if metadata_path.exists():
        with open(metadata_path, "r", encoding="utf-8") as f:
            metrics["test_evaluation"] = json.load(f)

    if binary_comp_path.exists():
        with open(binary_comp_path, "r", encoding="utf-8") as f:
            metrics["binary_model_comparison"] = json.load(f)

    if multi_comp_path.exists():
        with open(multi_comp_path, "r", encoding="utf-8") as f:
            metrics["multiclass_model_comparison"] = json.load(f)

    if leakage_path.exists():
        with open(leakage_path, "r", encoding="utf-8") as f:
            metrics["dataset_leakage_audit"] = json.load(f)

    if jb_analysis_path.exists():
        with open(jb_analysis_path, "r", encoding="utf-8") as f:
            metrics["multiclass_jailbreak_analysis"] = json.load(f)

    if latency_path.exists():
        with open(latency_path, "r", encoding="utf-8") as f:
            metrics["latency_benchmark_breakdown"] = json.load(f)

    return {
        "success": True,
        "metrics": metrics
    }

@router.get("/status")
def get_model_status():
    """
    Returns runtime ML inference engine health and loaded pipeline details.
    """
    return {
        "is_loaded": ml_engine.is_loaded,
        "models_dir": str(ml_engine.models_dir),
        "binary_pipeline_loaded": ml_engine.binary_pipeline is not None,
        "multiclass_pipeline_loaded": ml_engine.multiclass_pipeline is not None
    }
