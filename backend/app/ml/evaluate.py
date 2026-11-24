import os
import sys
import json
import time
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR))

MODELS_DIR = BASE_DIR / "app" / "ml" / "models"
RESULTS_DIR = BASE_DIR / "experiments" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def evaluate_on_held_out_test():
    test_path = BASE_DIR / "datasets" / "processed" / "test_processed.parquet"
    binary_path = MODELS_DIR / "binary_pipeline.joblib"
    multiclass_path = MODELS_DIR / "multiclass_pipeline.joblib"

    if not test_path.exists() or not binary_path.exists() or not multiclass_path.exists():
        print("Required test data or trained model pipelines missing!")
        sys.exit(1)

    print("Loading held-out test split for strict final evaluation...")
    test_df = pd.read_parquet(test_path)
    X_test = test_df['text'].fillna("").values
    y_test_binary = test_df['label_binary'].values
    y_test_cat = test_df['label_category'].values

    print(f"Held-out test set size: {len(X_test)} samples")
    print(f"Binary distribution: Benign: {(y_test_binary == 0).sum()}, Attack: {(y_test_binary == 1).sum()}")

    # 1. Evaluate Binary Model
    print("\n--- Evaluating Best Binary Classifier on Held-out Test Split ---")
    binary_pipeline = joblib.load(binary_path)
    
    t0 = time.time()
    y_pred_binary = binary_pipeline.predict(X_test)
    binary_latency_total = time.time() - t0
    binary_latency_per_sample = (binary_latency_total / len(X_test)) * 1000.0

    if hasattr(binary_pipeline, "predict_proba"):
        y_proba_binary = binary_pipeline.predict_proba(X_test)[:, 1]
        binary_auc = float(roc_auc_score(y_test_binary, y_proba_binary))
    else:
        y_proba_binary = None
        binary_auc = None

    bin_acc = float(accuracy_score(y_test_binary, y_pred_binary))
    bin_prec = float(precision_score(y_test_binary, y_pred_binary, pos_label=1, zero_division=0))
    bin_rec = float(recall_score(y_test_binary, y_pred_binary, pos_label=1, zero_division=0))
    bin_macro_f1 = float(f1_score(y_test_binary, y_pred_binary, average="macro"))
    bin_weighted_f1 = float(f1_score(y_test_binary, y_pred_binary, average="weighted"))
    
    cm_bin = confusion_matrix(y_test_binary, y_pred_binary)
    tn, fp, fn, tp = cm_bin.ravel()
    bin_fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    bin_fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    print(f"Test Binary Metrics:")
    print(f"  Accuracy: {bin_acc:.4f} | Recall: {bin_rec:.4f} | Precision: {bin_prec:.4f}")
    print(f"  Macro F1: {bin_macro_f1:.4f} | ROC-AUC: {binary_auc} | Latency: {binary_latency_per_sample:.3f}ms")

    # 2. Evaluate Multi-Class Model
    print("\n--- Evaluating Best Multi-Class Classifier on Held-out Test Split ---")
    multiclass_pipeline = joblib.load(multiclass_path)
    classes = ["benign", "direct_injection", "indirect_injection", "jailbreak"]
    
    # Normalize ground truth categories
    y_test_cat_norm = [c if c in classes else "benign" for c in y_test_cat]

    t0 = time.time()
    y_pred_cat = multiclass_pipeline.predict(X_test)
    multi_latency_total = time.time() - t0
    multi_latency_per_sample = (multi_latency_total / len(X_test)) * 1000.0

    multi_acc = float(accuracy_score(y_test_cat_norm, y_pred_cat))
    multi_macro_f1 = float(f1_score(y_test_cat_norm, y_pred_cat, average="macro", zero_division=0))
    multi_weighted_f1 = float(f1_score(y_test_cat_norm, y_pred_cat, average="weighted", zero_division=0))
    
    cm_multi = confusion_matrix(y_test_cat_norm, y_pred_cat, labels=classes)
    report_multi = classification_report(y_test_cat_norm, y_pred_cat, labels=classes, output_dict=True, zero_division=0)

    print(f"Test Multi-Class Metrics:")
    print(f"  Accuracy: {multi_acc:.4f} | Macro F1: {multi_macro_f1:.4f} | Weighted F1: {multi_weighted_f1:.4f}")

    # Build final metadata artifact
    metadata = {
        "dataset": "dmilush/shieldlm-prompt-injection",
        "held_out_test_samples": len(X_test),
        "binary_model": {
            "pipeline_type": str(binary_pipeline.named_steps['classifier'].__class__.__name__),
            "test_accuracy": round(bin_acc, 4),
            "test_precision": round(bin_prec, 4),
            "test_recall": round(bin_rec, 4),
            "test_macro_f1": round(bin_macro_f1, 4),
            "test_weighted_f1": round(bin_weighted_f1, 4),
            "test_roc_auc": round(binary_auc, 4) if binary_auc else None,
            "false_positive_rate": round(bin_fpr, 4),
            "false_negative_rate": round(bin_fnr, 4),
            "latency_ms_per_sample": round(binary_latency_per_sample, 4),
            "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
        },
        "multiclass_model": {
            "pipeline_type": str(multiclass_pipeline.named_steps['classifier'].__class__.__name__),
            "test_accuracy": round(multi_acc, 4),
            "test_macro_f1": round(multi_macro_f1, 4),
            "test_weighted_f1": round(multi_weighted_f1, 4),
            "classes": classes,
            "confusion_matrix": cm_multi.tolist(),
            "classification_report": report_multi,
            "latency_ms_per_sample": round(multi_latency_per_sample, 4)
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model_version": "1.0.0"
    }

    # Save to both models/ and experiments/results/
    with open(MODELS_DIR / "model_metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    with open(RESULTS_DIR / "final_test_evaluation.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nFinal evaluation saved to {MODELS_DIR / 'model_metadata.json'}")

if __name__ == "__main__":
    evaluate_on_held_out_test()
