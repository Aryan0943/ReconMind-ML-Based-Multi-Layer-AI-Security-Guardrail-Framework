import os
import sys
import time
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR))

from app.ml.preprocess import SecurityTextPreprocessor, create_security_tfidf

MODELS_DIR = BASE_DIR / "app" / "ml" / "models"
EXPERIMENTS_DIR = BASE_DIR / "experiments" / "binary_classification"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

def train_and_compare_binary():
    train_path = BASE_DIR / "datasets" / "processed" / "train_processed.parquet"
    val_path = BASE_DIR / "datasets" / "processed" / "validation_processed.parquet"
    
    if not train_path.exists() or not val_path.exists():
        print(f"Processed datasets not found at {train_path}. Run download_dataset.py first.")
        sys.exit(1)

    print("Loading processed training and validation splits...")
    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)

    X_train = train_df['text'].fillna("").values
    y_train = train_df['label_binary'].values
    
    X_val = val_df['text'].fillna("").values
    y_val = val_df['label_binary'].values

    print(f"Training samples: {len(X_train)} (Benign: {(y_train==0).sum()}, Attack: {(y_train==1).sum()})")
    print(f"Validation samples: {len(X_val)} (Benign: {(y_val==0).sum()}, Attack: {(y_val==1).sum()})")

    classifiers = {
        "LogisticRegression": LogisticRegression(
            C=2.0, max_iter=1000, class_weight="balanced", random_state=42
        ),
        "MultinomialNB": MultinomialNB(alpha=0.1),
        "LinearSVM_Calibrated": CalibratedClassifierCV(
            SGDClassifier(loss="log_loss", penalty="l2", alpha=1e-4, max_iter=1000, class_weight="balanced", random_state=42),
            cv=3
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=100, max_depth=40, random_state=42, n_jobs=-1, class_weight="balanced"
        )
    }

    results = {}
    best_model_name = None
    best_macro_f1 = -1.0
    best_pipeline = None

    for name, clf in classifiers.items():
        print(f"\n--- Training {name} ---")
        start_time = time.time()
        
        pipeline = Pipeline([
            ("preprocessor", SecurityTextPreprocessor()),
            ("tfidf", create_security_tfidf(max_features=50000)),
            ("classifier", clf)
        ])
        
        pipeline.fit(X_train, y_train)
        train_time = time.time() - start_time
        
        # Validation inference & latency
        infer_start = time.time()
        y_pred = pipeline.predict(X_val)
        infer_time = time.time() - infer_start
        latency_ms_per_sample = (infer_time / len(X_val)) * 1000.0

        if hasattr(pipeline, "predict_proba"):
            y_proba = pipeline.predict_proba(X_val)[:, 1]
            auc = float(roc_auc_score(y_val, y_proba))
        else:
            y_proba = None
            auc = None

        acc = float(accuracy_score(y_val, y_pred))
        prec = float(precision_score(y_val, y_pred, pos_label=1, zero_division=0))
        rec = float(recall_score(y_val, y_pred, pos_label=1, zero_division=0))
        macro_f1 = float(f1_score(y_val, y_pred, average="macro"))
        weighted_f1 = float(f1_score(y_val, y_pred, average="weighted"))
        
        cm = confusion_matrix(y_val, y_pred)
        tn, fp, fn, tp = cm.ravel()
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        print(f"Validation Metrics for {name}:")
        print(f"  Accuracy: {acc:.4f} | Recall (Malicious): {rec:.4f} | Precision: {prec:.4f}")
        print(f"  Macro F1: {macro_f1:.4f} | ROC-AUC: {auc if auc else 'N/A'}")
        print(f"  FPR: {fpr:.4f} | FNR: {fnr:.4f} | Train Time: {train_time:.2f}s | Latency/sample: {latency_ms_per_sample:.3f}ms")
        
        model_result = {
            "model_name": name,
            "train_time_sec": round(train_time, 2),
            "latency_ms_per_sample": round(latency_ms_per_sample, 4),
            "accuracy": round(acc, 4),
            "malicious_precision": round(prec, 4),
            "malicious_recall": round(rec, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "roc_auc": round(auc, 4) if auc else None,
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "confusion_matrix": {
                "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)
            },
            "classification_report": classification_report(y_val, y_pred, output_dict=True, zero_division=0)
        }
        
        results[name] = model_result
        
        # We prioritize high malicious-class recall combined with strong Macro F1
        score = macro_f1 * 0.5 + rec * 0.5
        if score > best_macro_f1:
            best_macro_f1 = score
            best_model_name = name
            best_pipeline = pipeline

    print(f"\n==========================================")
    print(f"Best Binary Model Selected: {best_model_name}")
    print(f"==========================================")

    # Save comparison experiment results
    comparison_path = EXPERIMENTS_DIR / "binary_comparison_results.json"
    with open(comparison_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    # Save best pipeline
    best_model_path = MODELS_DIR / "binary_pipeline.joblib"
    joblib.dump(best_pipeline, best_model_path)
    print(f"Saved best binary pipeline to {best_model_path}")

    return best_model_name, results

if __name__ == "__main__":
    train_and_compare_binary()
