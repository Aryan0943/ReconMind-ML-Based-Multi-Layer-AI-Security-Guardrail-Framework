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
    confusion_matrix, classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(BASE_DIR))

from app.ml.preprocess import SecurityTextPreprocessor, create_security_tfidf

MODELS_DIR = BASE_DIR / "app" / "ml" / "models"
EXPERIMENTS_DIR = BASE_DIR / "experiments" / "multiclass_classification"
MODELS_DIR.mkdir(parents=True, exist_ok=True)
EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

CATEGORY_CLASSES = ["benign", "direct_injection", "indirect_injection", "jailbreak"]
LABEL_TO_INT = {cat: idx for idx, cat in enumerate(CATEGORY_CLASSES)}
INT_TO_LABEL = {idx: cat for idx, cat in enumerate(CATEGORY_CLASSES)}

def train_and_compare_multiclass():
    train_path = BASE_DIR / "datasets" / "processed" / "train_processed.parquet"
    val_path = BASE_DIR / "datasets" / "processed" / "validation_processed.parquet"
    
    if not train_path.exists() or not val_path.exists():
        print(f"Processed datasets not found at {train_path}. Run download_dataset.py first.")
        sys.exit(1)

    print("Loading processed training and validation splits for Multi-Class classification...")
    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)

    # Map categories safely
    train_df['label_cat_norm'] = train_df['label_category'].apply(lambda x: x if x in LABEL_TO_INT else "benign")
    val_df['label_cat_norm'] = val_df['label_category'].apply(lambda x: x if x in LABEL_TO_INT else "benign")

    X_train = train_df['text'].fillna("").values
    y_train = train_df['label_cat_norm'].values
    
    X_val = val_df['text'].fillna("").values
    y_val = val_df['label_cat_norm'].values

    print("Class distribution in Train:")
    for cat in CATEGORY_CLASSES:
        print(f"  {cat}: {(y_train == cat).sum()}")

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
        print(f"\n--- Training Multi-Class {name} ---")
        start_time = time.time()
        
        pipeline = Pipeline([
            ("preprocessor", SecurityTextPreprocessor()),
            ("tfidf", create_security_tfidf(max_features=50000)),
            ("classifier", clf)
        ])
        
        pipeline.fit(X_train, y_train)
        train_time = time.time() - start_time
        
        infer_start = time.time()
        y_pred = pipeline.predict(X_val)
        infer_time = time.time() - infer_start
        latency_ms_per_sample = (infer_time / len(X_val)) * 1000.0

        acc = float(accuracy_score(y_val, y_pred))
        macro_f1 = float(f1_score(y_val, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_val, y_pred, average="weighted", zero_division=0))
        
        cm = confusion_matrix(y_val, y_pred, labels=CATEGORY_CLASSES)
        clf_report = classification_report(y_val, y_pred, labels=CATEGORY_CLASSES, output_dict=True, zero_division=0)

        print(f"Validation Multi-Class Metrics for {name}:")
        print(f"  Accuracy: {acc:.4f} | Macro F1: {macro_f1:.4f} | Weighted F1: {weighted_f1:.4f}")
        for cat in CATEGORY_CLASSES:
            prec = clf_report[cat]['precision']
            rec = clf_report[cat]['recall']
            f1 = clf_report[cat]['f1-score']
            print(f"    - {cat:20s}: P={prec:.4f}, R={rec:.4f}, F1={f1:.4f}")
        
        model_result = {
            "model_name": name,
            "train_time_sec": round(train_time, 2),
            "latency_ms_per_sample": round(latency_ms_per_sample, 4),
            "accuracy": round(acc, 4),
            "macro_f1": round(macro_f1, 4),
            "weighted_f1": round(weighted_f1, 4),
            "confusion_matrix": cm.tolist(),
            "classes": CATEGORY_CLASSES,
            "classification_report": clf_report
        }
        
        results[name] = model_result
        
        if macro_f1 > best_macro_f1:
            best_macro_f1 = macro_f1
            best_model_name = name
            best_pipeline = pipeline

    print(f"\n==========================================")
    print(f"Best Multi-Class Model Selected: {best_model_name} (Macro F1: {best_macro_f1:.4f})")
    print(f"==========================================")

    comparison_path = EXPERIMENTS_DIR / "multiclass_comparison_results.json"
    with open(comparison_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    best_model_path = MODELS_DIR / "multiclass_pipeline.joblib"
    joblib.dump(best_pipeline, best_model_path)
    print(f"Saved best multi-class pipeline to {best_model_path}")

    return best_model_name, results

if __name__ == "__main__":
    train_and_compare_multiclass()
