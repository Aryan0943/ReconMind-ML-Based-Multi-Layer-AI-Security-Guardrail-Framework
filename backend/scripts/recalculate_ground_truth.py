import sys
from pathlib import Path
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report
)

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR.parent))

TEST_SPLIT_PATH = BASE_DIR / "datasets" / "processed" / "test_processed.parquet"
BINARY_MODEL_PATH = BASE_DIR / "app" / "ml" / "models" / "binary_pipeline.joblib"
MULTICLASS_MODEL_PATH = BASE_DIR / "app" / "ml" / "models" / "multiclass_pipeline.joblib"
RESULTS_DIR = BASE_DIR / "experiments" / "results"

def recalculate_metrics():
    print("Loading test split and serialized models...")
    test_df = pd.read_parquet(TEST_SPLIT_PATH)
    bin_model = joblib.load(BINARY_MODEL_PATH)
    multi_model = joblib.load(MULTICLASS_MODEL_PATH)

    X_test = test_df['text'].fillna("").values
    y_test_bin = test_df['label_binary'].values
    y_test_cat_raw = test_df['label_category'].values

    classes = ["benign", "direct_injection", "indirect_injection", "jailbreak"]
    y_test_cat = np.array([c if c in classes else "benign" for c in y_test_cat_raw])

    print(f"Total test samples: {len(X_test)}")
    
    # ----------------- BINARY EVALUATION -----------------
    y_bin_pred = bin_model.predict(X_test)
    y_bin_proba = bin_model.predict_proba(X_test)[:, 1]

    bin_cm = confusion_matrix(y_test_bin, y_bin_pred)
    tn, fp, fn, tp = bin_cm.ravel()
    bin_acc = float(accuracy_score(y_test_bin, y_bin_pred))
    bin_prec = float(precision_score(y_test_bin, y_bin_pred, pos_label=1))
    bin_rec = float(recall_score(y_test_bin, y_bin_pred, pos_label=1))
    bin_macro_f1 = float(f1_score(y_test_bin, y_bin_pred, average="macro"))
    bin_weighted_f1 = float(f1_score(y_test_bin, y_bin_pred, average="weighted"))
    bin_auc = float(roc_auc_score(y_test_bin, y_bin_proba))
    bin_fpr = float(fp / (fp + tn))
    bin_fnr = float(fn / (fn + tp))

    binary_results = {
        "total_samples": len(X_test),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
        "accuracy": bin_acc,
        "attack_precision": bin_prec,
        "attack_recall": bin_rec,
        "macro_f1": bin_macro_f1,
        "weighted_f1": bin_weighted_f1,
        "roc_auc": bin_auc,
        "false_positive_rate": bin_fpr,
        "false_negative_rate": bin_fnr
    }

    # ----------------- MULTICLASS EVALUATION -----------------
    y_multi_pred = multi_model.predict(X_test)
    multi_cm = confusion_matrix(y_test_cat, y_multi_pred, labels=classes)
    multi_report = classification_report(y_test_cat, y_multi_pred, labels=classes, output_dict=True, digits=6)
    multi_acc = float(accuracy_score(y_test_cat, y_multi_pred))
    multi_macro_f1 = float(f1_score(y_test_cat, y_multi_pred, average="macro"))
    multi_weighted_f1 = float(f1_score(y_test_cat, y_multi_pred, average="weighted"))

    # Jailbreak-specific inspection
    jb_idx = classes.index("jailbreak")
    jb_support = int(multi_cm[jb_idx].sum())
    jb_tp = int(multi_cm[jb_idx, jb_idx])
    jb_fn = int(jb_support - jb_tp)
    jb_pred_total = int(multi_cm[:, jb_idx].sum())
    jb_fp = int(jb_pred_total - jb_tp)
    jb_rec = float(jb_tp / jb_support)
    jb_prec = float(jb_tp / jb_pred_total) if jb_pred_total > 0 else 0.0
    jb_f1 = float(2 * (jb_prec * jb_rec) / (jb_prec + jb_rec)) if (jb_prec + jb_rec) > 0 else 0.0

    multiclass_results = {
        "classes": classes,
        "overall_accuracy": multi_acc,
        "macro_f1": multi_macro_f1,
        "weighted_f1": multi_weighted_f1,
        "confusion_matrix": multi_cm.tolist(),
        "classification_report": multi_report,
        "jailbreak_deep_dive": {
            "support": jb_support,
            "true_positives": jb_tp,
            "false_negatives": jb_fn,
            "false_positives": jb_fp,
            "total_predicted_as_jailbreak": jb_pred_total,
            "exact_recall": jb_rec,
            "exact_precision": jb_prec,
            "exact_f1": jb_f1,
            "where_false_positives_came_from": {
                classes[i]: int(multi_cm[i, jb_idx]) for i in range(len(classes)) if i != jb_idx
            },
            "where_false_negatives_went": {
                classes[i]: int(multi_cm[jb_idx, i]) for i in range(len(classes)) if i != jb_idx
            }
        }
    }

    full_audit = {
        "binary_evaluation": binary_results,
        "multiclass_evaluation": multiclass_results
    }

    output_path = RESULTS_DIR / "exact_recalculated_metrics.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(full_audit, f, indent=2)

    print("--- RECALCULATED MULTICLASS CONFUSION MATRIX ---")
    df_cm = pd.DataFrame(multi_cm, index=[f"True_{c}" for c in classes], columns=[f"Pred_{c}" for c in classes])
    print(df_cm)
    print("\n--- JAILBREAK EXACT METRICS ---")
    print(f"Support: {jb_support}")
    print(f"True Positives: {jb_tp}")
    print(f"False Positives: {jb_fp}")
    print(f"False Negatives: {jb_fn}")
    print(f"Precision: {jb_prec:.6f} ({jb_tp}/{jb_pred_total})")
    print(f"Recall: {jb_rec:.6f} ({jb_tp}/{jb_support})")
    print(f"F1: {jb_f1:.6f}")
    print(f"\nAudit saved to {output_path}")

if __name__ == "__main__":
    recalculate_metrics()
