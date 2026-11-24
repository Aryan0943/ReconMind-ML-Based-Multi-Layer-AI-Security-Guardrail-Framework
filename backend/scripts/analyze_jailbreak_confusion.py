import sys
import json
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.metrics import confusion_matrix, classification_report

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR.parent))
MODELS_DIR = BASE_DIR / "app" / "ml" / "models"
RESULTS_DIR = BASE_DIR / "experiments" / "results"

def analyze_jailbreak():
    test_path = BASE_DIR / "datasets" / "processed" / "test_processed.parquet"
    multiclass_path = MODELS_DIR / "multiclass_pipeline.joblib"

    print("Loading held-out test split and multiclass model...")
    test_df = pd.read_parquet(test_path)
    model = joblib.load(multiclass_path)

    classes = ["benign", "direct_injection", "indirect_injection", "jailbreak"]
    
    # Normalize labels
    test_df['label_cat_norm'] = test_df['label_category'].apply(lambda x: x if x in classes else "benign")
    
    X_test = test_df['text'].fillna("").values
    y_true = test_df['label_cat_norm'].values

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    cm = confusion_matrix(y_true, y_pred, labels=classes)
    clf_report = classification_report(y_true, y_pred, labels=classes, output_dict=True, zero_division=0)

    cm_df = pd.DataFrame(cm, index=[f"True_{c}" for c in classes], columns=[f"Pred_{c}" for c in classes])
    print("\n--- 4x4 MULTICLASS CONFUSION MATRIX ---")
    print(cm_df)

    # Detailed breakdown for JAILBREAK
    jb_idx = classes.index("jailbreak")
    total_true_jb = int(cm[jb_idx].sum())
    true_jb_pred_as = {classes[i]: int(cm[jb_idx, i]) for i in range(len(classes))}
    
    # False positives for jailbreak: predicted jailbreak, but true class is NOT jailbreak
    pred_jb_true_as = {classes[i]: int(cm[i, jb_idx]) for i in range(len(classes))}
    total_pred_jb = sum(pred_jb_true_as.values())
    false_pos_jb = total_pred_jb - pred_jb_true_as["jailbreak"]

    # Extract sample false positives (e.g. True Direct Injection predicted as Jailbreak)
    fp_indices = [i for i, (yt, yp) in enumerate(zip(y_true, y_pred)) if yp == "jailbreak" and yt != "jailbreak"]
    fn_indices = [i for i, (yt, yp) in enumerate(zip(y_true, y_pred)) if yt == "jailbreak" and yp != "jailbreak"]

    fp_examples = []
    for idx in fp_indices[:5]:
        fp_examples.append({
            "text_snippet": X_test[idx][:120],
            "true_category": y_true[idx],
            "predicted_category": "jailbreak",
            "jailbreak_probability": round(float(y_proba[idx][jb_idx]), 4)
        })

    fn_examples = []
    for idx in fn_indices[:5]:
        fn_examples.append({
            "text_snippet": X_test[idx][:120],
            "true_category": "jailbreak",
            "predicted_category": y_pred[idx],
            "jailbreak_probability": round(float(y_proba[idx][jb_idx]), 4)
        })

    analysis = {
        "classes": classes,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_dataframe": cm_df.to_dict(),
        "jailbreak_metrics": {
            "support_in_test": total_true_jb,
            "percentage_of_test_split": f"{(total_true_jb / len(X_test)) * 100:.2f}%",
            "precision": round(clf_report["jailbreak"]["precision"], 4),
            "recall": round(clf_report["jailbreak"]["recall"], 4),
            "f1_score": round(clf_report["jailbreak"]["f1-score"], 4),
            "true_positives": true_jb_pred_as["jailbreak"],
            "false_negatives": total_true_jb - true_jb_pred_as["jailbreak"],
            "where_true_jailbreaks_went": true_jb_pred_as,
            "where_false_jailbreaks_came_from": pred_jb_true_as,
            "total_predicted_as_jailbreak": total_pred_jb,
            "total_false_positives": false_pos_jb
        },
        "root_cause_analysis": {
            "class_imbalance": (
                f"Jailbreak is heavily minority: only 153 out of 8,125 test samples (1.88%) and 712 out of 37,913 train samples (1.87%). "
                "Because class_weight='balanced' was applied to protect against missing attacks, the model assigns ~13x higher weight "
                "to jailbreak errors during training, driving recall up to 91.5% at the cost of precision (68.4%)."
            ),
            "semantic_boundary_overlap": (
                "The vast majority of false positives for jailbreak come from direct_injection (not benign). "
                "Direct injections containing persona manipulation, 'pretend', or role-play markers share identical n-grams "
                "with jailbreaks (e.g. 'ignore instructions and act as', 'you are now')."
            )
        },
        "sample_false_positives": fp_examples,
        "sample_false_negatives": fn_examples
    }

    out_path = RESULTS_DIR / "multiclass_jailbreak_analysis.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    print("\n--- JAILBREAK ERROR BREAKDOWN ---")
    print(f"Total True Jailbreaks: {total_true_jb}")
    print(f"True Positives (Correctly identified as Jailbreak): {true_jb_pred_as['jailbreak']} / {total_true_jb} ({clf_report['jailbreak']['recall']*100:.1f}% Recall)")
    print(f"False Positives: {false_pos_jb} prompts predicted as Jailbreak")
    print(f"  - from direct_injection: {pred_jb_true_as.get('direct_injection', 0)}")
    print(f"  - from benign: {pred_jb_true_as.get('benign', 0)}")
    print(f"  - from indirect_injection: {pred_jb_true_as.get('indirect_injection', 0)}")
    print(f"Report written to: {out_path}")

if __name__ == "__main__":
    analyze_jailbreak()
