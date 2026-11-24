import json
import logging
from pathlib import Path
from collections import defaultdict
import pandas as pd
import numpy as np

BASE_DIR = Path(__file__).resolve().parent.parent
PROCESSED_DATA_DIR = BASE_DIR / "datasets" / "processed"
RESULTS_DIR = BASE_DIR / "experiments" / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def audit_dataset_leakage():
    splits = ["train", "validation", "test"]
    dfs = {}
    
    print("Loading processed splits...")
    for s in splits:
        p = PROCESSED_DATA_DIR / f"{s}_processed.parquet"
        dfs[s] = pd.read_parquet(p)
        print(f"Loaded {s}: {len(dfs[s])} samples")

    # 1. Exact Duplicate Analysis
    text_to_splits = defaultdict(set)
    text_to_sources = defaultdict(set)
    text_to_labels = defaultdict(set)

    for s in splits:
        for idx, row in dfs[s].iterrows():
            clean_t = str(row['text']).strip().lower()
            text_to_splits[clean_t].add(s)
            text_to_sources[clean_t].add(str(row.get('source', 'unknown')))
            text_to_labels[clean_t].add(int(row['label_binary']))

    total_unique_texts = len(text_to_splits)
    
    # Overlap between specific splits
    train_texts = set(dfs['train']['text'].str.strip().str.lower())
    val_texts = set(dfs['validation']['text'].str.strip().str.lower())
    test_texts = set(dfs['test']['text'].str.strip().str.lower())

    train_val_overlap = len(train_texts.intersection(val_texts))
    train_test_overlap = len(train_texts.intersection(test_texts))
    val_test_overlap = len(val_texts.intersection(test_texts))
    all_three_overlap = len(train_texts.intersection(val_texts).intersection(test_texts))

    # Label inconsistencies for exact duplicates
    inconsistent_labels = sum(1 for t, labels in text_to_labels.items() if len(labels) > 1)

    # 2. Source Distribution Analysis
    source_distribution = {}
    all_sources = set()
    for s in splits:
        src_counts = dfs[s]['source'].value_counts().to_dict()
        source_distribution[s] = {str(k): int(v) for k, v in src_counts.items()}
        all_sources.update(src_counts.keys())

    # Check which sources appear across multiple splits
    source_spread = {}
    for src in sorted(all_sources):
        in_splits = [s for s in splits if src in source_distribution[s]]
        counts = {s: source_distribution[s].get(src, 0) for s in in_splits}
        source_spread[src] = {
            "splits": in_splits,
            "counts": counts,
            "is_shared": len(in_splits) > 1
        }

    # 3. Near-Duplicate Sampling (Jaccard similarity >= 0.85 on test vs train)
    print("Checking near-duplicate overlap between train and held-out test...")
    # Sample 500 test samples for computational feasibility of n-gram Jaccard comparison
    import random
    random.seed(42)
    sample_test = random.sample(list(test_texts), min(500, len(test_texts)))
    
    def get_shingles(text, k=3):
        words = text.split()
        if len(words) < k:
            return set(words)
        return set(" ".join(words[i:i+k]) for i in range(len(words)-k+1))

    train_shingles = [(t, get_shingles(t)) for t in random.sample(list(train_texts), min(5000, len(train_texts)))]
    
    near_duplicates_found = []
    for t_test in sample_test:
        s_test = get_shingles(t_test)
        if not s_test:
            continue
        for t_train, s_train in train_shingles:
            if not s_train:
                continue
            inter = len(s_test.intersection(s_train))
            union = len(s_test.union(s_train))
            sim = inter / union if union > 0 else 0
            if 0.85 <= sim < 1.0:
                near_duplicates_found.append({
                    "test_snippet": t_test[:100],
                    "train_snippet": t_train[:100],
                    "jaccard_similarity": round(sim, 4)
                })
                break

    report = {
        "total_dataset_samples": sum(len(df) for df in dfs.values()),
        "total_unique_texts": total_unique_texts,
        "exact_duplicates": {
            "train_val_overlap_count": train_val_overlap,
            "train_test_overlap_count": train_test_overlap,
            "val_test_overlap_count": val_test_overlap,
            "all_three_splits_overlap_count": all_three_overlap,
            "train_test_overlap_percentage": round((train_test_overlap / len(test_texts)) * 100, 2),
            "label_inconsistencies_on_identical_text": inconsistent_labels
        },
        "source_splitting_analysis": {
            "total_unique_sources": len(all_sources),
            "sources_appearing_in_multiple_splits": sum(1 for v in source_spread.values() if v["is_shared"]),
            "is_source_isolated_split": False,
            "explanation": (
                "ShieldLM was partitioned using random stratified sampling rather than source-based group splitting. "
                "Consequently, the underlying source datasets (e.g. alespalla/chatbot-instruction-prompts, "
                "spml/chatbot-prompt-injection) have samples distributed proportionally across Train (~70%), "
                "Validation (~15%), and Test (~15%). While this mirrors standard Hugging Face benchmark splits, "
                "it means test samples share similar stylistic distributions with training sources."
            ),
            "detailed_source_spread": source_spread
        },
        "near_duplicate_audit": {
            "sample_size_audited": len(sample_test),
            "near_duplicates_detected_in_sample": len(near_duplicates_found),
            "near_duplicate_rate_estimate": f"{len(near_duplicates_found) / len(sample_test) * 100:.2f}%",
            "examples": near_duplicates_found[:5]
        }
    }

    report_path = RESULTS_DIR / "dataset_leakage_audit.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\n--- DATASET LEAKAGE AUDIT SUMMARY ---")
    print(f"Total Unique Texts: {total_unique_texts}")
    print(f"Exact Train-Test Overlap: {train_test_overlap} ({report['exact_duplicates']['train_test_overlap_percentage']}%)")
    print(f"Sources shared across splits: {report['source_splitting_analysis']['sources_appearing_in_multiple_splits']} / {len(all_sources)}")
    print(f"Near-duplicate sample rate: {report['near_duplicate_audit']['near_duplicate_rate_estimate']}")
    print(f"Report written to: {report_path}")

if __name__ == "__main__":
    audit_dataset_leakage()
