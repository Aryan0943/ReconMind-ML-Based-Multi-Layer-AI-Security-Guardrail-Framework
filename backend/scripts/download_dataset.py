import os
import sys
import json
import logging
from pathlib import Path
import pandas as pd
import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("dataset_loader")

BASE_DIR = Path(__file__).resolve().parent.parent
RAW_DATA_DIR = BASE_DIR / "datasets" / "raw"
PROCESSED_DATA_DIR = BASE_DIR / "datasets" / "processed"
RAW_DATA_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_DATA_DIR.mkdir(parents=True, exist_ok=True)

def download_and_validate_dataset():
    logger.info("Initiating ShieldLM Prompt Injection dataset download from Hugging Face...")
    try:
        from datasets import load_dataset
        dataset = load_dataset("dmilush/shieldlm-prompt-injection")
    except Exception as e:
        logger.error(f"Failed to load dataset from Hugging Face: {e}")
        sys.exit(1)

    splits = ["train", "validation", "test"]
    split_dfs = {}
    quality_report = {
        "dataset_name": "dmilush/shieldlm-prompt-injection",
        "splits": {},
        "global_checks": {},
        "label_mapping": {
            "binary": {0: "BENIGN", 1: "ATTACK"},
            "category": ["benign", "direct_injection", "indirect_injection", "jailbreak"]
        }
    }

    total_samples = 0
    all_texts_seen = {}

    for split in splits:
        if split not in dataset:
            logger.warning(f"Split {split} not found in dataset! Available: {dataset.keys()}")
            continue
            
        ds_split = dataset[split]
        df = ds_split.to_pandas()
        split_dfs[split] = df
        total_samples += len(df)
        
        logger.info(f"Processing split '{split}': {len(df)} samples, columns: {list(df.columns)}")
        
        # Save raw copy
        raw_split_path = RAW_DATA_DIR / f"{split}.parquet"
        df.to_parquet(raw_split_path, index=False)
        
        # Split metrics
        missing_counts = df.isnull().sum().to_dict()
        empty_text_count = int((df['text'].str.strip() == '').sum()) if 'text' in df.columns else 0
        
        binary_counts = df['label_binary'].value_counts().to_dict() if 'label_binary' in df.columns else {}
        category_counts = df['label_category'].value_counts().to_dict() if 'label_category' in df.columns else {}
        source_counts = df['source'].value_counts().head(10).to_dict() if 'source' in df.columns else {}
        lang_counts = df['language'].value_counts().head(10).to_dict() if 'language' in df.columns else {}
        
        # Duplicate detection within split
        internal_duplicates = int(df.duplicated(subset=['text']).sum()) if 'text' in df.columns else 0
        
        quality_report["splits"][split] = {
            "sample_count": len(df),
            "columns": list(df.columns),
            "missing_values": {k: int(v) for k, v in missing_counts.items()},
            "empty_text_count": empty_text_count,
            "binary_distribution": {str(k): int(v) for k, v in binary_counts.items()},
            "category_distribution": {str(k): int(v) for k, v in category_counts.items()},
            "internal_text_duplicates": internal_duplicates,
            "top_sources": {str(k): int(v) for k, v in source_counts.items()},
            "top_languages": {str(k): int(v) for k, v in lang_counts.items()}
        }
        
        # Track text for cross-split leakage
        for idx, text in enumerate(df['text']):
            norm_text = text.strip().lower()
            if norm_text not in all_texts_seen:
                all_texts_seen[norm_text] = []
            all_texts_seen[norm_text].append(split)

    # Cross-split overlap check
    cross_split_leakage = 0
    for text, occurrences in all_texts_seen.items():
        if len(set(occurrences)) > 1:
            cross_split_leakage += 1

    quality_report["global_checks"] = {
        "total_samples": total_samples,
        "unique_texts": len(all_texts_seen),
        "cross_split_overlapping_texts": cross_split_leakage,
        "note": "Cross-split overlaps are tracked; standard splits preserved according to Hugging Face benchmark standards."
    }

    # Save cleaned processed splits
    for split, df in split_dfs.items():
        # Clean whitespace and handle NaN safely without dropping entire rows
        df['text'] = df['text'].fillna("").astype(str)
        # Ensure correct types
        if 'label_binary' in df.columns:
            df['label_binary'] = df['label_binary'].astype(int)
        if 'label_category' in df.columns:
            df['label_category'] = df['label_category'].astype(str)
            
        processed_path = PROCESSED_DATA_DIR / f"{split}_processed.parquet"
        df.to_parquet(processed_path, index=False)
        logger.info(f"Saved processed {split} to {processed_path}")

    # Write quality report
    report_json_path = BASE_DIR / "datasets" / "dataset_quality_report.json"
    with open(report_json_path, "w", encoding="utf-8") as f:
        json.dump(quality_report, f, indent=2)

    # Write Markdown summary
    report_md_path = BASE_DIR / "datasets" / "README.md"
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# ShieldLM Dataset Quality & Exploration Report\n\n")
        f.write(f"- **Primary Dataset**: `dmilush/shieldlm-prompt-injection`\n")
        f.write(f"- **Total Samples**: {total_samples}\n")
        f.write(f"- **Unique Text Prompts**: {len(all_texts_seen)}\n")
        f.write(f"- **Cross-split duplicates detected**: {cross_split_leakage}\n\n")
        f.write("## Split Summaries\n\n")
        for s, s_data in quality_report["splits"].items():
            f.write(f"### Split: `{s}`\n")
            f.write(f"- Sample count: {s_data['sample_count']}\n")
            f.write(f"- Internal text duplicates: {s_data['internal_text_duplicates']}\n")
            f.write(f"- Binary class distribution: {s_data['binary_distribution']}\n")
            f.write(f"- Category distribution: {s_data['category_distribution']}\n\n")

    logger.info("Dataset download, exploration, and quality validation report completed successfully!")

if __name__ == "__main__":
    download_and_validate_dataset()
