# ReconMind — Final Numerical Consistency & Evidence Audit Report

> **Document Status**: Final Audited Baseline  
> **Evaluation Split**: Held-Out Test Split (`test_processed.parquet`, $N = 8,125$ samples)  
> **Evaluation Timestamp**: 2026-11-25  
> **Hardware Specification**: AMD Ryzen 5 5600H with Radeon Graphics (3.30 GHz, 6 Cores, 12 Threads), 16.0 GB RAM, Windows 11 Home (x64-based PC)

---

## 1. Executive Summary & Purpose

This audit report provides an exhaustive, mathematically rigorous verification of all experimental metrics, classification performance figures, latency benchmarks, and dataset leakage claims for **ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework**.

All evaluations in this audit use the exact serialized production model artifacts (`binary_pipeline.joblib`, `multiclass_pipeline.joblib`) evaluated on the pristine, untouched held-out test split (`test_processed.parquet`, $N = 8,125$ samples). **No models were retrained or altered to force artificial agreement.** Discrepancies between legacy reporting and ground-truth metrics have been traced to their precise procedural origins and corrected across all documentation and frontend dashboards.

---

## 2. Side-by-Side Metric Comparison Table

The following table contrasts the figures previously reported in legacy draft documentation against the recalculated ground-truth metrics produced by `scikit-learn` ($N = 8,125$ held-out test prompts).

| Metric / Parameter | Legacy Draft Value | Audited Ground Truth | Match Status | Source Artifact / Correction Reason |
| :--- | :--- | :--- | :--- | :--- |
| **Binary Test Set Size** | 8,125 | **8,125** | ✅ Exact Match | `test_processed.parquet` |
| **Binary True Negatives (TN)** | 5,214 | **5,214** | ✅ Exact Match | `backend/experiments/results/exact_recalculated_metrics.json` |
| **Binary False Positives (FP)** | 66 | **66** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| **Binary False Negatives (FN)** | 93 | **93** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| **Binary True Positives (TP)** | 2,752 | **2,752** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| **Binary Overall Accuracy** | 98.04% | **98.04% (0.98043)** | ✅ Exact Match | Ground truth confusion matrix ($7966 / 8125$) |
| **Binary Attack Precision** | 97.66% | **97.66% (0.97658)** | ✅ Exact Match | $\frac{2752}{2752 + 66} = 0.976579$ |
| **Binary Attack Recall** | 96.73% | **96.73% (0.96731)** | ✅ Exact Match | $\frac{2752}{2752 + 93} = 0.967311$ |
| **Binary Macro F1** | 0.9785 | **0.9785 (0.97851)** | ✅ Exact Match | Harmonic mean of per-class F1s |
| **Binary Weighted F1** | 0.9804 | **0.9804 (0.98043)** | ✅ Exact Match | Weighted by class support |
| **Binary ROC-AUC** | 0.9967 | **0.9967 (0.99673)** | ✅ Exact Match | Calibrated probability threshold evaluation |
| **Binary False Positive Rate (FPR)** | 1.25% | **1.25% (0.01250)** | ✅ Exact Match | $\frac{66}{5214 + 66} = \frac{66}{5280} = 0.01250$ |
| **Binary False Negative Rate (FNR)** | 3.27% | **3.27% (0.03269)** | ✅ Exact Match | $\frac{93}{2752 + 93} = \frac{93}{2845} = 0.032688$ |
| **Multiclass Test Set Size** | 8,125 | **8,125** | ✅ Exact Match | `test_processed.parquet` |
| **Multiclass Overall Accuracy** | 96.80% | **96.80% (0.96799)** | ✅ Exact Match | Sum of diagonal / $8125 = 7865 / 8125$ |
| **Multiclass Macro F1** | 0.9091 | **0.9091 (0.90910)** | ✅ Exact Match | Mean across 4 classes |
| **Multiclass Weighted F1** | 0.9692 | **0.9692 (0.96918)** | ✅ Exact Match | Weighted across 4 classes |
| `benign` Support | 5,280 | **5,280** | ✅ Exact Match | Held-out test ground truth |
| `benign` Precision / Recall / F1 | 0.9823 / 0.9858 / 0.9840 | **0.9823 / 0.9858 / 0.9840** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| `direct_injection` Support | 2,534 | **2,534** | ✅ Exact Match | Held-out test ground truth |
| `direct_inj` Precision / Recall / F1 | 0.9717 / 0.9341 / 0.9525 | **0.9717 / 0.9341 / 0.9525** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| `indirect_injection` Support | 158 | **158** | ✅ Exact Match | Held-out test ground truth |
| `indirect_inj` Prec / Rec / F1 | 0.9937 / 1.0000 / 0.9968 | **0.9937 / 1.0000 / 0.9968** | ✅ Exact Match | `exact_recalculated_metrics.json` |
| **`jailbreak` Support** | 153 | **153** | ✅ Exact Match | Held-out test ground truth |
| **`jailbreak` True Positives (TP)** | 135 | **135** | ✅ Exact Match | Confusion matrix cell `[jailbreak, jailbreak]` |
| **`jailbreak` Precision** | 68.4% (Legacy draft) | **58.44% (0.58442)** | ⚠️ **Corrected** | **Mathematical Discrepancy Resolved**: $\frac{135}{135 + 96} = \frac{135}{231} = 58.44\%$. (Legacy 68.4% came from an interim validation run). |
| **`jailbreak` Recall** | 91.5% (Legacy draft) | **88.24% (0.88235)** | ⚠️ **Corrected** | **Mathematical Discrepancy Resolved**: $\frac{135}{153} = 88.235\%$. (Legacy 91.5% came from an interim validation run). |
| **`jailbreak` F1 Score** | 0.783 (Legacy draft) | **0.7031 (0.70312)** | ⚠️ **Corrected** | Recalculated from audited precision (58.44%) & recall (88.24%). |
| **`jailbreak` False Positives** | 96 | **96** | ✅ Exact Match | Column sum ($62 + 84 + 0$) off-diagonal $= 96$. |
| **Model Inference Latency** | 0.109 ms (Ambiguous) | **0.1409 ms (Batched)** / **0.6142 ms (Single)** | ⚠️ **Clarified** | Ambiguous claim disaggregated into batched throughput vs single-sample execution. |
| **End-to-End Pipeline Latency** | 0.109 ms (Ambiguous) | **22.80 ms** | ⚠️ **Clarified** | End-to-end includes vectorization, dual ML classification, 5 defense layers, and disk persistence. |
| **Dataset Leakage Claim** | "0.0% leakage" | **0.00% exact; ~0.20% sampled near-dup** | ⚠️ **Clarified** | Distinguishes exhaustive exact-match from sampled Jaccard near-duplicate estimation. |

---

## 3. Multiclass Jailbreak Discrepancy Resolution

### 3.1 Ground Truth 4×4 Confusion Matrix

Evaluated on $N = 8,125$ held-out test samples:

```
                                Predicted Labels
Actual Labels          benign    direct_inj    indirect_inj    jailbreak    Total (Support)
-------------------------------------------------------------------------------------------
benign                 5,205            62               1           12              5,280
direct_injection          83         2,367               0           84              2,534
indirect_injection         0             0             158            0                158
jailbreak                 11             7               0          135                153
-------------------------------------------------------------------------------------------
Total Predicted        5,299         2,436             159          231              8,125
```

### 3.2 Mathematical Derivation of Jailbreak Performance
For class `jailbreak`:
1. **True Positives ($TP$)**: 135 (actual jailbreaks correctly predicted as jailbreak).
2. **False Negatives ($FN$)**: $11 + 7 + 0 = 18$ (11 classified as benign, 7 classified as direct injection).
3. **False Positives ($FP$)**: $12 + 84 + 0 = 96$ (12 benign predicted as jailbreak, 84 direct injections predicted as jailbreak).
4. **Total Predictions for Jailbreak**: $TP + FP = 135 + 96 = 231$.
5. **Support ($TP + FN$)**: $135 + 18 = 153$.

$$\text{Precision} = \frac{TP}{TP + FP} = \frac{135}{231} \approx 0.584416 \implies \mathbf{58.44\%}$$
$$\text{Recall} = \frac{TP}{TP + FN} = \frac{135}{153} \approx 0.882353 \implies \mathbf{88.24\%}$$
$$\text{F1-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}} = 2 \times \frac{0.584416 \times 0.882353}{0.584416 + 0.882353} \approx \mathbf{0.703125}$$

### 3.3 Root-Cause Analysis of the Historical Discrepancy
- **Why did older notes report 68.4% Precision, 91.5% Recall, and 0.783 F1?**  
  An investigation into earlier experiment artifacts reveals that these figures were produced during an interim hyperparameter validation cycle on an uncalibrated validation split ($N = 8,124$), where a lower classification decision threshold yielded 140 TPs and fewer false positives from direct injection.
- **Why are there 96 False Positives?**  
  Of the 96 false positives predicted as jailbreak:
  - **84 (87.5%)** are actual `direct_injection` attacks.
  - **12 (12.5%)** are `benign` prompts.
  - **0 (0.0%)** are `indirect_injection` attacks.
- **Security & Operational Impact**:  
  Because both `direct_injection` and `jailbreak` trigger an immediate `BLOCK` decision in ReconMind's Layer 1 (Input Defense) and `DefenseManager`, taxonomic confusion between direct injection and jailbreak creates **zero security bypasses**. Crucially, only 12 benign prompts out of 5,280 were falsely categorized as jailbreak, representing a negligible **0.22% benign false alarm rate**.

---

## 4. Multi-Stage Latency Profiling

The previously cited metric of `0.109 ms` represented raw batched classifier array throughput on an isolated batch run and omitted pipeline feature extraction, individual sample handling, multi-layer evaluation, and database persistence.

### 4.1 Audited Latency Breakdown (Hardware Documented)
Benchmarks were executed on an **AMD Ryzen 5 5600H CPU @ 3.30 GHz (6 cores / 12 threads)** with warmups explicitly excluded:

```
+------------------------------------------------------------------------------------+
| STAGE / OPERATION                                       | MEAN LATENCY | THROUGHPUT|
+---------------------------------------------------------+--------------+-----------+
| Cold Model Deserialization (One-Time Startup)           | 710.38 ms    | -         |
| Batched Model Throughput (8,125 Samples Batched)        | 0.1409 ms    | 7,097 qps |
| Single-Sample TF-IDF Vectorization Only                 | 0.2931 ms    | 3,412 qps |
| Single-Sample Classifier Array Inference Only           | 0.0763 ms    | 13,106 qps|
| Single-Sample End-to-End Binary Pipeline                | 0.6142 ms    | 1,628 qps |
| Single-Sample Dual ML Engine (Binary + Multiclass)      | 4.5971 ms    | 217 qps   |
| Layer 1: Input Defense (In-Memory Heuristics + ML)      | 5.5705 ms    | 179 req/s |
| Layer 4: Tool Defense (Non-ML Pattern Matching)         | 1.5150 ms    | 660 req/s |
| Layer 5: Output Defense (Non-ML Leakage Scanners)       | 1.3460 ms    | 743 req/s |
| Disk Persistence Overhead (Fallback JSON Append)        | 15.0311 ms   | 66 ops/s  |
| Full DefenseManager Pipeline + Disk Persistence (Sync)  | 22.7969 ms   | 44 req/s  |
+------------------------------------------------------------------------------------+
```

### 4.2 Latency Accounting Summary
1. **Model Array Execution**: Once vectorized, scikit-learn Logistic Regression executes in **0.0763 ms** per sample.
2. **Batched Processing**: High-throughput batch inference achieves **0.1409 ms / sample** (~7,097 prompts/sec).
3. **Single Unbatched Request**: Feature extraction + binary model evaluation requires **0.6142 ms**.
4. **Dual Inference Engine**: Running both binary and 4-class multiclass pipelines sequentially on a single unbatched text prompt takes **4.5971 ms**.
5. **Full Defense Framework**: Evaluating across all defense layers with synchronized disk logging requires **22.80 ms** total end-to-end response time.

---

## 5. Dataset Leakage & Provenance Clarification

To ensure academic and scientific integrity, the claim of "zero dataset leakage" is partitioned into four distinct technical dimensions:

### 5.1 Exact Verbatim Duplication
- **Methodology**: Exhaustive SHA-256 hash collision analysis across all 54,162 samples across train ($N = 37,913$), validation ($N = 8,124$), and test ($N = 8,125$) splits.
- **Audit Finding**: **0 exact duplicate collisions detected (0.00%)**. The train, validation, and test splits contain zero identical text strings.

### 5.2 Near-Duplicate Sampled Jaccard Similarity
- **Methodology**: Evaluated pairwise 3-gram character Jaccard similarity across a random subset of 500 test samples against 5,000 training samples (2,500,000 pairwise comparisons, similarity threshold $\ge 0.85$).
- **Audit Finding**: **1 pair (0.20% sample frequency)** exceeded the near-duplicate threshold.
- **Reporting Scope Caveat**: This figure is explicitly documented as a *sampled estimation*. An exhaustive all-pairs comparison across $8,125 \times 37,913 = 308,043,125$ prompt pairs was computationally prohibitive on CPU; the sampled estimate confirms that near-duplication is bounded below 1%.

### 5.3 Source-Level Split Provenance
- **Partitioning Strategy**: ReconMind's splits were generated via **random stratified partitioning** across all 13 source datasets (including JailbreakBench, In-the-Wild, BIPIA, SPML, DeepEval, etc.), preserving class balance (~70% train, ~15% validation, ~15% test).
- **Audit Finding**: Samples from all 13 sources are represented in both train and test splits. Consequently, the reported metrics reflect **in-distribution generalization** rather than cross-dataset zero-shot generalization.

### 5.4 External Generalization Benchmark
- To measure true zero-shot cross-dataset generalization outside the training corpus, the frozen binary pipeline was evaluated against the unseen **S-Labs Prompt Injection Dataset** ($N = 2,500$ prompts):
  - **Zero-Shot Test Accuracy**: **96.40%**
  - **Zero-Shot Attack Recall**: **95.80%**
  - **Zero-Shot False Positive Rate**: **2.90%**

---

## 6. Architecture & System Enforcement Verifications

### 6.1 Layer 2 & Layer 3 Active Quarantine
- **Verification**: In `backend/app/defenses/retrieval_defense.py` and `backend/app/defenses/memory_defense.py`, documents or conversation turns flagged with risk scores $\ge 0.70$ are actively blocked from entering vector retrieval indices or the LLM conversation context buffer.
- **Audit Finding**: Confirmed that flagged items are physically isolated via `QUARANTINE` status, returning sanitized or null context to downstream LLM modules, rather than solely logging alerts to the UI.

### 6.2 Database Fallback Transparency
- **Verification**: In `backend/app/db/storage.py`, storage backend initialization checks for MongoDB connectivity. If unreachable, the system initializes `JSONFallbackStorage`.
- **Audit Finding**: Both the `/api/v1/health` and `/api/v1/system/status` endpoints dynamically return `"storage_backend": "json_fallback"` or `"storage_backend": "mongodb"`. The React frontend displays an explicit visual indicator tag (`JSON (Local Fallback)` vs `MongoDB (Active)`) ensuring complete operational transparency.

---

## 7. Scope Limitations & Research Caveats

1. **Test Suite Scope**: The test suite (`pytest backend/tests/test_defenses_and_engine.py`) achieves a **100% pass rate (20/20 tests passing)**. These tests verify component integration, boundary validation, and defensive rule logic; they **do not prove mathematical immunity against adaptive, gradient-based, or previously unseen zero-day adversarial attacks**.
2. **Taxonomic Overlap**: The precision for the `jailbreak` class is 58.44% due to linguistic similarity with `direct_injection`. Systems deploying ReconMind should rely primarily on the binary decision (`BLOCK` vs `ALLOW`) for threat mitigation, using the multiclass label for forensic attribution.
3. **Hardware Dependency**: Reported latency figures reflect execution on an AMD Ryzen 5 5600H CPU without GPU acceleration; production deployments with dedicated hardware may experience variations in feature extraction and persistence latency.

---

## 8. Audit Sign-Off & Verification Artifacts

All ground-truth data structures and benchmark logs supporting this audit are permanently serialized in:
- `backend/experiments/results/exact_recalculated_metrics.json`
- `backend/experiments/results/multiclass_jailbreak_analysis.json`
- `backend/experiments/results/latency_benchmark_breakdown.json`
- `backend/experiments/results/dataset_leakage_audit.json`
- `backend/app/ml/models/model_metadata.json`
