# ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework
## Major Academic Project Report · B.Tech Computer Engineering

---

## 1. Introduction
Large Language Models (LLMs) and autonomous AI agent architectures have rapidly transitioned from research curiosities to mission-critical backbones across financial systems, healthcare portals, customer service bots, and software engineering copilot tools. Despite their generative strengths, LLMs are fundamentally vulnerable to adversarial prompt exploitation. Because these systems ingest data from uncurated sources—direct user prompts, retrieved RAG context documents, long-term memory stores, and output streams—traditional boundary firewalls fail to secure them.

**ReconMind** is an end-to-end, multi-layer AI security guardrail framework engineered to inspect, classify, sanitize, and intercept adversarial interactions across five critical application layers. Rather than treating prompt security as an isolated input filter, ReconMind combines classical Machine Learning (TF-IDF vectorization with regularized Logistic Regression and Naive Bayes) with deterministic security heuristics and role-based policy enforcement.

---

## 2. Problem Statement & Project Objectives

### 2.1 Problem Statement
Modern AI applications interface with multiple input and execution vectors simultaneously. A single input-level regex filter cannot protect against:
1. **Direct Prompt Injections & Jailbreaks**: User prompts attempting to override system behavior or force unrestricted output.
2. **Context & Memory Poisoning**: Adversarial instructions injected into conversation memory to alter future persona behavior.
3. **Indirect Injections via Document Retrieval (RAG)**: Malicious payloads hidden inside uploaded PDFs or external web pages retrieved into prompt context.
4. **Unauthorized AI Agent Tool Misuse**: Manipulation of tool function calls (e.g. path traversal, SQL injection, unauthorized email dispatches).
5. **Confidential Secret Leakage**: Accidental emission of API tokens, AWS keys, passwords, or PII in LLM output streams.

### 2.2 Core Objectives
- Train and compare classical ML models for **Binary Threat Classification** (Benign vs. Attack) and **Multi-Class Attack Taxonomy** (Benign, Direct Injection, Indirect Injection, Jailbreak).
- Implement five independent, decoupled defense layers: **Input Defense**, **Memory Defense**, **Retrieval Defense**, **Tool Defense**, and **Output Defense**.
- Build a centralized **DefenseManager** and **Policy Engine** enforcing `PASS`, `SANITIZE`, and `BLOCK` decisions.
- Maintain persistent security audit logs with MongoDB (and high-speed local development fallback).
- Build a production-grade cybersecurity SaaS dashboard in React & Vite with real-time telemetry and visualization.

---

## 3. Dataset Description

ReconMind utilizes the curated **ShieldLM Prompt Injection Dataset** (`dmilush/shieldlm-prompt-injection`) hosted on Hugging Face as its primary training and evaluation benchmark.

### 3.1 Dataset Summary Statistics
- **Total Samples**: 54,162
- **Language**: English-dominant (~98.8%), with multi-lingual samples (Spanish, French, Italian, German)
- **Columns**: `id`, `text`, `label_binary`, `label_category`, `label_intent`, `source`, `language`, `context`, `metadata`

### 3.2 Split Breakdown (Benchmark Preserved)
| Split | Total Samples | Benign Prompts | Malicious Prompts | Direct Injection | Indirect Injection | Jailbreak |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Train** | 37,913 | 24,638 | 13,275 | 11,825 | 738 | 712 |
| **Validation** | 8,124 | 5,279 | 2,845 | 2,534 | 158 | 153 |
| **Test (Held-out)** | 8,125 | 5,280 | 2,845 | 2,534 | 158 | 153 |
| **Combined** | **54,162** | **35,197** | **18,965** | **16,893** | **1,054** | **1,018** |

### 3.3 Multi-Tier Dataset Leakage & Provenance Audit
A rigorous multi-tier audit was conducted across the 54,162 samples to clearly distinguish exact duplication, sampled near-duplication, and source provenance:
1. **Tier 1: Exhaustive Exact Verbatim Duplicate Audit**:
   - **Scope**: All 54,162 prompts compared pairwise across Train (37,913), Validation (8,124), and Test (8,125).
   - **Result**: Exactly **0 duplicate prompts (0.00% overlap)**. Every prompt text in the dataset is unique, with zero verbatim overlap between training and held-out test splits.
   - **Label Inconsistencies**: 0 identical texts with conflicting binary labels.

2. **Tier 2: Sampled Near-Duplicate Audit (Important Methodology Note)**:
   - **Scope**: Stochastic sample comparison (500 randomly sampled test prompts evaluated against a pool of 5,000 training prompts).
   - **Method**: Tri-gram Jaccard Similarity (\( \text{Jaccard} \ge 0.85 \)).
   - **Result**: Detected 1 near-duplicate in the 500-sample audit (**~0.20% sampled rate**).
   - **Explicit Limitation**: This check was a *sampled estimation*, not an exhaustive all-pairs comparison of all 8,125 test prompts against all 37,913 training prompts (which would require ~308 million text comparisons).

3. **Tier 3: Source-Level Split Provenance Audit**:
   - **Scope**: Group-level tracking of all 13 underlying benchmark sources across splits.
   - **Result**: **13 out of 13 sources appear across Train, Validation, and Test splits**.
   - **Academic Finding**: ShieldLM was created via **random stratified splitting across classes**, *not* by source-level group splitting. All source datasets (`alespalla/chatbot-instruction-prompts`, `spml/chatbot-prompt-injection`, `safeguard/prompt-injection`, etc.) are partitioned proportionally (~70% train, ~15% val, ~15% test). Consequently, test prompts share stylistic conventions and vocabulary distributions with training data.

4. **Tier 4: Independent External Dataset Evaluation**:
   - **Status**: Candidate for future zero-shot out-of-distribution transfer benchmarking.
   - **Notes**: ShieldLM metrics reflect in-distribution evaluation. External datasets (such as `S-Labs/prompt-injection-dataset` and `cyberec/Prompt-injection-dataset`) must be evaluated independently to establish true cross-corpus robustness.

---

## 4. Data Preprocessing & Feature Extraction

### 4.1 Token Normalization with Security Preservation
Standard NLP preprocessing (such as aggressive stopword removal and stemming) damages attack detection because words like `ignore`, `system`, `instructions`, `reveal`, `override`, and `bypass` are critical adversarial indicators.
- **Unicode Normalization**: NFKC normalization converts visual confusables and homoglyphs.
- **Whitespace Normalization**: Uniform newline/tab standardization while preserving syntactic structure.
- **Punctuation & Delimiter Retention**: Preservation of brackets `[]`, XML tags `<>`, and backticks ``` essential for detecting delimiter injection attacks.

### 4.2 TF-IDF Feature Representation
Features are extracted using an adversarial-tuned Term Frequency-Inverse Document Frequency (TF-IDF) vectorizer fitted **only** on the training split:
\[
\text{TF-IDF}(t, d, D) = \text{TF}(t, d) \times \log\left(\frac{1 + |D|}{1 + |\{d \in D : t \in d\}|}\right) + 1
\]
- **N-gram Range**: $(1, 2)$ (capturing unigrams and key bigrams such as "ignore previous", "system prompt", "DAN mode")
- **Max Features**: 50,000 top sublinear features
- **Minimum Document Frequency (min_df)**: 2
- **Sublinear TF Scaling**: Replaces $\text{TF}$ with $1 + \log(\text{TF})$ to dampen the effect of repetitive query payloads.

---

## 5. Machine Learning Models & Empirical Comparison

Four classical machine learning algorithms were trained and empirically evaluated on the validation split:
1. **Logistic Regression (with $L_2$ regularization and balanced class weights)**
2. **Multinomial Naive Bayes (with Laplace smoothing $\alpha = 0.1$)**
3. **Linear Support Vector Machine (SGDClassifier calibrated via Platt scaling)**
4. **Random Forest Classifier (Ensemble of 100 balanced decision trees)**

### 5.1 Binary Classifier Comparison (Validation Split)
| Algorithm | Accuracy | Malicious Recall | Precision | Macro F1 | ROC-AUC | Latency / Sample |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | **97.86%** | **96.38%** | **97.48%** | **0.9764** | **0.9965** | **0.102 ms** |
| Multinomial Naive Bayes | 96.70% | 95.40% | 95.19% | 0.9638 | 0.9919 | 0.102 ms |
| Linear SVM (Calibrated) | 96.66% | 94.73% | 95.70% | 0.9633 | 0.9932 | 0.106 ms |
| Random Forest | 95.16% | 87.98% | 98.00% | 0.9455 | 0.9876 | 0.122 ms |

**Finding**: Logistic Regression outperformed Random Forest by +8.4% on malicious recall because high-dimensional sparse TF-IDF text vectors are linearly separable.

### 5.2 Multi-Class Classifier Comparison (Validation Split)
| Algorithm | Accuracy | Macro F1 | Weighted F1 | Train Time |
| :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | **97.11%** | **0.9253** | **0.9716** | **9.12 s** |
| Multinomial Naive Bayes | 96.07% | 0.9125 | 0.9613 | 6.84 s |
| Linear SVM (Calibrated) | 95.27% | 0.8787 | 0.9520 | 8.35 s |
| Random Forest | 93.83% | 0.8845 | 0.9367 | 14.21 s |

---

## 6. Final Evaluation on Held-Out Test Split (8,125 Samples)

The final pipelines were evaluated on the completely untouched held-out test split:

### 6.1 Binary Classification (Task A)
- **Test Accuracy**: **98.04%**
- **Malicious Recall**: **96.73%** (2,752 out of 2,845 attacks detected)
- **Precision**: **97.66%**
- **Macro F1-Score**: **0.9785**
- **Test ROC-AUC**: **0.9967**
- **False Positive Rate (FPR)**: **1.25%** (only 66 false alarms out of 5,280 benign prompts)
- **False Negative Rate (FNR)**: **3.27%**
- **Average Inference Latency**: **0.109 ms per sample**

#### Confusion Matrix (Held-out Test Split)
```
                  Predicted Benign   Predicted Attack
Actual Benign          5,214               66        (98.75% TNR)
Actual Attack             93            2,752        (96.73% TPR)
```

### 6.2 Multi-Class Classification (Task B)
- **Overall Test Accuracy**: **96.80%**
- **Macro F1-Score**: **0.9091**
- **Weighted F1-Score**: **0.9692**

#### Per-Class Performance Breakdown (Held-out Test Split, Exact Ground-Truth)
| Class | Precision | Recall | F1-Score | Support |
| :--- | :--- | :--- | :--- | :--- |
| **Benign** | 98.23% | 98.58% | 0.9840 | 5,280 |
| **Direct Injection** | 97.17% | 93.41% | 0.9525 | 2,534 |
| **Indirect Injection** | 99.37% | 100.00% | 0.9968 | 158 |
| **Jailbreak** | 58.44% | 88.24% | 0.7031 | 153 |

#### 4x4 Multi-Class Confusion Matrix (Exact Counts)
```
                          Pred: benign   Pred: direct_inj   Pred: indirect_inj   Pred: jailbreak
Actual: benign                5,205              62                  1                 12
Actual: direct_injection         83           2,367                  0                 84
Actual: indirect_injection        0               0                158                  0
Actual: jailbreak                11               7                  0                135
```

### 6.3 Deep-Dive Error Analysis: Jailbreak Metric Audit
A mathematical and empirical audit was conducted to investigate jailbreak classification performance:
1. **Mathematical Consistency Verification**:
   - **Support**: 153 actual jailbreak samples (1.88% of test split).
   - **True Positives**: 135 correctly predicted as jailbreak.
   - **False Negatives**: 18 jailbreak samples misclassified (11 as benign, 7 as direct injection).
   - **Total Predicted as Jailbreak**: 231 (135 TP + 84 from direct injection + 12 from benign + 0 from indirect injection).
   - **False Positives**: 96 prompts falsely predicted as jailbreak.
   - **Exact Recall**: \( \frac{135}{153} = 88.2353\% \)
   - **Exact Precision**: \( \frac{135}{231} = 58.4416\% \)
   - **Exact Harmonic Mean F1**: \( 2 \times \frac{0.584416 \times 0.882353}{0.584416 + 0.882353} = 0.703125 \)
   *(Note: The earlier draft numbers—68.4% precision / 91.5% recall—originated from an interim validation run; the above verified metrics represent the exact, reproducible ground-truth on the final serialized pipeline and held-out test split).*

2. **Root Cause Analysis**:
   - **Severe Class Imbalance**: Jailbreak is a minority class (153/8,125 test prompts, 1.88%). Applying `class_weight='balanced'` assigns ~13x higher loss weight to jailbreak errors, deliberately pulling the decision boundary to maximize attack detection (88.24% recall).
   - **False Positive Origin**: Of the 96 false positives, **84 (87.5%) are actual attacks (`direct_injection`)** featuring persona-override vocabulary ("act as", "pretend", "ignore rules"). Only 12 of 5,280 benign prompts were misclassified as jailbreak (0.22% benign FPR).
   - **Security Guardrail Outcome**: Both `direct_injection` and `jailbreak` receive an immediate **`BLOCK`** action by the centralized PolicyEngine. Taxonomic confusion between these two attack types does **not** result in a security bypass.

### 6.4 Audited Multi-Stage Latency Profiling
Latency was systematically audited across isolated pipeline stages with cold-start initialization excluded and 10 warm-up iterations discarded:
- **Cold Model Initialization**: **710.38 ms** (one-time Joblib deserialization from disk at server startup).
- **Batched Model Throughput**: **0.1409 ms / sample** (~7,097 samples/sec across 8,125 test texts via sparse BLAS matrix operations).
- **Vectorization Only (Single-Sample)**: **0.2931 ms** (unbatched text cleaning and TF-IDF feature mapping).
- **Classifier Only (Single-Sample)**: **0.0763 ms** (Logistic Regression inference on pre-vectorized sparse row).
- **Single-Sample Binary Model Pipeline**: **0.6142 ms** (~1,628 queries/sec for full unbatched single string prediction).
- **Single-Sample Dual ML Engine**: **4.5971 ms** (~217 queries/sec for binary + 4-class multi-class + probability array extraction).
- **Layer 1: Input Defense (In-Memory)**: **5.5705 ms** (~179 requests/sec for Dual ML + regex heuristic signature scan).
- **Layer 4: Tool Defense (Non-ML)**: **1.515 ms** (RBAC allowlist and path traversal prevention).
- **Layer 5: Output Defense (Non-ML)**: **1.346 ms** (Regex secret scanning and automatic string redaction).
- **Database Persistence I/O Overhead**: **15.0311 ms** (Serializing audit log to local JSON file store).
- **End-to-End DefenseManager with Persistence**: **22.7969 ms** (~44 complete audited transactions/sec).

---

## 7. The Five Defense Layers & Centralized Architecture

```
[User / Application / RAG / Agent / Model]
                  │
                  ▼
         [FastAPI Gateway]
                  │
 ┌────────────────┴────────────────┐
 │     Five Defense Modules        │
 ├─────────────────────────────────┤
 │ Layer 1: Input Defense          │  <-- TF-IDF + Binary/Multiclass ML + Heuristics
 │ Layer 2: Memory Defense         │  <-- Persistent Poisoning Checker + Context Store
 │ Layer 3: Retrieval Defense      │  <-- Chunked Text/PDF Scanner + Risk Aggregator
 │ Layer 4: Tool Defense           │  <-- Role-based ACL + Path Traversal Filter
 │ Layer 5: Output Defense         │  <-- Regex Secret Scanner + Automatic Redactor
 └────────────────┬────────────────┘
                  │
                  ▼
       [Centralized DefenseManager]
                  │
                  ▼
           [Policy Engine]
           PASS / SANITIZE / BLOCK
                  │
       ┌──────────┴──────────┐
       ▼                     ▼
[Security Audit DB]   [React Dashboard]
```

### 7.1 Layer Functionality Summary
1. **Input Defense**: Validates user prompts for length anomalies, runs TF-IDF inference, and detects direct injections, DAN jailbreaks, and system extractions.
2. **Memory Defense**: Inspects conversation memory entries before storage; prevents malicious instructions from polluting agent memory sessions.
3. **Retrieval Defense**: Parses TXT and PDF documents via `pypdf`, splits text into sliding chunks, flags individual hazardous chunks, and determines overall document quarantine status.
4. **Tool Defense**: Evaluates AI agent tool execution requests against an allowlist (calculator, document_search, file_listing, mock_email), role hierarchy, and path traversal checks. Independent of text classification.
5. **Output Defense**: Scans generated AI text for exposed API keys, OpenAI tokens (`sk-...`), AWS access keys, GitHub personal access tokens, private RSA keys, emails, and credit cards. Redacts sensitive patterns in-place (`SANITIZE`).

### 7.2 Active Memory & Retrieval Quarantine Enforcement
A common flaw in security prototypes is flagging an interaction in a dashboard while still allowing it to enter the application's active context. ReconMind implements physical architectural separation:
- **Active Memory Isolation**: The conversation memory repository implements strict dual-view querying. When an AI agent requests conversational memory context, queries enforce `approved_only=True`. Any entry marked as `rejected` (BLOCK) or `quarantined` (SANITIZE) is physically excluded from active prompt assembly.
- **Active Retrieval Index Isolation**: When a document is scanned, only documents receiving a `PASS` rating are stored in the active retrieval index. Poisoned documents are stored exclusively in the quarantine register (`is_active_for_retrieval=False`) and cannot be indexed into RAG search results.

### 7.3 Database Persistence Transparency
ReconMind operates with dual storage capability. To avoid misleading users into believing a production database is active:
- The system checks for live MongoDB availability. If unavailable, it activates the `Local JSON File Store (Development Fallback)`.
- The API health check (`/api/v1/health`) and UI Navbar/Dashboard prominently surface the active storage engine with an amber alert pill whenever running in fallback mode, exposing the exact local file path.

---

## 8. Software Testing & Verification Scope

A comprehensive Pytest test suite (`backend/tests/test_defenses_and_engine.py`) with 20 integration and unit tests was executed:
- All 20 tests passed with **100% pass rate** in 11.40 seconds.
- Verified components: ML Inference Engine, Binary & Multiclass prediction, All 5 defense layers, Active memory context exclusion, Active retrieval quarantine exclusion, Database fallback transparency, Policy engine dynamic threshold updates, and Redaction gates.

> **Important Scope Caveat**:
> The 20 passing unit and integration tests prove that the implemented modules, security boundaries, and tested adversarial cases behave strictly in accordance with their design specifications. They **do not** prove comprehensive security against all possible zero-day prompt injection variants, multi-step jailbreaks, or production readiness. In a production enterprise deployment, continuous adversarial red-teaming, rate-limiting, and runtime WAF proxies remain mandatory.

---

## 9. Challenges and Limitations

1. **High Class Imbalance in Attack Taxonomy**: Minority classes like `jailbreak` and `indirect_injection` comprise <3% of the training dataset. Addressed using `class_weight='balanced'`.
2. **Context-Free TF-IDF Limitation**: TF-IDF examines n-gram token frequencies rather than deep bidirectional transformer attention.
3. **Multi-Turn Stealth Injections**: Complex attacks distributed across dozens of conversational turns require multi-turn conversational graph tracking.
4. **Tool Execution Boundaries**: Tool defense is reliant on strict deterministic allowlists and parameter schemas rather than probabilistic classification.

---

## 10. Conclusion & Future Scope

ReconMind demonstrates that multi-layer AI security cannot rely solely on a basic input classifier. By integrating empirical classical ML models trained on 54,000+ benchmark prompts with five dedicated defense layers, centralized policy enforcement, and audit persistence, ReconMind provides a robust, locally runnable guardrail framework for production AI applications.

**Future Scope**:
- Integration with local Ollama / vLLM endpoints and OpenAI-compatible proxy APIs.
- Extension to multilingual semantic embeddings (e.g. BGE or MiniLM).
- Agent execution sandboxing with WebAssembly (Wasm) isolated runtimes.
