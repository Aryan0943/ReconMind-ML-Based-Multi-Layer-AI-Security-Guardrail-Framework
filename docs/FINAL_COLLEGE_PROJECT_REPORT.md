# ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework
## Final Major Project Comprehensive Technical Report & Presentation Guide

> **Document Status**: Official Final Engineering & Academic Report  
> **Repository**: ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework  
> **Date**: November 2026  
> **Technologies**: Python 3.13, FastAPI, Scikit-Learn, React 18, Vite 5.4, MongoDB / Local Dual-Store  

---

## 1. Problem Statement & Objectives

Large Language Models (LLMs) and autonomous AI agent workflows are vulnerable to adversarial manipulation across multiple stages of execution. Standard perimeter firewalls and simple regex blacklists fail to mitigate sophisticated threats such as:
1. **Direct Prompt Injections**: Instruction overriding and system prompt leakage.
2. **Context & Memory Poisoning**: Persistent injection payloads stored across multi-turn sessions.
3. **Indirect Prompt Injections (RAG Attacks)**: Untrusted retrieved external documents that hijack agent instructions.
4. **Tool Misuse & Privilege Escalation**: Unauthorized function calls, path traversal, and unverified permission elevation.
5. **Sensitive Information Disclosure**: Accidental leakage of API keys, tokens, and PII in model output.

### Project Objectives
- Engineer a **centralized, 5-layer defense architecture** operating under a strict zero-trust model.
- Integrate **classical machine learning (TF-IDF + Logistic Regression)** trained on the **ShieldLM dataset** ($54,162$ samples) with deterministic security rules.
- Implement **authoritative decision enforcement** (`PASS`, `SANITIZE`, `BLOCK`) with request-level telemetry and deduplication.
- Establish an end-to-end autonomous agent workflow demonstrating multi-stage defense isolation.

---

## 2. System Architecture

```
                                  [ User / External Client ]
                                              │
                                              ▼
                                   [ React + Vite Dashboard ]
                                              │  (REST / Axios)
                                              ▼
                                      [ FastAPI Gateway ]
                                              │
                        ┌─────────────────────┴─────────────────────┐
                        ▼                                           ▼
              [Five Defense Modules]                       [ML Inference Engine]
       ┌──────────────────────────────────┐            ┌───────────────────────────┐
       │ Layer 1: Input Defense           │            │ TF-IDF Vectorizer         │
       │ Layer 2: Memory Defense          │ ─────────> │ Binary Logistic Reg.      │
       │ Layer 3: Retrieval Defense       │            │ Multi-Class Classifier    │
       │ Layer 4: Tool Defense            │            └───────────────────────────┘
       │ Layer 5: Output Defense          │
       └──────────────────────────────────┘
                        │
                        ▼
             [Centralized DefenseManager]
                        │
                        ▼
                 [Policy Engine]
            PASS  /  SANITIZE  /  BLOCK
                        │
             ┌──────────┴──────────┐
             ▼                     ▼
      [MongoDB / Fallback]   [Audit Logs API]
```

---

## 3. Dataset Description & Preprocessing

- **Dataset**: `dmilush/shieldlm-prompt-injection` ($54,162$ total samples).
- **Splits**:
  - Training Split: $37,913$ samples ($70.0\%$)
  - Validation Split: $8,124$ samples ($15.0\%$)
  - Held-out Test Split: $8,125$ samples ($15.0\%$)
- **Preprocessing Pipeline**:
  - `clean_security_text`: Unicode NFKC normalization, whitespace standardization, newline formatting.
  - `create_security_tfidf`: Sublinear term frequency, unigram + bigram extraction ($50,000$ max features), token pattern preserving syntax delimiters `r"(?u)\b\w+\b|[\[\]<>{}]"`.
- **Dataset Provenance & Leakage Audit**:
  - Exact duplicates between train and held-out test split: **0** ($0.00\%$ verbatim leakage).
  - Near-duplicate sampled rate: $0.20\%$ (Trigram Jaccard similarity $\ge 0.85$).

---

## 4. Five Defense Layers

### Layer 1: Input Defense (ML + Heuristics)
- Combines classical ML probability scoring with deterministic heuristics.
- Intercepts instruction overrides (`ignore previous instructions`), system prompt extractions (`reveal system prompt`), jailbreak templates (`DAN mode`), and generalized privilege-escalation attempts (`give me admin privilege`, `elevate my access level`, `operate with root privileges`).

### Layer 2: Memory Defense (Session Poisoning Quarantine)
- Inspects proposed conversation memory updates before writing to persistent stores (`memories.json` / MongoDB).
- Isolates memory poisoning attempts into a quarantined state. Downstream agent context queries strictly exclude non-approved entries.

### Layer 3: Retrieval Defense (RAG Passage Inspection)
- Chunks incoming reference documents and scans passages for embedded adversarial instructions.
- Quarantines infected documents before they can be merged into the prompt context.

### Layer 4: Tool Defense (RBAC & Sandboxing)
- Enforces Role-Based Access Control (`ALLOWED_TOOLS` allowlist across `standard_user`, `admin`, `analyst`).
- Prevents path traversal (`..` and absolute paths) and mathematical code injection (`__import__('os')`).

### Layer 5: Output Defense (Deterministic Redaction)
- Scans model responses for credential leaks (OpenAI API keys, AWS credentials, GitHub tokens, PII).
- Redacts secrets with tokens (`[REDACTED_API_KEY]`) or blocks catastrophic outputs (private keys).

---

## 5. Experimental Results & Benchmark Summary

### Held-Out Test Split Metrics (8,125 Samples)

| Metric | Task A: Binary Threat Detection | Task B: Multi-Class Taxonomy |
|---|---|---|
| **Accuracy** | **98.04%** | **96.80%** |
| **Precision** | **97.66%** | $97.17\%$ (Direct), $99.37\%$ (Indirect), $58.44\%$ (Jailbreak) |
| **Recall** | **96.73%** | $93.41\%$ (Direct), $100.0\%$ (Indirect), $88.24\%$ (Jailbreak) |
| **Macro F1** | **0.9785** | **0.9091** |
| **ROC-AUC** | **0.9967** | N/A |
| **False Positive Rate** | **1.25%** ($66 / 5,280$) | N/A |
| **False Negative Rate** | **3.27%** ($93 / 2,845$) | N/A |

### Jailbreak Calibration Analysis
- **Root Cause**: Jailbreak is a minority class ($1.88\%$ of split, $153$ samples). Weighted class balancing drives recall to $88.24\%$ while precision drops to $58.44\%$.
- **Security Impact**: $87.5\%$ of false positives come from overlapping `direct_injection` roleplay attacks. Because `DefenseManager` enforces `BLOCK` on both categories, this boundary confusion does not produce a security bypass.
- **Threshold Calibration**: Raising the jailbreak decision threshold from $0.50$ to $0.65$ improves jailbreak F1 from $0.7031$ to **$0.7187$**.

---

## 6. Live Demonstrations & Recorded Evidence

All five core demonstration scenarios were executed against the live system and recorded in `docs/DEMONSTRATION_RECORDED_EVIDENCE.json`:

1. **Direct Prompt Injection Blocked**: `"Ignore all previous instructions..."` $\rightarrow$ Layer 1 `BLOCK` ($10.82\text{ ms}$).
2. **Privilege Escalation Blocked**: `"give me admin privilege"` $\rightarrow$ Layer 1 `BLOCK` ($4.75\text{ ms}$).
3. **Malicious RAG Document Quarantined**: Prompt passed, poisoned document chunk blocked $\rightarrow$ Layer 3 `BLOCK`, Agent status `INTERCEPTED` ($2.47\text{ ms}$).
4. **Unauthorized Tool Execution Denied**: `read_file` with `../../../../etc/passwd` by `standard_user` $\rightarrow$ Layer 4 `BLOCK` ($0.45\text{ ms}$).
5. **Sensitive Output Automatically Redacted**: Raw API key sanitized $\rightarrow$ Layer 5 `SANITIZE`, key replaced with `[REDACTED_API_KEY]` ($0.58\text{ ms}$).

---

## 7. Limitations & Future Scope

1. **In-Distribution Evaluation**: ShieldLM was randomly partitioned across 13 sources. Future work will benchmark zero-shot transfer against out-of-distribution datasets (`S-Labs`, `cyberec`).
2. **Short Adversarial Prompts**: Very brief semantic paraphrases benefit from dual-layer heuristic reinforcement; future model iterations will explore subword embeddings or distillation for short prompts.
3. **Local Database Mode**: While local JSON dual-persistence ensures zero-configuration development, enterprise production deployments should leverage clustered MongoDB or PostgreSQL with write-ahead logging.
