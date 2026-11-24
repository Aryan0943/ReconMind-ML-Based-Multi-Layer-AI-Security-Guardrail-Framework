# ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.4+-F7931E.svg)](https://scikit-learn.org)
[![React](https://img.shields.io/badge/React-18-61DAFB.svg)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-5.4-646CFF.svg)](https://vitejs.dev)

ReconMind is a centralized, multi-layer AI security guardrail framework engineered to inspect, classify, sanitize, and intercept adversarial interactions across five critical application layers in LLM applications and AI agent workflows.

---

## Key Highlights

- **Classical Machine Learning Integration**: Trained on **54,162 samples** from the **ShieldLM Prompt Injection Dataset** (`dmilush/shieldlm-prompt-injection`).
  - **Binary Model**: 98.04% Test Accuracy, 96.73% Attack Recall, 0.9967 ROC-AUC, 0.1409 ms batched throughput (0.614 ms unbatched).
  - **Multi-Class Taxonomy**: 4 classes (`benign`, `direct_injection`, `indirect_injection`, `jailbreak`) with 96.80% Test Accuracy and 0.9091 Macro F1.
- **Five Decoupled Defense Layers**:
  - **Layer 1: Input Defense**: Direct prompt injections, DAN jailbreaks, system extractions.
  - **Layer 2: Memory Defense**: Prevents persistent instruction override and context poisoning in conversation stores.
  - **Layer 3: Retrieval Defense**: Chunks TXT and PDF documents, identifies indirect prompt injection payloads.
  - **Layer 4: Tool Defense**: Evaluates mock agent tool requests against role-based allowlists and prevents path traversal.
  - **Layer 5: Output Defense**: Scans model responses and automatically redacts API keys, AWS secrets, tokens, and PII.
- **Centralized DefenseManager & Policy Engine**: Unifies all layer decisions into standard `PASS`, `SANITIZE`, and `BLOCK` actions.
- **Dual Persistence Architecture**: Native MongoDB integration with automatic, high-speed local file-based development fallback store.
- **Modern Cyber SaaS Dashboard**: Dark navy theme, interactive testing workbench, Recharts telemetry, and real-time security event logs.

---

## System Architecture

```
                                 [ User / External Agents ]
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

## Directory Structure

```
ReconMind/
├── backend/
│   ├── app/
│   │   ├── api/                  # REST endpoints: scan, logs, dashboard, models, policies
│   │   ├── database/             # MongoDB connection & local JSON fallback store
│   │   ├── defenses/             # Five independent defense layer modules
│   │   ├── engine/               # Centralized DefenseManager & PolicyEngine
│   │   ├── ml/                   # Preprocessing, training scripts, pipelines, and inference engine
│   │   │   └── models/           # Serialized Joblib pipelines & model_metadata.json
│   │   ├── schemas/              # Pydantic request & response models
│   │   ├── security/             # Regex rules, sensitive data scanner, tool ACLs
│   │   ├── config.py             # App & threshold configuration
│   │   └── main.py               # FastAPI application entrypoint
│   ├── datasets/
│   │   ├── processed/            # Parquet splits: train, validation, test
│   │   └── dataset_quality_report.json
│   ├── experiments/              # Comparison metrics & test results
│   ├── scripts/
│   │   └── download_dataset.py   # Dataset ingestion & statistical quality report
│   ├── tests/                    # Pytest test suite (20 passed tests)
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/           # Sidebar, Navbar, StatCard, Badges
│   │   ├── pages/                # Dashboard, SecurityScanner, LayerTesting, Logs, Evaluation, Settings
│   │   ├── services/             # Axios API client
│   │   ├── styles/               # Cybersecurity Dark Navy CSS theme
│   │   ├── App.jsx
│   │   └── main.jsx
│   ├── package.json
│   └── vite.config.js
├── DEVELOPMENT_PROGRESS.md
├── PROJECT_REPORT.md             # Formal B.Tech major project academic report
└── README.md
```

---

## Quickstart & Installation

### 1. Prerequisites
- Python 3.11 or newer
- Node.js 18+ and npm
- (Optional) MongoDB 6+ running on `mongodb://localhost:27017` (ReconMind automatically activates its local storage fallback if MongoDB is not detected).

### 2. Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create & activate a virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Dataset Download & Model Training
The dataset scripts and trained model artifacts are already included in the repository. If you wish to re-download or re-train:
```bash
# In backend/ directory:

# Download and validate ShieldLM dataset
python scripts/download_dataset.py

# Train & compare binary classifiers
python app/ml/train_binary.py

# Train & compare multi-class classifiers
python app/ml/train_multiclass.py

# Evaluate on held-out test split
python app/ml/evaluate.py
```

### 4. Running the Backend Server
```bash
# Start FastAPI backend (port 8000)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Interactive Swagger documentation is available at: `http://localhost:8000/docs`

### 5. Running the React Frontend Dashboard
```bash
# In a new terminal, navigate to frontend/
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```
Open your browser to: `http://localhost:5173`

---

## Running the Automated Test Suite

ReconMind includes an automated Pytest test suite covering all five defense layers, ML model inference, database fallback operations, and security policy gates:
```bash
# Run pytest from the project root
pytest backend/tests/test_defenses_and_engine.py -v
```

---

## Experimental Benchmark Results

Evaluated on the **ShieldLM Held-out Test Split (8,125 samples)** (see [FINAL_METRICS_CONSISTENCY_AUDIT.md](file:///c:/Users/asus/Documents/ReconMind/FINAL_METRICS_CONSISTENCY_AUDIT.md) for full audited derivation):

| Metric | Task A: Binary Classification | Task B: Multi-Class Classification |
| :--- | :--- | :--- |
| **Accuracy** | **98.04%** | **96.80%** |
| **Malicious Recall** | **96.73%** | 93.41% (Direct), 100.0% (Indirect), 88.24% (Jailbreak) |
| **Precision** | **97.66%** | 97.17% (Direct), 99.37% (Indirect), 58.44% (Jailbreak) |
| **Macro F1** | **0.9785** | **0.9091** |
| **ROC-AUC** | **0.9967** | N/A |
| **Inference Latency** | **0.1409 ms (Batched)** / **0.614 ms (Single)** | **0.218 ms (Batched)** / **4.597 ms (Dual Engine)** |
| **FPR / FNR** | **1.25% / 3.27%** | N/A |

---

## API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/scan/input` | Layer 1: Prompt injection & jailbreak detection |
| `POST` | `/api/v1/scan/memory` | Layer 2: Conversation memory poisoning validation |
| `POST` | `/api/v1/scan/retrieval` | Layer 3: RAG passage & delimiter scan |
| `POST` | `/api/v1/scan/document` | Layer 3: TXT / PDF document upload & chunk scanner |
| `POST` | `/api/v1/scan/tool` | Layer 4: AI agent tool authorization & path traversal check |
| `POST` | `/api/v1/scan/output` | Layer 5: Secret pattern detection & automatic redaction |
| `GET` | `/api/v1/dashboard/stats` | Real-time aggregated guardrail metrics & telemetry |
| `GET` | `/api/v1/logs` | Paginated security event ledger with filtering |
| `GET` | `/api/v1/models/metrics`| Verified test split benchmarks & confusion matrices |
| `GET` | `/api/v1/health` | Service, database, and ML pipeline health check |
| `GET/PUT` | `/api/v1/policies` | Retrieve or adjust defense thresholds and layer toggles |

---

## Academic Project Information

- **Project Title**: ReconMind: ML-Based Multi-Layer AI Security Guardrail Framework
- **Discipline**: B.Tech in Computer Engineering
- **Domain**: Machine Learning, Artificial Intelligence Security, Cybersecurity
- **Documentation**: See [PROJECT_REPORT.md](file:///c:/Users/asus/Documents/ReconMind/PROJECT_REPORT.md) for full academic development specification and analysis.
