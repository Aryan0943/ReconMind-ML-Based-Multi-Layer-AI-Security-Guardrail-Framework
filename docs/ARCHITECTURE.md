# ReconMind System Architecture

## Architectural Overview

ReconMind decouples defensive inspection into five distinct layers coordinated by a centralized PolicyEngine and DefenseManager:

```mermaid
graph TD
    User([User / External AI Workflow]) --> Gateway[FastAPI REST Gateway]
    Gateway --> DM[DefenseManager Singleton]
    
    subgraph MultiLayerDefenses [ReconMind Five Defense Layers]
        L1[Layer 1: Input Defense - ML + Heuristics]
        L2[Layer 2: Memory Defense - Context Quarantining]
        L3[Layer 3: Retrieval Defense - RAG Chunk Scanner]
        L4[Layer 4: Tool Defense - RBAC & Path Validation]
        L5[Layer 5: Output Defense - Credential Redaction]
    end

    DM --> L1
    DM --> L2
    DM --> L3
    DM --> L4
    DM --> L5

    subgraph Governance [Policy & Classification Engine]
        PE[PolicyEngine]
        ML[TF-IDF + Logistic Regression Pipelines]
    end

    L1 <--> ML
    L2 <--> ML
    L3 <--> ML
    DM <--> PE

    subgraph Storage [Persistence Layer]
        DB[(MongoDB Daemon)]
        FB[(JSON Fallback Store)]
    end

    DM --> DB
    DM --> FB
```

## Defensive Decision Flow

Each defense layer evaluates its respective payload and emits a verdict:
- **`PASS`**: Payload satisfies all heuristic and machine learning safety bounds.
- **`SANITIZE`**: Mild anomalies or sensitive tokens detected; dangerous parts are redacted or quarantined.
- **`BLOCK`**: High-confidence adversarial injection, privilege violation, or path traversal detected.
