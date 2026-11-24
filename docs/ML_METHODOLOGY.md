# ReconMind Machine Learning Methodology

## Classification Taxonomy

ReconMind employs a two-tier classification architecture:

1. **Task A: Binary Attack Detection**
   - Classes: `benign` (0) vs `malicious` (1)
   - Primary Gate: Evaluated first on incoming prompts
   - Decision Rule: Probability $\ge 0.75 \implies \text{BLOCK}$

2. **Task B: Multiclass Threat Attribution**
   - Classes: `benign`, `direct_injection`, `indirect_injection`, `jailbreak`
   - Role: Forensic telemetry and granular threat attribution

## Model Pipeline

- **Feature Extraction**: Character n-grams (3-5) and Word n-grams (1-3) using Sublinear TF-IDF scaling ($50,000$ max features).
- **Classifier**: Logistic Regression with $L_2$ regularization, balanced class weights, and liblinear solver.
- **Inference Efficiency**: In-memory matrix computation executes in under $0.08\text{ ms}$ per sample.
