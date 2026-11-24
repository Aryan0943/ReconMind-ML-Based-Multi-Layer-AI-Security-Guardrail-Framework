# ReconMind — Scope Limitations & Future Research

## Operational Limitations

1. **Deterministic Mock LLM in Demonstration**:
   - The integrated simulation agent (`agent/`) utilizes a deterministic mock reasoning engine to enable reproducible demonstration of multi-layer defense interception without requiring paid third-party API keys.
2. **Taxonomic Lexical Ambiguity**:
   - Direct prompt injections and jailbreak templates exhibit linguistic overlap. In multiclass evaluation, jailbreak classification yields 58.44% precision because direct injections share similar directive phrases. However, because both categories receive a hard `BLOCK` decision, zero security bypasses occur.
3. **Synchronous File Persistence Bottleneck**:
   - In development fallback mode, writing logs to local JSON files requires array serialization (~15 ms). In high-throughput production environments, MongoDB or message queue streaming is recommended.

## Future Scope

1. **Transformer-Based Semantic Embeddings**:
   - Augment TF-IDF feature extraction with distilled cross-encoders (e.g. ModernBERT or DeBERTa-v3) for nuanced context disambiguation.
2. **Adaptive Dynamic Honeytoken Traps**:
   - Inject canary tokens into RAG context buffers to detect context leakage in real time.
3. **Streaming Token Guardrail**:
   - Implement WebSocket token chunking to redact sensitive secrets on streaming LLM responses.
