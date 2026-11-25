import time
import re
from typing import Any, List, Dict
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding, DocumentChunkFinding, DocumentScanResponse
from app.security.rules import scan_rule_patterns
from app.ml.predict import ml_engine

class RetrievalDefense(BaseDefense):
    """
    Layer 3: Retrieval Defense
    Detects malicious instructions, indirect prompt injections, and delimiter attacks
    embedded within external documents (TXT/PDF) and RAG retrieval chunks.
    """
    def __init__(self, threshold: float = 0.65):
        super().__init__(layer_name="retrieval", threshold=threshold)

    def _chunk_text(self, text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
        # Validate chunking parameters to strictly prevent DoS infinite loops
        chunk_size = max(10, min(10000, int(chunk_size)))
        # Guard: overlap must be strictly less than chunk_size
        if overlap >= chunk_size:
            overlap = max(0, chunk_size // 2)
        else:
            overlap = max(0, int(overlap))

        words = text.split()
        if len(words) <= chunk_size:
            return [text]
            
        chunks = []
        i = 0
        step = max(1, chunk_size - overlap)
        while i < len(words):
            chunk = " ".join(words[i : i + chunk_size])
            chunks.append(chunk)
            i += step
        return chunks

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        """
        Inspects text or document passage.
        """
        start_time = time.time()
        text = str(content or "").strip()
        chunk_size = kwargs.get("chunk_size", 500)
        chunk_overlap = kwargs.get("chunk_overlap", 50)

        chunks = self._chunk_text(text, chunk_size=chunk_size, overlap=chunk_overlap)
        findings: List[Finding] = []
        suspicious_chunks = 0
        detected_categories = set()
        max_confidence = 0.0

        for idx, chunk in enumerate(chunks):
            # Check rules on chunk
            has_rule, rule_findings = scan_rule_patterns(chunk)
            # ML on chunk
            ml_res = ml_engine.predict(chunk)
            is_mal = ml_res.get("prediction") == "malicious"
            conf = ml_res.get("confidence", 0.0)
            cat = ml_res.get("category", "benign")

            if has_rule or (is_mal and conf >= self.threshold):
                suspicious_chunks += 1
                if cat != "benign":
                    detected_categories.add(cat)
                else:
                    detected_categories.add("indirect_injection")
                max_confidence = max(max_confidence, conf)
                
                findings.append(Finding(
                    type=f"suspicious_chunk_{idx}",
                    description=f"Malicious pattern in chunk #{idx}: {rule_findings[0]['description'] if has_rule else f'ML detected {cat}'}",
                    severity="high" if conf > 0.8 else "medium",
                    details={"chunk_index": idx, "snippet": chunk[:120]}
                ))

        # Overall action for document passage
        if suspicious_chunks > 0:
            if suspicious_chunks >= 2 or max_confidence >= 0.85:
                action = "BLOCK"
                reason = f"Document contains {suspicious_chunks} dangerous injection payload(s)"
            else:
                action = "SANITIZE"
                reason = f"Document contains {suspicious_chunks} suspicious chunk(s); quarantined"
            prediction = "malicious"
            category = list(detected_categories)[0] if detected_categories else "indirect_injection"
            confidence = max(max_confidence, 0.85)
        else:
            action = "PASS"
            prediction = "benign"
            category = "benign"
            confidence = 0.95
            reason = f"All {len(chunks)} chunks passed retrieval safety inspection"

        latency = (time.time() - start_time) * 1000.0
        return self.build_response(
            prediction=prediction,
            category=category,
            confidence=confidence,
            action=action,
            reason=reason,
            findings=findings,
            latency_ms=latency
        )

    def scan_full_document(self, filename: str, full_text: str) -> DocumentScanResponse:
        """
        Comprehensive document scanner for uploaded files.
        """
        start_time = time.time()
        chunks = self._chunk_text(full_text, chunk_size=500, overlap=50)
        chunk_findings: List[DocumentChunkFinding] = []
        suspicious_count = 0
        detected_categories = set()

        for idx, chunk in enumerate(chunks):
            has_rule, rule_findings = scan_rule_patterns(chunk)
            ml_res = ml_engine.predict(chunk)
            is_mal = ml_res.get("prediction") == "malicious"
            conf = ml_res.get("confidence", 0.0)
            cat = ml_res.get("category", "benign")

            if has_rule or (is_mal and conf >= self.threshold):
                suspicious_count += 1
                c_action = "BLOCK" if conf >= 0.80 or has_rule else "SANITIZE"
                c_pred = "malicious"
                c_cat = cat if cat != "benign" else "indirect_injection"
                detected_categories.add(c_cat)
                reason = rule_findings[0]["description"] if has_rule else f"ML threat: {cat}"
            else:
                c_action = "PASS"
                c_pred = "benign"
                c_cat = "benign"
                reason = "Chunk is safe"

            if c_pred == "malicious":
                chunk_findings.append(DocumentChunkFinding(
                    chunk_index=idx,
                    content_snippet=chunk[:150] + ("..." if len(chunk) > 150 else ""),
                    prediction=c_pred,
                    category=c_cat,
                    confidence=round(conf, 4),
                    action=c_action,
                    reason=reason
                ))

        if suspicious_count > 0:
            overall_action = "BLOCK" if suspicious_count >= 2 else "QUARANTINE"
            reason = f"Identified {suspicious_count} potentially hazardous chunk(s) in document"
        else:
            overall_action = "PASS"
            reason = "Document cleared all security checks. Safe for retrieval indexing."

        import uuid
        from datetime import datetime, timezone
        latency = (time.time() - start_time) * 1000.0

        return DocumentScanResponse(
            success=True,
            event_id=f"doc_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            filename=filename,
            total_chunks=len(chunks),
            suspicious_chunks=suspicious_count,
            detected_categories=list(detected_categories),
            overall_action=overall_action,
            reason=reason,
            chunk_findings=chunk_findings,
            latency_ms=round(latency, 2)
        )
