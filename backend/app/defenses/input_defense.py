import time
from typing import Any, List
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.rules import scan_rule_patterns
from app.ml.predict import ml_engine

class InputDefense(BaseDefense):
    """
    Layer 1: Input Defense (ML-enabled)
    Detects malicious instructions, direct injection, jailbreaks, and system extractions
    in user prompts.
    """
    def __init__(self, threshold: float = 0.75):
        super().__init__(layer_name="input", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        start_time = time.time()
        text = str(content or "").strip()
        
        findings: List[Finding] = []
        
        # 1. Structural and length checks
        if not text:
            latency = (time.time() - start_time) * 1000.0
            return self.build_response(
                prediction="benign",
                category="benign",
                confidence=1.0,
                action="PASS",
                reason="Empty input passed safely",
                latency_ms=latency
            )
            
        if len(text) > 10000:
            findings.append(Finding(
                type="oversized_payload",
                description="Prompt exceeds maximum length threshold (possible buffer/DoS attack)",
                severity="high"
            ))

        # 2. Heuristic Pattern / Rule-based check
        has_rule_violation, rule_findings = scan_rule_patterns(text)
        for rf in rule_findings:
            findings.append(Finding(
                type=rf["type"],
                description=rf["description"],
                severity=rf["severity"],
                details=rf.get("details")
            ))

        # 3. Machine Learning Detection
        ml_res = ml_engine.predict(text)
        is_ml_malicious = ml_res.get("prediction") == "malicious"
        ml_confidence = ml_res.get("confidence", 0.0)
        ml_category = ml_res.get("category", "benign")

        if is_ml_malicious and ml_confidence >= self.threshold:
            findings.append(Finding(
                type="ml_threat_detected",
                description=f"ML classifier detected {ml_category} with {ml_confidence:.2%} confidence",
                severity="high" if ml_confidence >= 0.85 else "medium",
                details=ml_res.get("category_probabilities")
            ))

        # 4. Security Action Determination
        # High-risk deterministic rules override benign ML predictions
        critical_rule = any(f.severity == "critical" for f in findings)
        high_rule = any(f.severity == "high" for f in findings)
        
        if critical_rule or (is_ml_malicious and ml_confidence >= self.threshold) or (high_rule and is_ml_malicious):
            action = "BLOCK"
            prediction = "malicious"
            category = ml_category if ml_category != "benign" else "direct_injection"
            reason = f"Security threat blocked: {findings[0].description if findings else 'Policy violation'}"
            confidence = max(ml_confidence, 0.95 if critical_rule else 0.85)
        elif high_rule or (is_ml_malicious and ml_confidence >= (self.threshold - 0.15)):
            # Borderline or medium severity rule
            action = "SANITIZE"
            prediction = "malicious"
            category = ml_category if ml_category != "benign" else "direct_injection"
            reason = "Suspicious prompt detected; sanitized execution required"
            confidence = ml_confidence
        else:
            action = "PASS"
            prediction = "benign"
            category = "benign"
            reason = "Input cleared all security and ML validation checks"
            confidence = ml_res.get("confidence", 1.0) if not is_ml_malicious else (1.0 - ml_confidence)

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
