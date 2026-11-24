import time
import uuid
from typing import Any, List, Dict
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.rules import scan_rule_patterns
from app.ml.predict import ml_engine

class MemoryDefense(BaseDefense):
    """
    Layer 2: Memory Defense
    Prevents persistent instruction manipulation, memory poisoning,
    and unauthorized context modifications before storage in session memory.
    """
    def __init__(self, threshold: float = 0.70):
        super().__init__(layer_name="memory", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        start_time = time.time()
        text = str(content or "").strip()
        findings: List[Finding] = []

        if not text:
            latency = (time.time() - start_time) * 1000.0
            return self.build_response(
                prediction="benign",
                category="benign",
                confidence=1.0,
                action="PASS",
                reason="Empty memory item",
                latency_ms=latency
            )

        # 1. Check memory-specific poisoning directives
        has_rule, rule_findings = scan_rule_patterns(text)
        for rf in rule_findings:
            if "memory" in rf["type"] or "override" in rf["type"] or "jailbreak" in rf["type"]:
                findings.append(Finding(
                    type=f"memory_violation_{rf['type']}",
                    description=f"Persistent memory attack pattern: {rf['description']}",
                    severity="critical"
                ))
            else:
                findings.append(Finding(
                    type=rf["type"],
                    description=rf["description"],
                    severity=rf["severity"]
                ))

        # 2. ML threat detection on memory content
        ml_res = ml_engine.predict(text)
        is_ml_malicious = ml_res.get("prediction") == "malicious"
        ml_conf = ml_res.get("confidence", 0.0)
        ml_cat = ml_res.get("category", "benign")

        if is_ml_malicious and ml_conf >= self.threshold:
            findings.append(Finding(
                type="ml_memory_poisoning_detected",
                description=f"ML detected potential memory payload: {ml_cat} ({ml_conf:.2%})",
                severity="high"
            ))

        # 3. Decision Logic
        has_critical = any(f.severity == "critical" for f in findings)
        
        if has_critical or (is_ml_malicious and ml_conf >= self.threshold):
            action = "BLOCK"
            prediction = "malicious"
            category = ml_cat if ml_cat != "benign" else "indirect_injection"
            reason = f"Memory entry rejected: {findings[0].description if findings else 'Poisoning risk detected'}"
            confidence = max(ml_conf, 0.92)
        elif is_ml_malicious or len(findings) > 0:
            action = "SANITIZE"
            prediction = "malicious"
            category = ml_cat if ml_cat != "benign" else "indirect_injection"
            reason = "Memory entry quarantined for administrative review"
            confidence = ml_conf
        else:
            action = "PASS"
            prediction = "benign"
            category = "benign"
            reason = "Memory entry validated and approved for storage"
            confidence = ml_res.get("confidence", 1.0) if not is_ml_malicious else (1.0 - ml_conf)

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
