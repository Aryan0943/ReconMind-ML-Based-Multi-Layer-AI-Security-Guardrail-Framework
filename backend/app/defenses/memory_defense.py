import time
import uuid
from typing import Any, List, Dict
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.rules import scan_rule_patterns
from app.ml.predict import ml_engine

# Severity ranking used for finding prioritization (higher = more severe)
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}


def _prioritized_findings(findings: List[Finding]) -> List[Finding]:
    """Return findings sorted highest-severity first."""
    return sorted(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)


class MemoryDefense(BaseDefense):
    """
    Layer 2: Memory Defense
    Prevents persistent instruction manipulation, memory poisoning,
    and unauthorized context modifications before storage in session memory.

    BUG FIX (A): ML fail-open removed.
      - Previously: ml_res.get("prediction") == "malicious" would silently evaluate
        to False when prediction == "unavailable", treating unverifiable memory as benign.
      - Now: When available == False, the engine immediately sets is_ml_malicious = True
        and category = "service_unavailable_fail_closed", matching InputDefense behaviour.

    BUG FIX (D-memory): Finding prioritization.
      - Previously findings[0] was used as the representative threat, but it was simply
        whichever finding was appended first (rule order), not the most severe.
      - Now findings are sorted by severity before selecting the representative threat.
    """

    def __init__(self, threshold: float = 0.70):
        super().__init__(layer_name="memory", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        start_time = time.time()
        text = str(content or "").strip()
        findings: List[Finding] = []

        # --- Structural guard: empty memory item is safe ---
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

        # --- Oversized payload guard ---
        if len(text) > 10000:
            findings.append(Finding(
                type="oversized_memory_payload",
                description="Memory entry exceeds maximum length threshold (possible DoS or injection attempt)",
                severity="high"
            ))

        # --- 1. Deterministic rule-based scan ---
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

        # --- 2. ML threat detection ---
        ml_res = ml_engine.predict(text)

        # BUG FIX A: Explicit fail-closed for unavailable ML engine
        if not ml_res.get("available", True):
            findings.append(Finding(
                type="ml_service_unavailable",
                description="ML Threat Detection Engine is unavailable. Enforcing fail-closed policy on memory.",
                severity="critical"
            ))
            is_ml_malicious = True
            ml_conf = 1.0
            ml_cat = "service_unavailable_fail_closed"
        else:
            is_ml_malicious = ml_res.get("prediction") == "malicious"
            ml_conf = ml_res.get("confidence", 0.0)
            ml_cat = ml_res.get("category", "benign")

        if is_ml_malicious and ml_conf >= self.threshold:
            findings.append(Finding(
                type="ml_memory_poisoning_detected",
                description=f"ML detected potential memory payload: {ml_cat} ({ml_conf:.2%})",
                severity="high" if ml_conf >= 0.85 else "medium",
                details=ml_res.get("category_probabilities")
            ))

        # --- 3. Prioritize findings by severity (BUG FIX D-memory) ---
        findings = _prioritized_findings(findings)
        top_finding = findings[0] if findings else None

        # --- 4. Decision logic ---
        has_critical = any(f.severity == "critical" for f in findings)

        if has_critical or (is_ml_malicious and ml_conf >= self.threshold):
            action = "BLOCK"
            prediction = "malicious"
            category = ml_cat if ml_cat not in ("benign", "service_unavailable_fail_closed") else (
                top_finding.type if top_finding else "indirect_injection"
            )
            reason = f"Memory entry rejected: {top_finding.description if top_finding else 'Poisoning risk detected'}"
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
