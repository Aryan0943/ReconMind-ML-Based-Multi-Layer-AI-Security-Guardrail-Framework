import time
from typing import Any, List
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.rules import scan_rule_patterns
from app.ml.predict import ml_engine

# Severity ranking used for finding prioritization (higher = more severe)
_SEVERITY_RANK = {"critical": 3, "high": 2, "medium": 1, "low": 0}

# Threat types that map directly to a canonical category name
_RULE_CATEGORY_MAP = {
    "privilege_escalation": "privilege_escalation",
    "instruction_override": "instruction_override",
    "jailbreak_attempt": "jailbreak_attempt",
    "system_extraction": "system_extraction",
    "memory_poisoning": "memory_poisoning",
    "indirect_delimiter": "indirect_injection",
    "ml_service_unavailable": "service_unavailable_fail_closed",
}


def _prioritized_findings(findings: List[Finding]) -> List[Finding]:
    """Return findings sorted highest-severity first, then by canonical threat priority."""
    _THREAT_PRIORITY = {
        "jailbreak_attempt": 10,
        "instruction_override": 9,
        "privilege_escalation": 8,
        "memory_poisoning": 7,
        "system_extraction": 6,
        "indirect_delimiter": 5,
        "ml_service_unavailable": 4,
        "ml_threat_detected": 3,
        "oversized_payload": 2,
    }

    def sort_key(f: Finding):
        severity_score = _SEVERITY_RANK.get(f.severity, 0) * 100
        threat_score = _THREAT_PRIORITY.get(f.type, 0)
        return severity_score + threat_score

    return sorted(findings, key=sort_key, reverse=True)


def _derive_category(findings: List[Finding], ml_category: str) -> str:
    """
    Derive the best threat category from prioritized findings + ML output.

    BUG FIX (D): Previously findings[0].type was used directly as the category,
    even though the first finding appended was just the first regex match, not
    necessarily the most severe or representative threat.  Now:
      1. Use the highest-priority finding whose type maps to a known category.
      2. Fall back to ml_category if the ML engine is available and not benign.
      3. Fall back to "direct_injection" as a safe default.
    """
    for f in findings:
        # Strip prefixes added by memory defense (e.g. "memory_violation_jailbreak_attempt")
        raw_type = f.type.split("memory_violation_")[-1]
        if raw_type in _RULE_CATEGORY_MAP:
            return _RULE_CATEGORY_MAP[raw_type]

    if ml_category and ml_category not in ("benign", "unavailable", "error",
                                            "service_unavailable_fail_closed"):
        return ml_category

    return "direct_injection"


class InputDefense(BaseDefense):
    """
    Layer 1: Input Defense (ML-enabled)
    Detects malicious instructions, direct injection, jailbreaks, and system extractions
    in user prompts.

    BUG FIX (D): Finding prioritization.
      - Previously: rule_threat_type = findings[0].type selected the first-appended
        finding (rule-order dependent), which could be a low-severity or irrelevant
        finding rather than the principal threat.
      - Now: findings are sorted by (severity × 100 + threat_priority) before any
        representative threat type or category is derived.
      - The representative category is determined via _derive_category() which walks
        the prioritized list and falls back cleanly to ML output or a safe default.
    """

    def __init__(self, threshold: float = 0.75):
        super().__init__(layer_name="input", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        start_time = time.time()
        text = str(content or "").strip()

        findings: List[Finding] = []

        # --- 1. Structural checks ---
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

        # --- 2. Deterministic heuristic / rule-based scan ---
        has_rule_violation, rule_findings = scan_rule_patterns(text)
        for rf in rule_findings:
            findings.append(Finding(
                type=rf["type"],
                description=rf["description"],
                severity=rf["severity"],
                details=rf.get("details")
            ))

        # --- 3. Machine Learning Detection ---
        ml_res = ml_engine.predict(text)
        if not ml_res.get("available", True):
            # Fail closed: If ML engine is unavailable, do NOT fail-open
            findings.append(Finding(
                type="ml_service_unavailable",
                description="ML Threat Detection Engine is unavailable. Enforcing fail-closed policy.",
                severity="critical"
            ))
            is_ml_malicious = True
            ml_confidence = 1.0
            ml_category = "service_unavailable_fail_closed"
        else:
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

        # --- 4. Prioritize findings (BUG FIX D) ---
        findings = _prioritized_findings(findings)

        # --- 5. Security Action Determination ---
        critical_rule = any(f.severity == "critical" for f in findings)
        high_rule = any(f.severity == "high" for f in findings)

        if critical_rule or (is_ml_malicious and ml_confidence >= self.threshold) or (high_rule and is_ml_malicious):
            action = "BLOCK"
            prediction = "malicious"
            category = _derive_category(findings, ml_category)
            top_desc = findings[0].description if findings else "Policy violation"
            reason = f"Security threat blocked: {top_desc}"
            confidence = max(ml_confidence, 0.95 if critical_rule else 0.85)
        elif high_rule or (is_ml_malicious and ml_confidence >= (self.threshold - 0.15)):
            # Borderline or medium-severity finding
            action = "SANITIZE"
            prediction = "malicious"
            category = _derive_category(findings, ml_category)
            reason = "Suspicious prompt detected; sanitization required before processing"
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
