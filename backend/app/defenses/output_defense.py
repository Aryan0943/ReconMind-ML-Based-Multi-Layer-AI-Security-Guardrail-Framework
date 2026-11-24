import time
from typing import Any, List
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.sensitive_data import scan_and_redact_sensitive_data

class OutputDefense(BaseDefense):
    """
    Layer 5: Output Defense
    Scans generated model responses for credential leakage, private keys,
    API keys, PII, email addresses, and configured secrets.
    Applies deterministic redaction or blocking.
    """
    def __init__(self, threshold: float = 0.50):
        super().__init__(layer_name="output", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        start_time = time.time()
        text = str(content or "").strip()
        redact = kwargs.get("redact", True)
        findings: List[Finding] = []

        if not text:
            latency = (time.time() - start_time) * 1000.0
            return self.build_response(
                prediction="benign",
                category="benign",
                confidence=1.0,
                action="PASS",
                reason="Empty output text",
                latency_ms=latency
            )

        has_leak, sanitized_text, raw_findings = scan_and_redact_sensitive_data(text, redact=redact)

        for rf in raw_findings:
            findings.append(Finding(
                type=rf["type"],
                description=rf["description"],
                severity=rf["severity"],
                details=rf.get("details")
            ))

        if has_leak:
            prediction = "malicious"
            category = "sensitive_leak"
            confidence = 1.0
            
            # Critical leaks like private keys can be blocked, while redactable keys are sanitized
            has_private_key = any("private_key" in f.type for f in findings)
            if has_private_key:
                action = "BLOCK"
                reason = "Severe secret leakage detected (Private Key). Output completely blocked."
                sanitized_content = None
            else:
                action = "SANITIZE"
                reason = f"Detected {len(findings)} sensitive pattern(s). Sensitive values safely redacted."
                sanitized_content = sanitized_text
        else:
            action = "PASS"
            prediction = "benign"
            category = "benign"
            confidence = 1.0
            reason = "No sensitive data leakage detected in output."
            sanitized_content = text

        latency = (time.time() - start_time) * 1000.0
        return self.build_response(
            prediction=prediction,
            category=category,
            confidence=confidence,
            action=action,
            reason=reason,
            findings=findings,
            sanitized_content=sanitized_content,
            latency_ms=latency
        )
