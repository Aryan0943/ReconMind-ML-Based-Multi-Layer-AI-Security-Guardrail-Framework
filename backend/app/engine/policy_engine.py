from typing import Dict, Any, Tuple
from app.schemas.responses import SecurityScanResponse

class PolicyEngine:
    """
    Enforces centralized governance policies across all five defense layers.
    Determines final PASS / SANITIZE / BLOCK actions based on findings,
    layer-specific risk policies, and confidence thresholds.
    """
    def __init__(self):
        pass

    def evaluate_decision(
        self,
        layer: str,
        scan_response: SecurityScanResponse,
        policy: Dict[str, Any]
    ) -> Tuple[str, str]:
        """
        Evaluates the scan response against active policy.
        Returns: (final_action, final_reason)
        """
        # If layer is disabled by admin policy, allow pass-through with explicit audit warning
        if not policy.get("enabled", True):
            return "PASS", f"Layer '{layer}' is administratively bypassed by policy"

        action = scan_response.action
        reason = scan_response.reason
        findings = scan_response.findings
        confidence = scan_response.confidence

        # Rule 1: Tool authorization violations are always strictly blocked
        if layer == "tool":
            if any(f.type in ["unauthorized_tool", "insufficient_permissions", "path_traversal", "unsafe_expression"] for f in findings):
                return "BLOCK", f"Tool access violation: {findings[0].description}"
            return action, reason

        # Rule 2: Critical security findings always override any other condition
        has_critical = any(f.severity == "critical" for f in findings)
        if has_critical:
            return "BLOCK", f"Critical security policy violation: {findings[0].description}"

        # Rule 3: Output defense sanitization
        if layer == "output":
            if action in ["SANITIZE", "BLOCK"]:
                return action, reason
            return "PASS", reason

        # Rule 4: Retrieval and memory defense quarantine/sanitization
        threshold = policy.get("threshold", 0.75)
        if scan_response.prediction == "malicious":
            if confidence >= threshold:
                return "BLOCK", reason
            else:
                # Borderline threat
                default_act = policy.get("default_action", "SANITIZE")
                return default_act, f"Threshold alert ({confidence:.2f} < {threshold:.2f}); {reason}"

        return action, reason
