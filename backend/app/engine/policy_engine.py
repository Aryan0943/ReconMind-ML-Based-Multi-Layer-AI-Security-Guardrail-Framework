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
        action = scan_response.action
        reason = scan_response.reason
        findings = scan_response.findings
        confidence = scan_response.confidence

        # Rule 0: Mandatory Security Control Invariance
        # Configuration toggles must never bypass mandatory security controls (Tool RBAC / Path Traversal)
        if layer == "tool":
            if any(f.type in ["unauthorized_tool", "insufficient_permissions", "path_traversal", "unsafe_expression"] for f in findings):
                return "BLOCK", f"Tool access violation: {findings[0].description}"

        # If non-mandatory layer is disabled by admin policy, allow pass-through with explicit audit warning
        if not policy.get("enabled", True):
            return "PASS", f"Layer '{layer}' is administratively bypassed by policy"

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

        # Rule 4: Borderline and probabilistic threats across layers
        threshold = policy.get("threshold", 0.75)
        if scan_response.prediction == "malicious":
            if confidence >= threshold:
                return "BLOCK", reason
            else:
                default_act = policy.get("default_action", "BLOCK")
                # Ensure reason cleanly matches the final action taken
                if default_act == "BLOCK":
                    return "BLOCK", f"Security policy blocked request: Risk score ({confidence:.2f}) evaluated under layer policy (threshold: {threshold:.2f})"
                elif default_act == "SANITIZE":
                    # Only report sanitization if content can actually be sanitized/quarantined
                    if layer == "output" or scan_response.sanitized_content is not None:
                        return "SANITIZE", f"Content sanitized: Risk score ({confidence:.2f}) required sanitization/redaction"
                    else:
                        return "SANITIZE", f"Quarantine action applied: Content held for review under policy default ({confidence:.2f} < {threshold:.2f})"
                else:
                    return default_act, reason

        return action, reason
