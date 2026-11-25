from typing import Dict, Any, Tuple, List
from app.schemas.responses import SecurityScanResponse, Finding

# Finding types that are ALWAYS mandatory — they cannot be bypassed by any policy toggle.
MANDATORY_BLOCK_TYPES = frozenset([
    # Fail-closed ML availability sentinel — must always block
    "ml_service_unavailable",
])

# Finding types that are mandatory-block ONLY on the tool layer
MANDATORY_TOOL_TYPES = frozenset([
    "unauthorized_tool",
    "insufficient_permissions",
    "path_traversal",
    "unsafe_expression",
    "expression_too_long",
])


class PolicyEngine:
    """
    Enforces centralized governance policies across all five defense layers.
    Determines final PASS / SANITIZE / BLOCK / QUARANTINE actions based on findings,
    layer-specific risk policies, and confidence thresholds.

    BUG FIX (B): Policy check order corrected.
      - Previously the disabled-layer early-return came BEFORE the mandatory-
        security-control check, meaning disabling any layer could bypass critical findings.
      - Now:
          Step 1  — Universal mandatory check (ml_service_unavailable)
          Step 2  — Tool-layer mandatory check (RBAC, path traversal)
          Step 3  — Critical-severity catch-all (blocks even on disabled layers)
          Step 4  — Layer-disabled early return (only if no mandatory/critical violations)
          Step 5  — Normal policy evaluation
      This guarantees: configuration toggles can NEVER bypass mandatory security controls.
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

        # ----------------------------------------------------------------
        # Step 1: Universal mandatory check — findings that are ALWAYS
        # blocked regardless of layer, policy, or enabled state.
        # ----------------------------------------------------------------
        for f in findings:
            if f.type in MANDATORY_BLOCK_TYPES:
                return "BLOCK", f"Mandatory security violation: {f.description}"

        # ----------------------------------------------------------------
        # Step 2: Tool-layer mandatory authorization check.
        # Must run BEFORE the disabled-layer check.
        # ----------------------------------------------------------------
        if layer == "tool":
            for f in findings:
                if f.type in MANDATORY_TOOL_TYPES:
                    return "BLOCK", f"Mandatory tool security violation: {f.description}"

        # ----------------------------------------------------------------
        # Step 3: Critical-severity catch-all.
        # Critical findings always block even if the layer is disabled.
        # ----------------------------------------------------------------
        has_critical = any(f.severity == "critical" for f in findings)
        if has_critical:
            top = next(f for f in findings if f.severity == "critical")
            return "BLOCK", f"Critical security policy violation: {top.description}"

        # ----------------------------------------------------------------
        # Step 4: Layer-disabled early return.
        # Reached only when no mandatory/critical violations were found.
        # ----------------------------------------------------------------
        if not policy.get("enabled", True):
            return "PASS", f"Layer '{layer}' is administratively bypassed by policy"

        # ----------------------------------------------------------------
        # Step 5a: Tool layer — authorized calls pass directly.
        # (Unauthorized calls were already blocked in Step 2.)
        # ----------------------------------------------------------------
        if layer == "tool":
            return action, reason

        # ----------------------------------------------------------------
        # Step 5b: Output defense — honour the layer's own SANITIZE/BLOCK.
        # ----------------------------------------------------------------
        if layer == "output":
            if action in ["SANITIZE", "BLOCK"]:
                return action, reason
            return "PASS", reason

        # ----------------------------------------------------------------
        # Step 5c: Probabilistic / borderline threats for input, memory, retrieval.
        # ----------------------------------------------------------------
        threshold = policy.get("threshold", 0.75)
        if scan_response.prediction == "malicious":
            if confidence >= threshold:
                return "BLOCK", reason
            else:
                default_act = policy.get("default_action", "BLOCK")
                if default_act == "BLOCK":
                    return "BLOCK", (
                        f"Security policy blocked request: Risk score ({confidence:.2f}) "
                        f"evaluated under layer policy (threshold: {threshold:.2f})"
                    )
                elif default_act == "SANITIZE":
                    if layer == "output" or scan_response.sanitized_content is not None:
                        return "SANITIZE", (
                            f"Content sanitized: Risk score ({confidence:.2f}) required sanitization/redaction"
                        )
                    else:
                        return "SANITIZE", (
                            f"Quarantine action applied: Content held for review under policy "
                            f"default ({confidence:.2f} < {threshold:.2f})"
                        )
                else:
                    return default_act, reason

        return action, reason
