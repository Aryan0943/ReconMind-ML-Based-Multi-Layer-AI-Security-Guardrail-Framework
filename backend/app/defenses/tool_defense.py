import time
from typing import Any, Dict, List
from app.defenses.base_defense import BaseDefense
from app.schemas.responses import SecurityScanResponse, Finding
from app.security.permissions import validate_tool_request

class ToolDefense(BaseDefense):
    """
    Layer 4: Tool Defense
    Prevents unauthorized tool calls, privilege escalation, parameter tampering,
    and path traversal. Uses strict permission validation and sandboxed mock tools.
    """
    def __init__(self, threshold: float = 0.50):
        super().__init__(layer_name="tool", threshold=threshold)

    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        """
        Expects content to be a dictionary with tool_name, user_role, parameters.
        Or accepts kwargs.
        """
        start_time = time.time()
        findings: List[Finding] = []

        if isinstance(content, dict):
            tool_name = content.get("tool_name", "")
            user_role = content.get("user_role", kwargs.get("user_role", "standard_user"))
            parameters = content.get("parameters", {})
        else:
            tool_name = str(content)
            user_role = kwargs.get("user_role", "standard_user")
            parameters = kwargs.get("parameters", {})

        # Validate with strict security permissions
        is_authorized, reason, raw_findings, exec_result = validate_tool_request(
            tool_name=tool_name,
            user_role=user_role,
            parameters=parameters
        )

        for rf in raw_findings:
            findings.append(Finding(
                type=rf["type"],
                description=rf["description"],
                severity=rf["severity"],
                details=rf.get("details")
            ))

        if not is_authorized:
            action = "BLOCK"
            prediction = "malicious"
            category = "tool_violation"
            confidence = 1.0
            sanitized_content = None
        else:
            action = "PASS"
            prediction = "benign"
            category = "benign"
            confidence = 1.0
            sanitized_content = str(exec_result)

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
