import requests
import json
import logging
from typing import Optional, Dict, Any, List
from reconmind.models import ScanResult, FindingItem
from reconmind.exceptions import ConnectionError, AuthenticationError, SecurityPolicyViolation

logger = logging.getLogger("reconmind.sdk")

class ReconMindClient:
    """
    Python SDK Client for ReconMind AI Security Guardrail Framework.
    Allows external applications and AI agent workflows to inspect prompts,
    quarantine memory poisoning, scan RAG passages, authorize tools,
    and sanitize output secrets with minimal lines of code.
    """
    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 5.0,
        raise_on_block: bool = False
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key or "development-key"
        self.timeout = timeout
        self.raise_on_block = raise_on_block
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type": "application/json",
            "X-API-Key": self.api_key,
            "User-Agent": "ReconMind-Python-SDK/1.0.0"
        })

    def _post(self, endpoint: str, payload: Dict[str, Any]) -> ScanResult:
        url = f"{self.base_url}{endpoint}"
        try:
            resp = self._session.post(url, json=payload, timeout=self.timeout)
            if resp.status_code == 401:
                raise AuthenticationError("Invalid or missing ReconMind API key.")
            resp.raise_for_status()
            data = resp.json()
            
            findings = [
                FindingItem(
                    type=f.get("type", "unknown"),
                    description=f.get("description", ""),
                    severity=f.get("severity", "medium"),
                    details=f.get("details")
                )
                for f in data.get("findings", [])
            ]

            result = ScanResult(
                event_id=data.get("event_id", ""),
                timestamp=data.get("timestamp", ""),
                layer=data.get("layer", ""),
                prediction=data.get("prediction", "benign"),
                category=data.get("category", "benign"),
                confidence=float(data.get("confidence", 0.0)),
                action=data.get("action", "PASS"),
                reason=data.get("reason", ""),
                findings=findings,
                sanitized_content=data.get("sanitized_content"),
                latency_ms=float(data.get("latency_ms", 0.0))
            )

            if self.raise_on_block and result.is_blocked:
                raise SecurityPolicyViolation(f"ReconMind Guardrail Blocked Request: {result.reason}", scan_result=result)

            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to communicate with ReconMind Guardrail at {url}: {e}")
            raise ConnectionError(f"ReconMind server unreachable: {e}")

    def scan_input(self, prompt: str) -> ScanResult:
        """Inspects user prompt for direct prompt injections, DAN jailbreaks, and system extractions."""
        return self._post("/api/v1/scan/input", {"text": prompt})

    def scan_memory(self, memory_content: str, session_id: Optional[str] = None) -> ScanResult:
        """Validates persistent memory updates against session poisoning and context overrides."""
        return self._post("/api/v1/scan/memory", {"content": memory_content, "session_id": session_id})

    def scan_retrieval(self, document_passage: str) -> ScanResult:
        """Scans external RAG document chunks for indirect prompt injections and delimiter attacks."""
        return self._post("/api/v1/scan/retrieval", {"content": document_passage})

    def authorize_tool(
        self,
        tool_name: str,
        user_role: str = "standard_user",
        parameters: Optional[Dict[str, Any]] = None
    ) -> ScanResult:
        """Evaluates tool invocation against role permissions and detects path traversal attacks."""
        return self._post("/api/v1/scan/tool", {
            "tool_name": tool_name,
            "user_role": user_role,
            "parameters": parameters or {}
        })

    def scan_output(self, model_response: str, redact: bool = True) -> ScanResult:
        """Inspects LLM output responses and automatically redacts API keys, AWS tokens, and PII."""
        return self._post("/api/v1/scan/output", {"text": model_response, "redact": redact})
