import uuid
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from app.schemas.responses import SecurityScanResponse, Finding

class BaseDefense(ABC):
    """
    Abstract Base Class for ReconMind Defense Layers.
    Provides standard lifecycle hooks, telemetry, and response packaging.
    """
    def __init__(self, layer_name: str, threshold: float = 0.75):
        self.layer_name = layer_name
        self.threshold = threshold
        self.enabled = True

    def set_threshold(self, threshold: float):
        self.threshold = max(0.0, min(1.0, threshold))

    def set_enabled(self, enabled: bool):
        self.enabled = enabled

    @abstractmethod
    def inspect(self, content: Any, **kwargs) -> SecurityScanResponse:
        """
        Inspects content using layer-specific rules, ML models, and security logic.
        """
        pass

    def build_response(
        self,
        prediction: str,
        category: str,
        confidence: float,
        action: str,
        reason: str,
        findings: List[Finding] = None,
        sanitized_content: Optional[str] = None,
        latency_ms: float = 0.0,
        model_version: str = "1.0.0"
    ) -> SecurityScanResponse:
        return SecurityScanResponse(
            success=True,
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            layer=self.layer_name,
            prediction=prediction,
            category=category,
            confidence=round(confidence, 4),
            action=action,
            reason=reason,
            findings=findings or [],
            sanitized_content=sanitized_content,
            latency_ms=round(latency_ms, 2),
            model_version=model_version
        )
