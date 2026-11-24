from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

@dataclass
class FindingItem:
    type: str
    description: str
    severity: str
    details: Optional[Dict[str, Any]] = None

@dataclass
class ScanResult:
    event_id: str
    timestamp: str
    layer: str
    prediction: str  # "malicious" or "benign"
    category: str
    confidence: float
    action: str      # "PASS", "SANITIZE", "BLOCK"
    reason: str
    findings: List[FindingItem] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    latency_ms: float = 0.0

    @property
    def is_blocked(self) -> bool:
        return self.action == "BLOCK"

    @property
    def is_sanitized(self) -> bool:
        return self.action == "SANITIZE"

    @property
    def is_allowed(self) -> bool:
        return self.action in ["PASS", "SANITIZE"]
