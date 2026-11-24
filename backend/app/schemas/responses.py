from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class Finding(BaseModel):
    type: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    details: Optional[Dict[str, Any]] = None

class SecurityScanResponse(BaseModel):
    success: bool = True
    event_id: str
    timestamp: str
    layer: str
    prediction: str  # "benign" | "malicious"
    category: str    # "benign" | "direct_injection" | "indirect_injection" | "jailbreak" | "tool_violation" | "sensitive_leak"
    confidence: float
    action: str      # "PASS" | "SANITIZE" | "BLOCK"
    reason: str
    findings: List[Finding] = Field(default_factory=list)
    sanitized_content: Optional[str] = None
    latency_ms: float = 0.0
    model_version: Optional[str] = "1.0.0"

class DocumentChunkFinding(BaseModel):
    chunk_index: int
    content_snippet: str
    prediction: str
    category: str
    confidence: float
    action: str
    reason: str

class DocumentScanResponse(BaseModel):
    success: bool = True
    event_id: str
    timestamp: str
    filename: str
    total_chunks: int
    suspicious_chunks: int
    detected_categories: List[str]
    overall_action: str  # "PASS" | "BLOCK" | "QUARANTINE"
    reason: str
    chunk_findings: List[DocumentChunkFinding] = Field(default_factory=list)
    latency_ms: float = 0.0

class MemoryEntryResponse(BaseModel):
    memory_id: str
    session_id: str
    content: str
    status: str      # "approved" | "rejected" | "quarantined"
    scan_result: SecurityScanResponse
    created_at: str

class DashboardStats(BaseModel):
    total_scanned: int
    threats_detected: int
    requests_blocked: int
    requests_sanitized: int
    requests_passed: int
    layer_activity: Dict[str, int]
    threat_distribution: Dict[str, int]
    action_distribution: Dict[str, int]
    avg_latency_ms: float
