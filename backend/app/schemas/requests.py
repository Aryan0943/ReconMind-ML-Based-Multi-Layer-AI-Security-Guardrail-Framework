from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field, model_validator

class InputScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="User prompt text to scan")
    layer: Optional[str] = "input"
    request_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class MemoryScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000, description="Memory instruction or conversation context to evaluate")
    session_id: Optional[str] = "default_session"
    user_id: Optional[str] = "default_user"
    request_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class RetrievalScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=500000, description="External document or retrieval passage text to inspect")
    source: Optional[str] = "uploaded_document"
    request_id: Optional[str] = None
    chunk_size: Optional[int] = Field(500, ge=10, le=10000)
    chunk_overlap: Optional[int] = Field(50, ge=0, le=5000)

    @model_validator(mode="after")
    def validate_overlap_less_than_chunk_size(self):
        if self.chunk_overlap is not None and self.chunk_size is not None:
            if self.chunk_overlap >= self.chunk_size:
                raise ValueError("chunk_overlap must be strictly less than chunk_size to prevent infinite chunking loops")
        return self

class ToolScanRequest(BaseModel):
    tool_name: str = Field(..., description="Name of tool: calculator, document_search, file_listing, mock_email")
    user_role: Optional[str] = "standard_user"
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters supplied to the tool")
    session_id: Optional[str] = "default_session"
    request_id: Optional[str] = None

class OutputScanRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Generated AI response to inspect for sensitive leaks")
    redact: Optional[bool] = True
    request_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

from enum import Enum

class ValidPolicyAction(str, Enum):
    PASS = "PASS"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"

class PolicyUpdateRequest(BaseModel):
    layer: str
    enabled: Optional[bool] = None
    threshold: Optional[float] = None
    default_action: Optional[ValidPolicyAction] = None
