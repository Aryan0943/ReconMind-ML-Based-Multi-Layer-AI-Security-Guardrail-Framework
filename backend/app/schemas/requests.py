from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class InputScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="User prompt text to scan")
    layer: Optional[str] = "input"
    metadata: Optional[Dict[str, Any]] = None

class MemoryScanRequest(BaseModel):
    content: str = Field(..., min_length=1, max_length=10000, description="Memory instruction or conversation context to evaluate")
    session_id: Optional[str] = "default_session"
    user_id: Optional[str] = "default_user"
    metadata: Optional[Dict[str, Any]] = None

class RetrievalScanRequest(BaseModel):
    content: str = Field(..., min_length=1, description="External document or retrieval passage text to inspect")
    source: Optional[str] = "uploaded_document"
    chunk_size: Optional[int] = 500
    chunk_overlap: Optional[int] = 50

class ToolScanRequest(BaseModel):
    tool_name: str = Field(..., description="Name of tool: calculator, document_search, file_listing, mock_email")
    user_role: Optional[str] = "standard_user"
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters supplied to the tool")
    session_id: Optional[str] = "default_session"

class OutputScanRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Generated AI response to inspect for sensitive leaks")
    redact: Optional[bool] = True
    metadata: Optional[Dict[str, Any]] = None

class PolicyUpdateRequest(BaseModel):
    layer: str
    enabled: Optional[bool] = None
    threshold: Optional[float] = None
    default_action: Optional[str] = None
