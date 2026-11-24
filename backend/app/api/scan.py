import os
import io
import time
from typing import Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, status
from pypdf import PdfReader

from app.schemas.requests import (
    InputScanRequest, MemoryScanRequest, RetrievalScanRequest,
    ToolScanRequest, OutputScanRequest
)
from app.schemas.responses import SecurityScanResponse, DocumentScanResponse
from app.engine.defense_manager import defense_manager
from app.defenses.retrieval_defense import RetrievalDefense
from app.database.connection import db_manager

router = APIRouter(prefix="/scan", tags=["Security Scans"])

@router.post("/input", response_model=SecurityScanResponse)
def scan_user_input(req: InputScanRequest):
    """
    Layer 1: Input Defense
    Scans user prompt for direct prompt injection, system prompt extraction,
    and jailbreaks using ML classification and heuristic rules.
    """
    try:
        return defense_manager.coordinate_scan(
            layer_name="input",
            content=req.text,
            log_event=True,
            metadata=req.metadata
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Input scan failed: {str(e)}")

@router.post("/memory", response_model=SecurityScanResponse)
def scan_memory_entry(req: MemoryScanRequest):
    """
    Layer 2: Memory Defense
    Validates conversation memory entry before persistent storage to prevent memory poisoning.
    If approved, persists into simulated conversation memory.
    """
    try:
        res = defense_manager.coordinate_scan(
            layer_name="memory",
            content=req.content,
            log_event=True,
            session_id=req.session_id,
            user_id=req.user_id,
            metadata=req.metadata
        )
        
        # Persist to memory store
        mem_status = "approved" if res.action == "PASS" else ("quarantined" if res.action == "SANITIZE" else "rejected")
        import uuid
        from datetime import datetime, timezone
        db_manager.insert_memory({
            "memory_id": f"mem_{uuid.uuid4().hex[:12]}",
            "session_id": req.session_id,
            "user_id": req.user_id,
            "content": req.content,
            "status": mem_status,
            "action": res.action,
            "is_active_context": mem_status == "approved",
            "created_at": datetime.now(timezone.utc).isoformat()
        })
        
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Memory scan failed: {str(e)}")

@router.get("/memory/active")
def get_active_conversation_memory(session_id: Optional[str] = None):
    """
    Enforcement Gate: Returns ONLY approved memories for active LLM context.
    Rejected or quarantined poisoning entries are strictly excluded.
    """
    memories = db_manager.get_memories(session_id=session_id, approved_only=True)
    all_memories = db_manager.get_memories(session_id=session_id, approved_only=False)
    blocked_count = sum(1 for m in all_memories if m.get("status") in ["rejected", "quarantined"])
    return {
        "success": True,
        "active_memory_count": len(memories),
        "blocked_or_quarantined_count": blocked_count,
        "active_memories": memories
    }

@router.post("/retrieval", response_model=SecurityScanResponse)
def scan_retrieval_text(req: RetrievalScanRequest):
    """
    Layer 3: Retrieval Defense
    Inspects document text or retrieval chunks for embedded adversarial instructions.
    """
    try:
        return defense_manager.coordinate_scan(
            layer_name="retrieval",
            content=req.content,
            log_event=True,
            chunk_size=req.chunk_size,
            chunk_overlap=req.chunk_overlap
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retrieval scan failed: {str(e)}")

@router.post("/tool", response_model=SecurityScanResponse)
def scan_tool_request(req: ToolScanRequest):
    """
    Layer 4: Tool Defense
    Validates AI tool invocation request against authorization policies,
    role-based permissions, and strict argument constraints.
    """
    try:
        return defense_manager.coordinate_scan(
            layer_name="tool",
            content={
                "tool_name": req.tool_name,
                "user_role": req.user_role,
                "parameters": req.parameters
            },
            log_event=True,
            session_id=req.session_id
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tool scan failed: {str(e)}")

@router.post("/output", response_model=SecurityScanResponse)
def scan_ai_output(req: OutputScanRequest):
    """
    Layer 5: Output Defense
    Inspects generated AI text for sensitive credentials, API keys, and PII leaks.
    Applies deterministic redaction or blocks output.
    """
    try:
        return defense_manager.coordinate_scan(
            layer_name="output",
            content=req.text,
            log_event=True,
            redact=req.redact,
            metadata=req.metadata
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Output scan failed: {str(e)}")

@router.post("/document", response_model=DocumentScanResponse)
async def upload_and_scan_document(file: UploadFile = File(...)):
    """
    Uploads and scans TXT or PDF documents for indirect prompt injections and threats.
    Splits document into manageable chunks and outputs granular chunk risk report.
    """
    # 1. File extension validation
    allowed_exts = [".txt", ".pdf", ".md", ".json"]
    filename = file.filename or "unknown_file"
    ext = os.path.splitext(filename)[1].lower()
    
    if ext not in allowed_exts:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported file format '{ext}'. Allowed: {', '.join(allowed_exts)}"
        )

    # 2. File size limit (max 5 MB for demo safe limits)
    contents = await file.read()
    if len(contents) > 5 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds maximum permitted limit (5MB)."
        )

    # 3. Extract text
    extracted_text = ""
    try:
        if ext == ".pdf":
            pdf_stream = io.BytesIO(contents)
            reader = PdfReader(pdf_stream)
            for page_num, page in enumerate(reader.pages):
                page_text = page.extract_text() or ""
                extracted_text += page_text + "\n"
        else:
            extracted_text = contents.decode("utf-8", errors="replace")
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Failed to extract text from document: {str(e)}"
        )

    if not extracted_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No inspectable text found in uploaded document."
        )

    # 4. Perform chunked retrieval inspection
    retrieval_layer: RetrievalDefense = defense_manager.layers["retrieval"]
    doc_response = retrieval_layer.scan_full_document(filename=filename, full_text=extracted_text)
    
    # Log document event
    import uuid
    from datetime import datetime, timezone
    
    is_safe = doc_response.overall_action == "PASS"
    db_manager.store_document_index({
        "document_id": doc_response.event_id,
        "filename": filename,
        "total_chunks": doc_response.total_chunks,
        "suspicious_chunks": doc_response.suspicious_chunks,
        "overall_action": doc_response.overall_action,
        "is_active_for_retrieval": is_safe,
        "quarantined": not is_safe,
        "timestamp": doc_response.timestamp
    })

    db_manager.insert_log({
        "event_id": doc_response.event_id,
        "timestamp": doc_response.timestamp,
        "layer": "retrieval_document",
        "input_preview": f"Document: {filename} ({doc_response.total_chunks} chunks, Active Retrieval: {'APPROVED' if is_safe else 'BARRED'})",
        "prediction": "malicious" if doc_response.suspicious_chunks > 0 else "benign",
        "category": doc_response.detected_categories[0] if doc_response.detected_categories else "benign",
        "confidence": 0.95 if doc_response.suspicious_chunks > 0 else 1.0,
        "action": doc_response.overall_action,
        "reason": doc_response.reason,
        "latency_ms": doc_response.latency_ms,
        "model_version": "1.0.0"
    })

    return doc_response

@router.get("/documents/active")
def get_active_retrieval_index():
    """
    Enforcement Gate: Returns list of documents in active retrieval index.
    Blocked or quarantined documents containing malicious chunks are strictly barred.
    """
    active_docs = db_manager.get_active_documents(active_only=True)
    all_docs = db_manager.get_active_documents(active_only=False)
    quarantined_count = sum(1 for d in all_docs if not d.get("is_active_for_retrieval"))
    return {
        "success": True,
        "active_document_count": len(active_docs),
        "quarantined_document_count": quarantined_count,
        "active_documents": active_docs
    }
