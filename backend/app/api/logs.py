from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Query
from app.database.connection import db_manager

router = APIRouter(prefix="/logs", tags=["Security Logs"])

@router.get("")
def get_security_logs(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    layer: Optional[str] = Query(None, description="Filter by defense layer"),
    action: Optional[str] = Query(None, description="Filter by security action: PASS, SANITIZE, BLOCK")
):
    """
    Retrieves paginated security event audit logs from the database.
    """
    logs = db_manager.get_logs(limit=limit, skip=skip, layer=layer, action=action)
    return {
        "success": True,
        "count": len(logs),
        "limit": limit,
        "skip": skip,
        "logs": logs
    }
