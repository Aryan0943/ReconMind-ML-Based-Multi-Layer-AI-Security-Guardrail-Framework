from fastapi import APIRouter, HTTPException, Depends, Header
from app.database.connection import db_manager
from app.schemas.requests import PolicyUpdateRequest
from app.engine.defense_manager import defense_manager
import os

router = APIRouter(prefix="/policies", tags=["Security Policies"])

# Server-Side Administrative Authorization
ADMIN_API_KEY = os.environ.get("RECONMIND_ADMIN_API_KEY", "reconmind-admin-secret-key-2026")

def verify_admin_auth(x_api_key: str = Header(None, alias="X-API-Key")):
    """
    Enforces server-side administrative authentication for policy and configuration management.
    """
    if not x_api_key or x_api_key != ADMIN_API_KEY:
        raise HTTPException(
            status_code=403,
            detail="Forbidden: Administrative authentication required to view or modify security policies."
        )
    return True

@router.get("")
def get_security_policies():
    """
    Returns current configuration and threshold policies for all 5 defense layers.
    """
    return {
        "success": True,
        "policies": db_manager.get_policies()
    }

@router.put("", dependencies=[Depends(verify_admin_auth)])
def update_security_policy(req: PolicyUpdateRequest):
    """
    Updates operational threshold or enabled status for a defense layer.
    Requires administrative authentication (X-API-Key header).
    Immediately applies changes to the live DefenseManager.
    """
    layer = req.layer.lower()
    valid_layers = ["input", "memory", "retrieval", "tool", "output"]
    if layer not in valid_layers:
        raise HTTPException(status_code=400, detail=f"Invalid layer '{layer}'. Must be one of {valid_layers}")

    update_payload = {}
    if req.enabled is not None:
        update_payload["enabled"] = req.enabled
    if req.threshold is not None:
        update_payload["threshold"] = max(0.0, min(1.0, req.threshold))
    if req.default_action is not None:
        action_val = req.default_action.value if hasattr(req.default_action, "value") else str(req.default_action).upper()
        if action_val not in ["PASS", "SANITIZE", "BLOCK", "QUARANTINE"]:
            raise HTTPException(status_code=400, detail=f"Invalid default_action '{action_val}'. Allowed: PASS, SANITIZE, BLOCK, QUARANTINE")
        update_payload["default_action"] = action_val

    updated = db_manager.update_policy(layer, update_payload)
    # Refresh live defense manager instance
    defense_manager.refresh_policies()
    
    return {
        "success": True,
        "layer": layer,
        "policy": updated
    }
