from fastapi import APIRouter, HTTPException
from app.database.connection import db_manager
from app.schemas.requests import PolicyUpdateRequest
from app.engine.defense_manager import defense_manager

router = APIRouter(prefix="/policies", tags=["Security Policies"])

@router.get("")
def get_security_policies():
    """
    Returns current configuration and threshold policies for all 5 defense layers.
    """
    return {
        "success": True,
        "policies": db_manager.get_policies()
    }

@router.put("")
def update_security_policy(req: PolicyUpdateRequest):
    """
    Updates operational threshold or enabled status for a defense layer.
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
        update_payload["default_action"] = req.default_action.upper()

    updated = db_manager.update_policy(layer, update_payload)
    # Refresh live defense manager instance
    defense_manager.refresh_policies()
    
    return {
        "success": True,
        "layer": layer,
        "policy": updated
    }
