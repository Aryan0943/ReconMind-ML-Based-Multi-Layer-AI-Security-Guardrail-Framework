import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import pytest
from app.engine.defense_manager import defense_manager
from app.ml.predict import ml_engine
from app.security.permissions import validate_tool_request
from app.defenses.retrieval_defense import RetrievalDefense
from app.schemas.requests import RetrievalScanRequest, PolicyUpdateRequest, ValidPolicyAction
from app.api.agent_router import resolve_server_side_role
from app.database.connection import db_manager
from pydantic import ValidationError

def test_ml_unavailable_fail_closed():
    """
    Vulnerability 1: ML model unavailable must fail-closed (BLOCK), not pass.
    """
    # Temporarily simulate ML unavailable
    original_loaded = ml_engine.is_loaded
    try:
        ml_engine.is_loaded = False
        res = defense_manager.coordinate_scan(layer_name="input", content="Hello world", log_event=False)
        assert res.action == "BLOCK", "ML unavailability must trigger fail-closed BLOCK"
        assert res.category == "service_unavailable_fail_closed"
    finally:
        ml_engine.is_loaded = original_loaded

def test_disabled_layer_cannot_bypass_mandatory_tool_controls():
    """
    Vulnerability 2: Disabled configuration toggles must never bypass mandatory security controls (Tool RBAC / Path Traversal).
    """
    # Disable tool defense in policy
    dummy_policy = {"enabled": False, "threshold": 0.5, "default_action": "BLOCK"}
    
    # Standard user attempting unapproved tool
    from app.schemas.responses import SecurityScanResponse
    from app.engine.policy_engine import PolicyEngine
    pe = PolicyEngine()
    
    # Run tool inspection
    tool_resp = defense_manager.layers["tool"].inspect({
        "tool_name": "read_file",
        "user_role": "standard_user",
        "parameters": {"path": "../../../../etc/passwd"}
    })
    
    action, reason = pe.evaluate_decision("tool", tool_resp, dummy_policy)
    assert action == "BLOCK", "Disabling layer must NEVER bypass tool authorization or path traversal"
    assert "Mandatory tool security violation" in reason or "Tool access violation" in reason

def test_server_side_role_resolution():
    """
    Vulnerability 3: User-controlled roles must be clamped to server-side identity.
    """
    # No auth header -> standard_user
    assert resolve_server_side_role(None) == "standard_user"
    assert resolve_server_side_role("fake-unverified-key") == "standard_user"
    
    # Verified admin key -> admin
    assert resolve_server_side_role("reconmind-admin-secret-key-2026") == "admin"
    assert resolve_server_side_role("reconmind-analyst-secret-key-2026") == "analyst"

def test_policy_action_validation():
    """
    Vulnerability 4: PolicyUpdateRequest must reject invalid arbitrary actions.
    """
    # Valid actions
    valid_req = PolicyUpdateRequest(layer="input", default_action=ValidPolicyAction.BLOCK)
    assert valid_req.default_action == "BLOCK"
    
    # Invalid action like ALLOW_ANYTHING must raise ValidationError
    with pytest.raises(ValidationError):
        PolicyUpdateRequest(layer="input", default_action="ALLOW_ANYTHING")

def test_retrieval_chunk_overlap_validation():
    """
    Vulnerability 5: RetrievalScanRequest must reject chunk_overlap >= chunk_size to prevent DoS infinite loop.
    """
    # Valid overlap
    valid_req = RetrievalScanRequest(content="Sample content", chunk_size=500, chunk_overlap=50)
    assert valid_req.chunk_overlap == 50
    
    # Overlap equals chunk_size -> must raise ValidationError
    with pytest.raises(ValidationError):
        RetrievalScanRequest(content="Sample content", chunk_size=100, chunk_overlap=100)
        
    # Overlap greater than chunk_size -> must raise ValidationError
    with pytest.raises(ValidationError):
        RetrievalScanRequest(content="Sample content", chunk_size=100, chunk_overlap=150)

def test_safe_ast_calculator_resource_boundary():
    """
    Vulnerability 6: AST calculator must reject exponential blowups, oversized literals, and dangerous expressions.
    """
    # Normal math works safely
    ok, reason, findings, res = validate_tool_request("calculator", "standard_user", {"expression": "25 * 40 + 10"})
    assert ok is True
    assert res["result"] == 1010
    
    # Exponential DoS attack (e.g. 10**1000)
    ok_dos, reason_dos, findings_dos, _ = validate_tool_request("calculator", "standard_user", {"expression": "10 ** 500"})
    assert ok_dos is False
    assert any("unsafe_expression" in f["type"] for f in findings_dos)
    assert "exceeds safe limits" in reason_dos or "magnitude" in reason_dos

    # Code execution attempt (e.g. __import__)
    ok_inj, reason_inj, findings_inj, _ = validate_tool_request("calculator", "standard_user", {"expression": "__import__('os').system('dir')"})
    assert ok_inj is False

def test_privacy_preserving_logging():
    """
    Vulnerability 7: Sensitive credentials and parameter values must not be logged in plain text.
    """
    # Scan tool with sensitive path
    defense_manager.coordinate_scan(
        layer_name="tool",
        content={
            "tool_name": "calculator",
            "user_role": "standard_user",
            "parameters": {"expression": "100+200", "auth_token": "sk-proj-super-secret-key-12345"}
        },
        log_event=True
    )
    latest_log = db_manager.get_logs(limit=1)[0]
    # Parameter values must be masked
    assert "sk-proj-super-secret-key-12345" not in latest_log["input_preview"]
    assert "[PARAM_VALUE_MASKED]" in latest_log["input_preview"]
