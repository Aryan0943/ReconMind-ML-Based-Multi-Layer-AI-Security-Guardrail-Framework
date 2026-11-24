import sys
from pathlib import Path

# Add project root and backend to python path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "backend"))

import pytest
from agent.agent_workflow import run_scenario, SCENARIOS
from agent.agent import ReconMindGuardedAgent

def test_agent_scenario_a_direct_injection_blocked():
    res = run_scenario("scenario_a")
    assert res.overall_status == "BLOCKED"
    assert res.execution_steps[0].layer == "input"
    assert res.execution_steps[0].verdict == "BLOCK"
    assert "ACCESS DENIED" in res.final_response

def test_agent_scenario_b_rag_indirect_injection_quarantined():
    res = run_scenario("scenario_b")
    # Document contains injection payload, so retrieval defense quarantines it
    assert res.overall_status in ["COMPLETED", "INTERCEPTED"]
    retrieval_steps = [s for s in res.execution_steps if s.layer == "retrieval"]
    assert len(retrieval_steps) > 0
    assert retrieval_steps[0].blocked is True
    # Verify poisoned doc was not placed in retrieved_documents
    assert len(res.retrieved_documents) == 0

def test_agent_scenario_c_memory_poisoning_quarantined():
    res = run_scenario("scenario_c")
    assert res.overall_status == "INTERCEPTED"
    mem_steps = [s for s in res.execution_steps if s.layer == "memory"]
    assert len(mem_steps) > 0
    assert mem_steps[0].blocked is True
    # Malicious directive must be absent from active memory
    assert len(res.active_memory) == 0

def test_agent_scenario_d_path_traversal_blocked():
    res = run_scenario("scenario_d")
    assert res.overall_status == "INTERCEPTED"
    tool_steps = [s for s in res.execution_steps if s.layer == "tool"]
    assert len(tool_steps) > 0
    assert tool_steps[0].blocked is True
    assert "Tool access violation" in res.final_response

def test_agent_scenario_e_output_redaction():
    res = run_scenario("scenario_e")
    out_steps = [s for s in res.execution_steps if s.layer == "output"]
    assert len(out_steps) > 0
    assert out_steps[0].verdict == "SANITIZE"
    assert "[REDACTED_API_KEY]" in res.final_response
    assert "sk-proj-" not in res.final_response

def test_agent_scenario_f_benign_safe_execution():
    res = run_scenario("scenario_f")
    assert res.overall_status == "COMPLETED"
    assert len(res.execution_steps) >= 4
    # All steps should have passed
    for s in res.execution_steps:
        assert s.verdict in ["PASS", "SANITIZE"]
        assert s.blocked is False
    assert "1150" in res.final_response
