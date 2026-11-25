from fastapi import APIRouter, HTTPException, Header
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from agent.agent_workflow import run_scenario, list_all_scenarios, SCENARIOS
from agent.agent import ReconMindGuardedAgent
import os

router = APIRouter(prefix="/agent", tags=["Simulated AI Agent"])

# Server-Side Identity and Role Mapping
# Roles MUST be derived from server-side verified credentials, never trusted from client payload
SERVER_API_KEY_ROLES = {
    "reconmind-admin-secret-key-2026": "admin",
    "reconmind-analyst-secret-key-2026": "analyst",
}

def resolve_server_side_role(x_api_key: Optional[str] = None) -> str:
    """
    Derives role from authenticated server-side identity.
    Defaults to 'standard_user' if unauthenticated or non-admin token.
    Never allows client to claim privileged roles arbitrarily.
    """
    if x_api_key and x_api_key in SERVER_API_KEY_ROLES:
        return SERVER_API_KEY_ROLES[x_api_key]
    return "standard_user"

class CustomAgentRunRequest(BaseModel):
    user_prompt: str = Field(..., description="Prompt to submit to guarded agent")
    proposed_memory_update: Optional[str] = Field(None, description="Optional persistent memory directive")
    candidate_documents: Optional[List[Dict[str, Any]]] = Field(None, description="Optional RAG passages")
    # user_role is optional in payload and will NEVER elevate privileges above server-side identity
    user_role: Optional[str] = Field(None, description="Optional client-requested role (clamped to authenticated server-side role)")

@router.get("/scenarios")
def get_scenarios():
    """Returns catalog of pre-configured demonstration scenarios."""
    return {"scenarios": list_all_scenarios()}

@router.post("/run-scenario/{scenario_key}")
def execute_scenario(scenario_key: str):
    """Executes a pre-configured multi-layer defense demonstration scenario."""
    try:
        result = run_scenario(scenario_key)
        # Convert dataclasses to dict
        steps_data = []
        for s in result.execution_steps:
            steps_data.append({
                "step_number": s.step_number,
                "layer": s.layer,
                "action_type": s.action_type,
                "input_data": str(s.input_data)[:200],
                "verdict": s.verdict,
                "reason": s.reason,
                "details": s.details,
                "blocked": s.blocked
            })

        return {
            "scenario_id": result.scenario_id,
            "user_prompt": result.user_prompt,
            "final_response": result.final_response,
            "overall_status": result.overall_status,
            "execution_steps": steps_data,
            "active_memory": result.active_memory,
            "retrieved_documents": result.retrieved_documents,
            "tool_calls_attempted": result.tool_calls_attempted,
            "execution_time_ms": round(result.execution_time_ms, 2)
        }
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/execute")
def execute_custom_agent(
    request: CustomAgentRunRequest,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key")
):
    """Executes a custom user prompt through all 5 ReconMind defense layers in the simulated agent."""
    try:
        # Server-side authentication and role resolution
        authenticated_role = resolve_server_side_role(x_api_key)
        
        # Security invariant: Standard users cannot claim administrative access via body
        if request.user_role and request.user_role in ["admin", "analyst"]:
            if authenticated_role != request.user_role:
                # Client attempted unauthenticated privilege elevation
                effective_role = "standard_user"
            else:
                effective_role = authenticated_role
        else:
            effective_role = authenticated_role

        agent = ReconMindGuardedAgent(user_role=effective_role)
        result = agent.execute_request(
            user_prompt=request.user_prompt,
            proposed_memory_update=request.proposed_memory_update,
            candidate_documents=request.candidate_documents,
            scenario_id="custom_execution"
        )
        steps_data = []
        for s in result.execution_steps:
            steps_data.append({
                "step_number": s.step_number,
                "layer": s.layer,
                "action_type": s.action_type,
                "input_data": str(s.input_data)[:200],
                "verdict": s.verdict,
                "reason": s.reason,
                "details": s.details,
                "blocked": s.blocked
            })

        return {
            "scenario_id": result.scenario_id,
            "user_prompt": result.user_prompt,
            "final_response": result.final_response,
            "overall_status": result.overall_status,
            "execution_steps": steps_data,
            "active_memory": result.active_memory,
            "retrieved_documents": result.retrieved_documents,
            "tool_calls_attempted": result.tool_calls_attempted,
            "execution_time_ms": round(result.execution_time_ms, 2)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
