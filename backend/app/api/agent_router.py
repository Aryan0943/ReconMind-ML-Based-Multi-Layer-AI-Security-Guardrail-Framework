from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from agent.agent_workflow import run_scenario, list_all_scenarios, SCENARIOS
from agent.agent import ReconMindGuardedAgent

router = APIRouter(prefix="/agent", tags=["Simulated AI Agent"])

class CustomAgentRunRequest(BaseModel):
    user_prompt: str = Field(..., description="Prompt to submit to guarded agent")
    proposed_memory_update: Optional[str] = Field(None, description="Optional persistent memory directive")
    candidate_documents: Optional[List[Dict[str, Any]]] = Field(None, description="Optional RAG passages")
    user_role: str = Field("standard_user", description="Caller role for tool authorization")

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
def execute_custom_agent(request: CustomAgentRunRequest):
    """Executes a custom user prompt through all 5 ReconMind defense layers in the simulated agent."""
    try:
        agent = ReconMindGuardedAgent(user_role=request.user_role)
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
