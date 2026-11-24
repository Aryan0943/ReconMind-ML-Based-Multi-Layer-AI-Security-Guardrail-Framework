from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import time

@dataclass
class AgentMessage:
    role: str  # "user", "assistant", "system", "tool"
    content: str
    timestamp: float = field(default_factory=time.time)

@dataclass
class AgentExecutionStep:
    step_number: int
    layer: str
    action_type: str
    input_data: Any
    verdict: str  # "PASS", "SANITIZE", "BLOCK"
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)
    blocked: bool = False

@dataclass
class AgentWorkflowResult:
    scenario_id: Optional[str]
    user_prompt: str
    final_response: str
    overall_status: str  # "COMPLETED", "INTERCEPTED", "BLOCKED"
    execution_steps: List[AgentExecutionStep] = field(default_factory=list)
    active_memory: List[Dict[str, Any]] = field(default_factory=list)
    retrieved_documents: List[Dict[str, Any]] = field(default_factory=list)
    tool_calls_attempted: List[Dict[str, Any]] = field(default_factory=list)
    execution_time_ms: float = 0.0
