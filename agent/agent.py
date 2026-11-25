import time
from typing import Dict, Any, List, Optional
from agent.agent_state import AgentWorkflowResult, AgentExecutionStep, AgentMessage
from agent.mock_llm import DeterministicMockLLM
from agent.mock_tools import MockSandboxedTools
from app.engine.defense_manager import defense_manager

class ReconMindGuardedAgent:
    """
    Autonomous AI Agent fully wired through all Five ReconMind Defense Layers.
    Enforces strict zero-trust:
    1. Input Defense inspects incoming user prompt.
    2. Memory Defense inspects any session context update before storage.
    3. Retrieval Defense inspects RAG passages before adding them to prompt context.
    4. Tool Defense evaluates RBAC, path traversal & arguments before any tool executes.
    5. Output Defense inspects and sanitizes LLM output before delivery.
    """
    def __init__(self, user_role: str = "standard_user"):
        self.user_role = user_role
        self.llm = DeterministicMockLLM()
        self.conversation_memory: List[Dict[str, Any]] = []
        self.retrieved_documents: List[Dict[str, Any]] = []

    def execute_request(
        self,
        user_prompt: str,
        proposed_memory_update: Optional[str] = None,
        candidate_documents: Optional[List[Dict[str, Any]]] = None,
        scenario_id: Optional[str] = None
    ) -> AgentWorkflowResult:
        import uuid
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        start_time = time.perf_counter()
        steps: List[AgentExecutionStep] = []
        step_idx = 1

        # -------------------------------------------------------------
        # STEP 1: LAYER 1 — INPUT DEFENSE
        # -------------------------------------------------------------
        input_scan = defense_manager.coordinate_scan(layer_name="input", content=user_prompt, request_id=request_id)
        step1 = AgentExecutionStep(
            step_number=step_idx,
            layer="input",
            action_type="inspect_user_prompt",
            input_data=user_prompt,
            verdict=input_scan.action,
            reason=input_scan.reason,
            details={
                "prediction": input_scan.prediction,
                "category": input_scan.category,
                "confidence": input_scan.confidence,
                "latency_ms": input_scan.latency_ms
            },
            blocked=(input_scan.action == "BLOCK")
        )
        steps.append(step1)
        step_idx += 1

        if input_scan.action == "BLOCK":
            total_time = (time.perf_counter() - start_time) * 1000.0
            return AgentWorkflowResult(
                scenario_id=scenario_id,
                user_prompt=user_prompt,
                final_response=f"ACCESS DENIED by ReconMind Layer 1 (Input Defense): {input_scan.reason}",
                overall_status="BLOCKED",
                execution_steps=steps,
                active_memory=self.conversation_memory,
                retrieved_documents=[],
                tool_calls_attempted=[],
                execution_time_ms=total_time
            )

        # -------------------------------------------------------------
        # STEP 2: LAYER 2 — MEMORY DEFENSE
        # -------------------------------------------------------------
        if proposed_memory_update:
            mem_scan = defense_manager.coordinate_scan(layer_name="memory", content=proposed_memory_update, request_id=request_id)
            mem_blocked = (mem_scan.action == "BLOCK")
            step2 = AgentExecutionStep(
                step_number=step_idx,
                layer="memory",
                action_type="inspect_memory_update",
                input_data=proposed_memory_update,
                verdict=mem_scan.action,
                reason=mem_scan.reason,
                details={
                    "prediction": mem_scan.prediction,
                    "confidence": mem_scan.confidence,
                    "quarantined": mem_blocked
                },
                blocked=mem_blocked
            )
            steps.append(step2)
            step_idx += 1

            if not mem_blocked:
                # Store in active session memory
                self.conversation_memory.append({
                    "content": proposed_memory_update,
                    "timestamp": time.time(),
                    "status": "APPROVED"
                })
            else:
                # Quarantined: strictly blocked from context
                pass

        # -------------------------------------------------------------
        # STEP 3: LAYER 3 — RETRIEVAL DEFENSE
        # -------------------------------------------------------------
        usable_docs = []
        if candidate_documents:
            for doc in candidate_documents:
                doc_text = doc.get("content") or doc.get("text") or ""
                ret_scan = defense_manager.coordinate_scan(layer_name="retrieval", content=doc_text, request_id=request_id)
                doc_blocked = (ret_scan.action in ["BLOCK", "SANITIZE"])
                
                step3 = AgentExecutionStep(
                    step_number=step_idx,
                    layer="retrieval",
                    action_type="inspect_rag_document",
                    input_data=doc_text[:120] + "...",
                    verdict=ret_scan.action,
                    reason=ret_scan.reason,
                    details={
                        "document_id": doc.get("id", "doc_unknown"),
                        "prediction": ret_scan.prediction,
                        "category": ret_scan.category,
                        "confidence": ret_scan.confidence
                    },
                    blocked=doc_blocked
                )
                steps.append(step3)
                step_idx += 1

                if not doc_blocked:
                    usable_docs.append(doc)

        self.retrieved_documents = usable_docs

        # -------------------------------------------------------------
        # STEP 4: MOCK LLM DECISION & LAYER 4 — TOOL DEFENSE
        # -------------------------------------------------------------
        llm_output = self.llm.generate(
            prompt=user_prompt,
            memory=self.conversation_memory,
            retrieved_docs=usable_docs
        )

        tool_calls_attempted = []
        tool_execution_result = None

        if llm_output.get("tool_call"):
            tool_call = llm_output["tool_call"]
            tool_name = tool_call["tool_name"]
            params = tool_call["parameters"]
            tool_calls_attempted.append(tool_call)

            # Validate tool request with Layer 4
            tool_scan = defense_manager.coordinate_scan(
                layer_name="tool",
                content={
                    "tool_name": tool_name,
                    "user_role": self.user_role,
                    "parameters": params
                },
                request_id=request_id
            )

            tool_blocked = (tool_scan.action == "BLOCK")
            step4 = AgentExecutionStep(
                step_number=step_idx,
                layer="tool",
                action_type=f"authorize_tool_call:{tool_name}",
                input_data=tool_call,
                verdict=tool_scan.action,
                reason=tool_scan.reason,
                details={
                    "user_role": self.user_role,
                    "findings": [f.model_dump() if hasattr(f, "model_dump") else str(f) for f in tool_scan.findings],
                    "blocked": tool_blocked
                },
                blocked=tool_blocked
            )
            steps.append(step4)
            step_idx += 1

            if not tool_blocked:
                # Safely execute mock tool
                if tool_name == "calculator":
                    tool_execution_result = MockSandboxedTools.calculator(params.get("expression", "0"))
                elif tool_name == "weather_lookup":
                    tool_execution_result = MockSandboxedTools.weather_lookup(params.get("location", ""))
                elif tool_name == "read_file":
                    tool_execution_result = MockSandboxedTools.read_file(params.get("path", ""))
                raw_agent_reply = f"Tool execution result: {tool_execution_result}"
            else:
                raw_agent_reply = f"Operation blocked by Tool Defense: {tool_scan.reason}"
        else:
            raw_agent_reply = llm_output.get("draft_response", "Request processed.")

        # -------------------------------------------------------------
        # STEP 5: LAYER 5 — OUTPUT DEFENSE
        # -------------------------------------------------------------
        output_scan = defense_manager.coordinate_scan(layer_name="output", content=raw_agent_reply, request_id=request_id)
        output_blocked = (output_scan.action == "BLOCK")
        
        # Decide final delivered response
        if output_scan.action == "SANITIZE":
            final_response = output_scan.sanitized_content or "[REDACTED]"
        elif output_scan.action == "BLOCK":
            final_response = f"DELIVERY BLOCKED by Output Defense: {output_scan.reason}"
        else:
            final_response = raw_agent_reply

        step5 = AgentExecutionStep(
            step_number=step_idx,
            layer="output",
            action_type="inspect_llm_output",
            input_data="[MASKED_RAW_RESPONSE]" if output_scan.findings else raw_agent_reply,
            verdict=output_scan.action,
            reason=output_scan.reason,
            details={
                "has_sensitive_leak": (output_scan.action in ["SANITIZE", "BLOCK"]),
                "findings_count": len(output_scan.findings),
                "sanitized": (output_scan.action == "SANITIZE")
            },
            blocked=output_blocked
        )
        steps.append(step5)

        total_time = (time.perf_counter() - start_time) * 1000.0

        overall_status = "COMPLETED"
        if any(s.blocked for s in steps):
            overall_status = "INTERCEPTED"

        return AgentWorkflowResult(
            scenario_id=scenario_id,
            user_prompt=user_prompt,
            final_response=final_response,
            overall_status=overall_status,
            execution_steps=steps,
            active_memory=self.conversation_memory,
            retrieved_documents=self.retrieved_documents,
            tool_calls_attempted=tool_calls_attempted,
            execution_time_ms=total_time
        )
