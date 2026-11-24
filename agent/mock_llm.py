from typing import Dict, Any, List, Optional
import json

class DeterministicMockLLM:
    """
    Deterministic Mock LLM that simulates realistic model reasoning,
    tool selection intents, and response drafting without calling paid APIs.
    """
    def __init__(self):
        pass

    def generate(
        self,
        prompt: str,
        memory: List[Dict[str, Any]],
        retrieved_docs: List[Dict[str, Any]],
        role_persona: str = "helpful_assistant"
    ) -> Dict[str, Any]:
        prompt_lower = prompt.lower()

        # Check if the prompt requires a tool call
        if any(w in prompt_lower for w in ["calculate", "multiply", "*", "compute", "math"]):
            # Extract expression or default
            if "25 * 40" in prompt:
                expr = "25 * 40 + 150"
            else:
                expr = "10 + 20"
            return {
                "thought": "User is asking for a calculation. I will call the calculator tool.",
                "tool_call": {
                    "tool_name": "calculator",
                    "parameters": {"expression": expr}
                },
                "draft_response": None
            }

        if "weather" in prompt_lower:
            loc = "San Francisco, CA"
            if "tokyo" in prompt_lower:
                loc = "Tokyo, Japan"
            return {
                "thought": "User is asking for weather information. I will call the weather tool.",
                "tool_call": {
                    "tool_name": "weather_lookup",
                    "parameters": {"location": loc}
                },
                "draft_response": None
            }

        # Scenario: Unauthorized tool attempt (e.g. asking to drop tables or access raw db)
        if "drop table" in prompt_lower or "database admin" in prompt_lower:
            return {
                "thought": "User is asking to modify internal database. I will invoke database admin tool.",
                "tool_call": {
                    "tool_name": "database_admin_tool",
                    "parameters": {"command": "DROP TABLE users;"}
                },
                "draft_response": None
            }

        # Scenario: Path traversal tool invocation
        if "read /etc/passwd" in prompt_lower or "read file" in prompt_lower or "../" in prompt_lower:
            return {
                "thought": "User requested reading an internal system file.",
                "tool_call": {
                    "tool_name": "read_file",
                    "parameters": {"path": "../../../../etc/passwd"}
                },
                "draft_response": None
            }

        # Scenario: Sensitive credential exposure in response
        if any(w in prompt_lower for w in ["database status report", "reveal secret", "show api key", "dump credentials"]):
            return {
                "thought": "Drafting response containing server credentials as requested.",
                "tool_call": None,
                "draft_response": "Connected to staging database. OpenAI API key: sk-proj-ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv12wx34 and AWS key AKIAIOSFODNN7EXAMPLE."
            }

        # Standard context-augmented response
        doc_context = ""
        if retrieved_docs:
            doc_context = f" Based on retrieved document: {retrieved_docs[0].get('content', '')[:100]}..."

        return {
            "thought": "User query is standard. Providing direct conversational response.",
            "tool_call": None,
            "draft_response": f"I have processed your request safely.{doc_context} How else may I assist you today?"
        }
