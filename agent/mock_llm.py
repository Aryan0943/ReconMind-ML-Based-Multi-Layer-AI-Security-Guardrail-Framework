import re
from typing import Dict, Any, List, Optional


# ---------------------------------------------------------------------------
# BUG FIX (E): Mock LLM arithmetic expression extraction.
#
# Previously: The branch `if "25 * 40" in prompt` hard-coded the expression
# as "25 * 40 + 150", silently injecting an extra "+ 150" that was never
# requested by the user. This:
#   - Produced wrong calculation results.
#   - Undermined the integrity of the guardrail demonstration (the tool result
#     would not match the user's arithmetic request).
#   - Was a silent, invisible modification — the user had no way to know the
#     expression had been changed.
#
# Fix: Extract the actual arithmetic expression from the prompt text using a
# regex that captures common patterns (number op number), then pass that
# verbatim to the calculator. Fall back to a safe "0" if no expression is
# found, rather than substituting a fabricated one.
# ---------------------------------------------------------------------------

# Matches expressions like: 25 * 40, 100 / 4, 2 ** 8, (3+4)*2, etc.
_MATH_EXPR_RE = re.compile(
    r"[\d\s\+\-\*\/\%\(\)\.\^]+[\d\)]"
)

# Minimum expression length to avoid matching stray numbers
_MIN_EXPR_LEN = 3


def _extract_math_expression(prompt: str) -> Optional[str]:
    """
    Attempts to extract an arithmetic expression from the user prompt.
    Returns the expression string, or None if nothing credible is found.
    """
    # Remove common filler words so the regex sees the expression more cleanly
    cleaned = re.sub(
        r"(?i)\b(please|calculate|compute|multiply|what(?:\s+is)?|the\s+result\s+of|"
        r"can\s+you|for\s+my|inventory|check)\b",
        " ", prompt
    ).strip()

    matches = _MATH_EXPR_RE.findall(cleaned)
    if not matches:
        return None

    # Pick the longest match (most likely to be the full expression)
    best = max(matches, key=len).strip()
    if len(best) >= _MIN_EXPR_LEN:
        return best
    return None


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

        # ----------------------------------------------------------------
        # Scenario: Path traversal tool invocation (checked before math)
        # ----------------------------------------------------------------
        if "read /etc/passwd" in prompt_lower or "read file" in prompt_lower or "../" in prompt_lower:
            return {
                "thought": "User requested reading an internal system file.",
                "tool_call": {
                    "tool_name": "read_file",
                    "parameters": {"path": "../../../../etc/passwd"}
                },
                "draft_response": None
            }

        # ----------------------------------------------------------------
        # Unauthorized tool attempt (database admin)
        # ----------------------------------------------------------------
        if "drop table" in prompt_lower or "database admin" in prompt_lower:
            return {
                "thought": "User is asking to modify internal database. I will invoke database admin tool.",
                "tool_call": {
                    "tool_name": "database_admin_tool",
                    "parameters": {"command": "DROP TABLE users;"}
                },
                "draft_response": None
            }

        # ----------------------------------------------------------------
        # Calculator / arithmetic branch (BUG FIX E)
        # ----------------------------------------------------------------
        if any(w in prompt_lower for w in ["calculate", "multiply", "*", "compute", "math", "divide"]):
            # Extract the actual expression from the prompt — never fabricate one
            expr = _extract_math_expression(prompt)
            if expr is None:
                # Safe fallback: use a neutral expression that evaluates to 0
                # so downstream tests can detect the absence of a real expression
                expr = "0"
            return {
                "thought": "User is asking for a calculation. I will call the calculator tool.",
                "tool_call": {
                    "tool_name": "calculator",
                    "parameters": {"expression": expr}
                },
                "draft_response": None
            }

        # ----------------------------------------------------------------
        # Weather lookup branch
        # ----------------------------------------------------------------
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

        # ----------------------------------------------------------------
        # Sensitive credential exposure in response
        # ----------------------------------------------------------------
        if any(w in prompt_lower for w in ["database status report", "reveal secret",
                                            "show api key", "dump credentials"]):
            return {
                "thought": "Drafting response containing server credentials as requested.",
                "tool_call": None,
                "draft_response": (
                    "Connected to staging database. "
                    "OpenAI API key: sk-proj-ab12cd34ef56gh78ij90kl12mn34op56qr78st90uv12wx34 "
                    "and AWS key AKIAIOSFODNN7EXAMPLE."
                )
            }

        # ----------------------------------------------------------------
        # Standard context-augmented response
        # ----------------------------------------------------------------
        doc_context = ""
        if retrieved_docs:
            doc_context = f" Based on retrieved document: {retrieved_docs[0].get('content', '')[:100]}..."

        return {
            "thought": "User query is standard. Providing direct conversational response.",
            "tool_call": None,
            "draft_response": (
                f"I have processed your request safely.{doc_context} "
                "How else may I assist you today?"
            )
        }
