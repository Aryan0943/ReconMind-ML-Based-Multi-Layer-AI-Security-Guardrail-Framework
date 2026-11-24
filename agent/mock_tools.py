import os
import re
from typing import Dict, Any, Tuple

class MockSandboxedTools:
    """
    Deterministic simulated tool executor for the ReconMind Agent.
    All calls are passed through ReconMind Layer 4 before execution.
    Direct invocation without defense validation is strictly prevented.
    """
    @staticmethod
    def calculator(expression: str) -> Dict[str, Any]:
        # Clean mathematical evaluation
        try:
            # Only allow digits, operators, parentheses, whitespace
            if not re.match(r"^[\d\s\+\-\*\/\(\)\.]+$", expression):
                return {"success": False, "error": "Invalid character in expression"}
            result = eval(expression, {"__builtins__": {}}, {})
            return {"success": True, "result": result}
        except Exception as e:
            return {"success": False, "error": str(e)}

    @staticmethod
    def weather_lookup(location: str) -> Dict[str, Any]:
        return {
            "success": True,
            "location": location,
            "condition": "Sunny with light breeze",
            "temperature_c": 22.5,
            "humidity": "45%"
        }

    @staticmethod
    def read_file(path: str) -> Dict[str, Any]:
        # Mock file reader - in production sandboxed, but should be blocked if path traversal
        return {
            "success": True,
            "path": path,
            "content": f"[Simulated Content of {path}]"
        }

    @staticmethod
    def database_admin_tool(command: str) -> Dict[str, Any]:
        return {
            "success": True,
            "command": command,
            "status": "Admin command executed (Simulated)"
        }
