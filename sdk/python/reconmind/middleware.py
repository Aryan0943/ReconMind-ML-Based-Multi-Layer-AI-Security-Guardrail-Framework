import functools
from typing import Callable, Any
from reconmind.client import ReconMindClient
from reconmind.exceptions import SecurityPolicyViolation

class ReconMindGuardMiddleware:
    """
    Middleware decorator wrapper for AI functions and agent tool methods.
    Automatically intercepts malicious inputs before execution and redacts output secrets.
    """
    def __init__(self, client: ReconMindClient):
        self.client = client

    def guard_prompt(self, arg_index: int = 0) -> Callable:
        """Decorator to automatically validate input prompt parameter."""
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                prompt = kwargs.get("prompt") if "prompt" in kwargs else (args[arg_index] if len(args) > arg_index else None)
                if prompt and isinstance(prompt, str):
                    res = self.client.scan_input(prompt)
                    if res.is_blocked:
                        raise SecurityPolicyViolation(f"Input blocked by ReconMind Guardrail: {res.reason}", scan_result=res)
                
                # Execute underlying AI function
                response = func(*args, **kwargs)

                # Scan and sanitize output
                if isinstance(response, str):
                    out_res = self.client.scan_output(response)
                    if out_res.is_blocked:
                        raise SecurityPolicyViolation(f"Output blocked by ReconMind Guardrail: {out_res.reason}", scan_result=out_res)
                    if out_res.is_sanitized and out_res.sanitized_content:
                        return out_res.sanitized_content
                return response
            return wrapper
        return decorator
