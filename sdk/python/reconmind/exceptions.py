from typing import Any

class ReconMindError(Exception):
    """Base exception for ReconMind SDK errors."""
    pass

class AuthenticationError(ReconMindError):
    """Raised when API key or authentication fails."""
    pass

class ConnectionError(ReconMindError):
    """Raised when connection to ReconMind API server fails or times out."""
    pass

class SecurityPolicyViolation(ReconMindError):
    """Raised when an operation is blocked by a critical security policy."""
    def __init__(self, message: str, scan_result: Any = None):
        super().__init__(message)
        self.scan_result = scan_result
