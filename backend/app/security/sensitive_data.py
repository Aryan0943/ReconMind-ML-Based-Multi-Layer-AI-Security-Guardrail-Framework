import re
from typing import Tuple, List, Dict, Any

# Regex patterns for sensitive data detection
SENSITIVE_PATTERNS = [
    # Generic API Keys / Tokens
    (r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,64})['\"]?", "api_key", "[REDACTED_API_KEY]"),
    # OpenAI / Vendor Style Keys (sk-..., sk-proj-...)
    (r"\bsk-(?:proj-)?[a-zA-Z0-9_\-]{20,80}\b", "openai_key", "[REDACTED_API_KEY]"),
    # AWS Access Key ID
    (r"\bAKIA[0-9A-Z]{16}\b", "aws_access_key", "[REDACTED_AWS_KEY]"),
    # AWS Secret Key (40 chars)
    (r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", "aws_secret_key", "[REDACTED_AWS_SECRET]"),
    # GitHub Token (ghp_, gho_, etc.)
    (r"\bgh[pousr]_[A-Za-z0-9_]{36,255}\b", "github_token", "[REDACTED_GITHUB_TOKEN]"),
    # Private Key Headers
    (r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA|OPENSSH|DSA|EC)?\s*PRIVATE\s+KEY-----", "private_key", "[REDACTED_PRIVATE_KEY]"),
    # Email Addresses
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b", "email", "[REDACTED_EMAIL]"),
    # IPv4 Addresses (private / public)
    (r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b", "ip_address", "[REDACTED_IP]"),
    # Credit Card Numbers
    (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "credit_card", "[REDACTED_CARD]"),
    # Password in text or config
    (r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^'\"\s]{6,32})['\"]?", "password", "[REDACTED_PASSWORD]"),
]

def scan_and_redact_sensitive_data(text: str, redact: bool = True) -> Tuple[bool, str, List[Dict[str, Any]]]:
    """
    Scans text for sensitive patterns, secrets, PII, and credentials.
    Returns (has_leak, sanitized_text, findings).
    Note: The original secret values are NEVER recorded in the findings dict for privacy.
    """
    if not text or not isinstance(text, str):
        return False, text, []

    sanitized_text = text
    findings = []
    
    for pattern, pattern_type, replacement in SENSITIVE_PATTERNS:
        matches = list(re.finditer(pattern, sanitized_text))
        if matches:
            for match in matches:
                findings.append({
                    "type": pattern_type,
                    "description": f"Detected sensitive pattern: {pattern_type}",
                    "severity": "high" if "key" in pattern_type or "private" in pattern_type or "password" in pattern_type else "medium",
                    "details": {
                        "matched_type": pattern_type,
                        "position": [match.start(), match.end()]
                    }
                })
            if redact:
                sanitized_text = re.sub(pattern, replacement, sanitized_text)

    has_leak = len(findings) > 0
    return has_leak, sanitized_text, findings
