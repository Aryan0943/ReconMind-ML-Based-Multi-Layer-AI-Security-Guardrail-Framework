import re
from typing import List, Dict, Any, Tuple

# Security Attack Signatures and Heuristic Patterns
INJECTION_PATTERNS = [
    # Instruction Overrides
    (r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|commands)\b", "instruction_override", "critical"),
    (r"(?i)\bdisregard\s+(all\s+)?(previous|prior|system)\s+(instructions|directives)\b", "instruction_override", "critical"),
    (r"(?i)\bforget\s+(everything\s+)?(you\s+(were|have\s+been)\s+told|prior\s+instructions)\b", "instruction_override", "critical"),
    
    # System Prompt Extraction / Leakage
    (r"(?i)\b(reveal|print|display|output|show|repeat)\s+(the\s+)?(system\s+prompt|initial\s+instructions|secret\s+instructions|system\s+message)\b", "system_extraction", "high"),
    (r"(?i)\bwhat\s+(is|are)\s+your\s+(exact\s+)?(instructions|system\s+prompt|internal\s+rules)\b", "system_extraction", "high"),
    
    # Jailbreak / Roleplay Manipulation
    (r"(?i)\byou\s+are\s+now\s+(DAN|unrestricted|in\s+developer\s+mode|freed|jailbroken)\b", "jailbreak_attempt", "critical"),
    (r"(?i)\b(DAN\s+mode|developer\s+mode\s+enabled|always\s+comply|bypass\s+all\s+safety\s+filters)\b", "jailbreak_attempt", "critical"),
    (r"(?i)\bdo\s+anything\s+now\b", "jailbreak_attempt", "critical"),
    (r"(?i)\bpretend\s+you\s+have\s+no\s+(morals|rules|limitations|filters)\b", "jailbreak_attempt", "critical"),
    
    # Indirect / Delimiter Injection
    (r"(?i)\[system\]\s*:\s*override", "indirect_delimiter", "high"),
    (r"(?i)<\s*system\s*>\s*(ignore|override|new\s+rule)", "indirect_delimiter", "high"),
    (r"(?i)```\s*system\s*(instruction|command)", "indirect_delimiter", "high"),
    (r"(?i)###\s*(instruction|system|override)", "indirect_delimiter", "medium"),
    
    # Memory Poisoning
    (r"(?i)\balways\s+remember\s+that\s+you\s+must\s+(ignore|bypass|disobey)\b", "memory_poisoning", "critical"),
    (r"(?i)\bfrom\s+now\s+on\s*,\s*every\s+time\s+user\s+asks\s*,\s*you\s+must\b", "memory_poisoning", "high"),
    (r"(?i)\bpermanently\s+replace\s+your\s+identity\s+with\b", "memory_poisoning", "critical"),

    # Privilege Escalation & Role Manipulation (Imperative Attack Intent)
    # Catches attempts to demand, assign, elevate, switch, or assume admin/privileged status
    (r"(?i)\b(?:give|grant|assign|elevate|assume|switch|change|set)\s+(?:me|my\s+(?:role|account|permissions?|status)|user)\s+(?:to\s+)?(?:an?\s+)?(?:admin(?:istrator)?|root|superuser|privileged(?:\s+user|\s+account)?)(?:\s+(?:privileges?|rights?|access|role))?\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:make|consider|treat)\s+me\s+(?:as\s+)?(?:an?\s+)?(?:admin(?:istrator)?|root|superuser|privileged(?:\s+user|\s+account)?)\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:elevate|escalate)\s+(?:my\s+)?(?:privileges?|access(?:\s+level)?|permissions?)\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:grant|give)\s+(?:me\s+)?unrestricted\s+access\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:override|bypass)\s+(?:the\s+)?(?:current\s+)?(?:user\s+)?(?:permissions?|access\s+controls?|authorization|privileges?)\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:treat|use)\s+my\s+account\s+as\s+(?:a\s+)?privileged\s+account\b", "privilege_escalation", "critical"),
    # Generalized semantic variations (assertions of unverified privilege, tier promotions, root operation, presupposed authorization)
    (r"(?i)\b(?:i\s+should\s+have|give\s+me|grant\s+me)\s+unrestricted\s+(?:permissions?|privileges?|access|rights?)\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:promote|upgrade)\s+(?:this|my)\s+account\s+to\s+(?:the\s+)?(?:highest|admin|privileged|root)\s+(?:access\s+)?tier\b", "privilege_escalation", "critical"),
    (r"(?i)\b(?:current\s+session|session)\s+should\s+operate\s+with\s+(?:root|admin|superuser|elevated)\s+(?:privileges?|permissions?|access)\b", "privilege_escalation", "critical"),
    (r"(?i)\bassume\s+(?:that\s+)?(?:authorization|permission|admin\s+access)\s+(?:has\s+already\s+been|is)\s+granted\b", "privilege_escalation", "critical"),
]

def scan_rule_patterns(text: str) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Scans input text against deterministic security rules.
    Returns (has_violation, findings).
    """
    findings = []
    if not text or not isinstance(text, str):
        return False, findings
        
    for pattern, rule_type, severity in INJECTION_PATTERNS:
        match = re.search(pattern, text)
        if match:
            findings.append({
                "type": rule_type,
                "description": f"Triggered security heuristic: '{match.group(0)}'",
                "severity": severity,
                "details": {
                    "matched_pattern": rule_type,
                    "matched_text": match.group(0),
                    "start": match.start(),
                    "end": match.end()
                }
            })
            
    has_violation = len(findings) > 0
    return has_violation, findings
