from typing import Dict, Any, Tuple, List

# Controlled Tool Specifications
# Supported tools:
# 1. calculator: basic arithmetic operations
# 2. document_search: search inside authorized doc pool
# 3. file_listing: list files ONLY inside designated demo sandbox directory
# 4. mock_email: send simulated email (requires special permission)

ALLOWED_TOOLS = {
    "calculator": {
        "allowed_roles": ["standard_user", "admin", "analyst"],
        "required_params": ["expression"],
        "description": "Safe math expression evaluator"
    },
    "document_search": {
        "allowed_roles": ["standard_user", "admin", "analyst"],
        "required_params": ["query"],
        "description": "Search index of approved documents"
    },
    "file_listing": {
        "allowed_roles": ["admin", "analyst"],
        "required_params": ["directory"],
        "description": "List files in sandbox directory"
    },
    "mock_email": {
        "allowed_roles": ["admin"],
        "required_params": ["recipient", "subject", "body"],
        "description": "Send mock notification email"
    },
    "weather_lookup": {
        "allowed_roles": ["standard_user", "admin", "analyst"],
        "required_params": ["location"],
        "description": "Look up weather for a given city or region"
    }
}

ALLOWED_DIRECTORIES = ["sandbox", "demo_docs", "public_reports"]

def validate_tool_request(
    tool_name: str,
    user_role: str,
    parameters: Dict[str, Any]
) -> Tuple[bool, str, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Validates a tool request against role-based access control and strict argument sanitization.
    Returns: (is_authorized, reason, findings, execution_result)
    Never executes arbitrary commands or uncontrolled code.
    """
    findings = []
    
    # 1. Check Tool Allowlist
    if tool_name not in ALLOWED_TOOLS:
        findings.append({
            "type": "unauthorized_tool",
            "description": f"Tool '{tool_name}' is not in the system allowlist",
            "severity": "critical"
        })
        return False, f"Unknown or disallowed tool: {tool_name}", findings, {}

    tool_meta = ALLOWED_TOOLS[tool_name]
    
    # 2. Check Role Authorization
    if user_role not in tool_meta["allowed_roles"]:
        findings.append({
            "type": "insufficient_permissions",
            "description": f"User role '{user_role}' is not authorized to execute tool '{tool_name}'",
            "severity": "high"
        })
        return False, f"Role '{user_role}' denied execution of '{tool_name}'", findings, {}

    # 3. Parameter Validation
    for req in tool_meta["required_params"]:
        if req not in parameters or parameters[req] is None or parameters[req] == "":
            findings.append({
                "type": "missing_parameter",
                "description": f"Missing required parameter '{req}' for tool '{tool_name}'",
                "severity": "medium"
            })
            return False, f"Missing required parameter: {req}", findings, {}

    # 4. Tool-Specific Semantic Validation
    if tool_name == "calculator":
        expr = str(parameters.get("expression", ""))
        # Strict allowlist of safe math characters
        import re
        if not re.match(r"^[\d\s\+\-\*\/\(\)\.\%]+$", expr):
            findings.append({
                "type": "unsafe_expression",
                "description": "Expression contains prohibited characters (possible code injection attempt)",
                "severity": "critical"
            })
            return False, "Dangerous math expression rejected", findings, {}
        try:
            # Safe eval with empty globals/locals
            res = eval(expr, {"__builtins__": None}, {})
            return True, "Calculator evaluated successfully", findings, {"result": res}
        except Exception as e:
            return False, f"Math calculation failed: {str(e)}", findings, {}

    elif tool_name == "file_listing":
        dir_name = str(parameters.get("directory", "")).strip().replace("\\", "/").strip("/")
        # Path traversal check
        if ".." in dir_name or dir_name.startswith("/") or dir_name.startswith("C:"):
            findings.append({
                "type": "path_traversal",
                "description": f"Path traversal attempt detected in directory '{dir_name}'",
                "severity": "critical"
            })
            return False, "Path traversal attempt blocked", findings, {}
        
        # Check against allowed demo directories
        if dir_name not in ALLOWED_DIRECTORIES and not any(dir_name.startswith(f"{d}/") for d in ALLOWED_DIRECTORIES):
            findings.append({
                "type": "unauthorized_directory",
                "description": f"Access to directory '{dir_name}' is forbidden",
                "severity": "high"
            })
            return False, f"Directory '{dir_name}' not in allowed sandbox", findings, {}
            
        return True, "Directory listing authorized", findings, {
            "files": ["report_q1.txt", "architecture_overview.pdf", "readme_public.md"]
        }

    elif tool_name == "document_search":
        query = str(parameters.get("query", ""))
        # Check for search manipulation attempts
        if any(bad in query.lower() for bad in ["drop table", "select *", "<script>", "ignore previous"]):
            findings.append({
                "type": "malicious_search_query",
                "description": "Search query contains injection patterns",
                "severity": "high"
            })
            return False, "Search query contained malicious patterns", findings, {}
        return True, "Document search authorized", findings, {
            "matches": [f"Matching reference for query '{query}': Document safe snippet #1"]
        }

    elif tool_name == "mock_email":
        recipient = str(parameters.get("recipient", ""))
        import re
        if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", recipient):
            findings.append({
                "type": "invalid_recipient",
                "description": "Recipient is not a valid email address",
                "severity": "medium"
            })
            return False, "Invalid recipient format", findings, {}
        return True, "Mock email dispatched safely", findings, {
            "status": "queued",
            "recipient": recipient,
            "subject": parameters.get("subject", "")
        }

    return True, "Tool authorized", findings, {"status": "executed"}
