from fastapi import APIRouter
from app.database.connection import db_manager
from app.schemas.responses import DashboardStats

router = APIRouter(prefix="/dashboard", tags=["Dashboard Metrics"])

@router.get("/stats", response_model=DashboardStats)
def get_dashboard_statistics():
    """
    Aggregates real-time security telemetry from the persistent database.
    Calculates total scanned requests, threats detected, actions taken,
    and layer activity distribution.
    """
    logs = db_manager.get_logs(limit=10000)
    
    total_scanned = len(logs)
    threats_detected = sum(1 for l in logs if l.get("prediction") == "malicious")
    requests_blocked = sum(1 for l in logs if l.get("action") == "BLOCK")
    requests_sanitized = sum(1 for l in logs if l.get("action") == "SANITIZE")
    requests_passed = sum(1 for l in logs if l.get("action") == "PASS")
    
    layer_activity = {"input": 0, "memory": 0, "retrieval": 0, "tool": 0, "output": 0}
    threat_distribution = {}
    action_distribution = {"PASS": requests_passed, "SANITIZE": requests_sanitized, "BLOCK": requests_blocked}
    latencies = []

    for l in logs:
        ly = l.get("layer", "input")
        if ly in layer_activity:
            layer_activity[ly] += 1
        elif "retrieval" in ly:
            layer_activity["retrieval"] += 1
            
        cat = l.get("category", "benign")
        if cat != "benign":
            threat_distribution[cat] = threat_distribution.get(cat, 0) + 1
            
        if "latency_ms" in l and l["latency_ms"] is not None:
            try:
                latencies.append(float(l["latency_ms"]))
            except (ValueError, TypeError):
                pass

    avg_latency = float(sum(latencies) / len(latencies)) if latencies else 0.0

    return DashboardStats(
        total_scanned=total_scanned,
        threats_detected=threats_detected,
        requests_blocked=requests_blocked,
        requests_sanitized=requests_sanitized,
        requests_passed=requests_passed,
        layer_activity=layer_activity,
        threat_distribution=threat_distribution,
        action_distribution=action_distribution,
        avg_latency_ms=round(avg_latency, 2)
    )

@router.get("/activity")
def get_recent_activity():
    """
    Returns latest 10 security events for timeline view.
    """
    recent = db_manager.get_logs(limit=10)
    return {
        "success": True,
        "activity": recent
    }
