import logging
import time
from typing import Dict, Any, Optional
from app.schemas.responses import SecurityScanResponse
from app.defenses.input_defense import InputDefense
from app.defenses.memory_defense import MemoryDefense
from app.defenses.retrieval_defense import RetrievalDefense
from app.defenses.tool_defense import ToolDefense
from app.defenses.output_defense import OutputDefense
from app.engine.policy_engine import PolicyEngine
from app.database.connection import db_manager

logger = logging.getLogger("reconmind.defense_manager")

class DefenseManager:
    """
    Centralized coordinator for ReconMind's 5 Security Defense Layers.
    Routes scan requests to specific defense layers, collects ML predictions
    and rule-based findings, applies layer-specific policies, enforces
    PASS / SANITIZE / BLOCK decisions, and persists security events.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(DefenseManager, cls).__new__(cls)
            cls._instance._init_layers()
        return cls._instance

    def _init_layers(self):
        self.policy_engine = PolicyEngine()
        self.layers = {
            "input": InputDefense(threshold=0.75),
            "memory": MemoryDefense(threshold=0.70),
            "retrieval": RetrievalDefense(threshold=0.65),
            "tool": ToolDefense(threshold=0.50),
            "output": OutputDefense(threshold=0.50),
        }
        # Synchronize layer thresholds from database policies
        self.refresh_policies()

    def refresh_policies(self):
        policies = db_manager.get_policies()
        for layer_name, p in policies.items():
            if layer_name in self.layers:
                self.layers[layer_name].set_threshold(p.get("threshold", 0.75))
                self.layers[layer_name].set_enabled(p.get("enabled", True))

    def coordinate_scan(
        self,
        layer_name: str,
        content: Any,
        log_event: bool = True,
        request_id: Optional[str] = None,
        **kwargs
    ) -> SecurityScanResponse:
        """
        Coordinates full inspection lifecycle for any of the 5 defense layers.
        """
        layer_name = layer_name.lower().strip()
        if layer_name not in self.layers:
            raise ValueError(f"Unknown defense layer '{layer_name}'. Available: {list(self.layers.keys())}")

        defense_layer = self.layers[layer_name]
        
        # 1. Execute layer inspection
        scan_response = defense_layer.inspect(content, **kwargs)
        if request_id:
            scan_response.request_id = request_id

        # 2. Apply centralized policy engine
        policies = db_manager.get_policies()
        layer_policy = policies.get(layer_name, {"enabled": True, "threshold": defense_layer.threshold, "default_action": "BLOCK"})
        
        final_action, final_reason = self.policy_engine.evaluate_decision(
            layer=layer_name,
            scan_response=scan_response,
            policy=layer_policy
        )

        scan_response.action = final_action
        scan_response.reason = final_reason

        # 3. Log security event to database
        if log_event:
            # Mask out any sensitive contents if output layer
            logged_input = "[REDACTED_SENSITIVE_CONTENT]" if layer_name == "output" else (
                str(content)[:500] if not isinstance(content, dict) else str(content)
            )
            
            event_record = {
                "event_id": scan_response.event_id,
                "request_id": scan_response.request_id or scan_response.event_id,
                "timestamp": scan_response.timestamp,
                "layer": scan_response.layer,
                "input_preview": logged_input,
                "prediction": scan_response.prediction,
                "category": scan_response.category,
                "confidence": scan_response.confidence,
                "action": scan_response.action,
                "reason": scan_response.reason,
                "latency_ms": scan_response.latency_ms,
                "model_version": scan_response.model_version
            }
            try:
                db_manager.insert_log(event_record)
            except Exception as e:
                logger.error(f"Failed to record security log: {e}")

        return scan_response

defense_manager = DefenseManager()
