import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger("reconmind.db")

# In-memory/File-based fallback store when MongoDB is not running
FALLBACK_STORE_DIR = Path(__file__).resolve().parent.parent.parent / "data_store"
FALLBACK_STORE_DIR.mkdir(parents=True, exist_ok=True)

class DatabaseManager:
    """
    Manages connections to MongoDB with automatic, transparent fallback
    to JSON local file storage if MongoDB service is unavailable.
    """
    def __init__(self):
        self.client = None
        self.db = None
        self.is_connected = False
        self.is_fallback = False
        self._fallback_logs_file = FALLBACK_STORE_DIR / "security_logs.json"
        self._fallback_memories_file = FALLBACK_STORE_DIR / "memories.json"
        self._fallback_policies_file = FALLBACK_STORE_DIR / "policies.json"
        self._init_files()
        
    def _init_files(self):
        for f in [self._fallback_logs_file, self._fallback_memories_file, self._fallback_policies_file]:
            if not f.exists():
                with open(f, "w", encoding="utf-8") as fp:
                    json.dump([], fp)

    def connect(self, uri: str = "mongodb://127.0.0.1:27017", db_name: str = "reconmind"):
        import os
        # If running in environment without live MongoDB daemon or fallback requested
        if os.environ.get("USE_DEV_FALLBACK_DB", "true").lower() == "true":
            logger.info("USE_DEV_FALLBACK_DB active. Initializing high-speed local storage engine.")
            self.client = None
            self.db = None
            self.is_connected = False
            self.is_fallback = True
            return

        try:
            import pymongo
            self.client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=500, connectTimeoutMS=500)
            self.client.admin.command('ping')
            self.db = self.client[db_name]
            self.is_connected = True
            self.is_fallback = False
            logger.info("Connected to MongoDB at %s", uri)
        except Exception as e:
            logger.warning("MongoDB ping failed (%s). Activating local file fallback store.", str(e))
            self.client = None
            self.db = None
            self.is_connected = False
            self.is_fallback = True

    def get_status(self) -> Dict[str, Any]:
        return {
            "connected": self.is_connected,
            "engine": "MongoDB Daemon" if self.is_connected else "Local JSON File Store (Development Fallback)",
            "mode": "mongodb" if self.is_connected else "local_fallback",
            "is_fallback": self.is_fallback,
            "storage_location": str(FALLBACK_STORE_DIR) if self.is_fallback else "mongodb://127.0.0.1:27017/reconmind",
            "warning": None if self.is_connected else "MongoDB is offline or bypassed. Using local JSON files.",
            "db_name": "reconmind" if self.is_connected else "local_json_store"
        }

    # Log Operations
    def insert_log(self, log_entry: Dict[str, Any]) -> str:
        if self.is_connected and self.db is not None:
            res = self.db.security_logs.insert_one(log_entry)
            return str(res.inserted_id)
        else:
            # File fallback
            entries = self.get_logs(limit=100000)
            entries.insert(0, log_entry)
            with open(self._fallback_logs_file, "w", encoding="utf-8") as f:
                json.dump(entries, f, indent=2, default=str)
            return log_entry.get("event_id", "fallback-id")

    def get_logs(self, limit: int = 50, skip: int = 0, layer: Optional[str] = None, action: Optional[str] = None) -> List[Dict[str, Any]]:
        if self.is_connected and self.db is not None:
            query = {}
            if layer:
                query["layer"] = layer
            if action:
                query["action"] = action
            cursor = self.db.security_logs.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit)
            return list(cursor)
        else:
            try:
                with open(self._fallback_logs_file, "r", encoding="utf-8") as f:
                    logs = json.load(f)
                if layer:
                    logs = [l for l in logs if l.get("layer") == layer]
                if action:
                    logs = [l for l in logs if l.get("action") == action]
                return logs[skip:skip + limit]
            except Exception:
                return []

    # Memory Operations
    def insert_memory(self, memory_entry: Dict[str, Any]) -> str:
        if self.is_connected and self.db is not None:
            res = self.db.memory_entries.insert_one(memory_entry)
            return str(res.inserted_id)
        else:
            memories = self.get_memories()
            memories.insert(0, memory_entry)
            with open(self._fallback_memories_file, "w", encoding="utf-8") as f:
                json.dump(memories, f, indent=2, default=str)
            return memory_entry.get("memory_id", "mem-id")

    def get_memories(self, session_id: Optional[str] = None, approved_only: bool = False) -> List[Dict[str, Any]]:
        """
        Retrieves memories. If approved_only is True, strictly filters for 'approved' status,
        guaranteeing that rejected or quarantined poisoning payloads never enter active agent context.
        """
        if self.is_connected and self.db is not None:
            query = {}
            if session_id:
                query["session_id"] = session_id
            if approved_only:
                query["status"] = "approved"
            cursor = self.db.memory_entries.find(query, {"_id": 0}).sort("created_at", -1)
            return list(cursor)
        else:
            try:
                with open(self._fallback_memories_file, "r", encoding="utf-8") as f:
                    memories = json.load(f)
                if session_id:
                    memories = [m for m in memories if m.get("session_id") == session_id]
                if approved_only:
                    memories = [m for m in memories if m.get("status") == "approved"]
                return memories
            except Exception:
                return []

    # Active Retrieval Index Storage (Clean vs Quarantined documents)
    def store_document_index(self, doc_record: Dict[str, Any]) -> None:
        """
        Stores document metadata. Only clean documents with PASS are placed in the active index.
        Blocked or quarantined documents are barred from retrieval.
        """
        doc_file = FALLBACK_STORE_DIR / "retrieval_documents.json"
        docs = []
        if doc_file.exists():
            try:
                with open(doc_file, "r", encoding="utf-8") as f:
                    docs = json.load(f)
            except Exception:
                docs = []
        docs.insert(0, doc_record)
        with open(doc_file, "w", encoding="utf-8") as f:
            json.dump(docs, f, indent=2, default=str)

    def get_active_documents(self, active_only: bool = True) -> List[Dict[str, Any]]:
        doc_file = FALLBACK_STORE_DIR / "retrieval_documents.json"
        if not doc_file.exists():
            return []
        try:
            with open(doc_file, "r", encoding="utf-8") as f:
                docs = json.load(f)
            if active_only:
                return [d for d in docs if d.get("overall_action") == "PASS"]
            return docs
        except Exception:
            return []

    # Policy Operations
    def get_policies(self) -> Dict[str, Any]:
        default_policies = {
            "input": {"enabled": True, "threshold": 0.75, "default_action": "BLOCK"},
            "memory": {"enabled": True, "threshold": 0.70, "default_action": "BLOCK"},
            "retrieval": {"enabled": True, "threshold": 0.65, "default_action": "QUARANTINE"},
            "tool": {"enabled": True, "threshold": 0.50, "default_action": "BLOCK"},
            "output": {"enabled": True, "threshold": 0.50, "default_action": "SANITIZE"},
        }
        if self.is_connected and self.db is not None:
            stored = list(self.db.security_policies.find({}, {"_id": 0}))
            if stored:
                return {p["layer"]: p for p in stored}
            return default_policies
        else:
            try:
                with open(self._fallback_policies_file, "r", encoding="utf-8") as f:
                    policies = json.load(f)
                if isinstance(policies, dict) and policies:
                    return policies
                return default_policies
            except Exception:
                return default_policies

    def update_policy(self, layer: str, update_data: Dict[str, Any]) -> Dict[str, Any]:
        current = self.get_policies()
        if layer not in current:
            current[layer] = {"enabled": True, "threshold": 0.75, "default_action": "BLOCK"}
        current[layer].update(update_data)
        
        if self.is_connected and self.db is not None:
            self.db.security_policies.update_one(
                {"layer": layer},
                {"$set": current[layer]},
                upsert=True
            )
        else:
            with open(self._fallback_policies_file, "w", encoding="utf-8") as f:
                json.dump(current, f, indent=2)
        return current[layer]

db_manager = DatabaseManager()
