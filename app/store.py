"""审计结论的持久化存储：按审计标识冻结载荷与结论，支撑回放与刷新读取。"""

import hashlib
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audits (
    audit_id     TEXT PRIMARY KEY,
    payload_hash TEXT NOT NULL,
    payload      TEXT NOT NULL,
    result       TEXT NOT NULL,
    created_at   TEXT NOT NULL
)
"""


def canonical(payload):
    """规范化 JSON，保证同载荷哈希稳定。"""
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def hash_payload(payload):
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


class AuditStore:
    def __init__(self, db_path):
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)),
                        exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_SCHEMA)
        self._conn.commit()

    def get(self, audit_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT audit_id, payload_hash, payload, result, created_at"
                " FROM audits WHERE audit_id = ?", (audit_id,)).fetchone()
        if row is None:
            return None
        return {
            "audit_id": row[0],
            "payload_hash": row[1],
            "payload": json.loads(row[2]),
            "result": json.loads(row[3]),
            "created_at": row[4],
        }

    def put(self, audit_id, payload, result):
        record = {
            "audit_id": audit_id,
            "payload_hash": hash_payload(payload),
            "payload": payload,
            "result": result,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with self._lock:
            self._conn.execute(
                "INSERT INTO audits (audit_id, payload_hash, payload, result,"
                " created_at) VALUES (?, ?, ?, ?, ?)",
                (record["audit_id"], record["payload_hash"],
                 canonical(payload), json.dumps(result, ensure_ascii=False),
                 record["created_at"]))
            self._conn.commit()
        return record

    def close(self):
        with self._lock:
            self._conn.close()
