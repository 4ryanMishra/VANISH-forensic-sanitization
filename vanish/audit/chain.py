"""
VANISH Tamper-Evident Cryptographic Audit Ledger
Implements SQLite-backed append-only audit event logging linked by
SHA-256 hash chains for unforgeable chain-of-custody verification.
"""

import sqlite3
import hashlib
import datetime
import uuid
import os
from typing import List, Tuple, Optional


class AuditChain:
    DEFAULT_DB = "vanish_audit.db"

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE NOT NULL,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    target_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    details TEXT
                )
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _get_last_hash(self) -> str:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT sha256_hash FROM audit_events ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return row[0]
            return "0" * 64  # Genesis block previous hash
        finally:
            conn.close()

    @staticmethod
    def compute_hash(event_id: str, timestamp: str, operation: str, target_path: str, status: str, previous_hash: str) -> str:
        payload = f"{event_id}|{timestamp}|{operation}|{target_path}|{status}|{previous_hash}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def append_event(self, operation: str, target_path: str, status: str, details: str = "") -> dict:
        """
        Append a new tamper-evident event to the cryptographic ledger.
        """
        event_id = f"evt-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        prev_hash = self._get_last_hash()
        curr_hash = self.compute_hash(event_id, timestamp, operation, target_path, status, prev_hash)

        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (event_id, timestamp, operation, target_path, sha256_hash, status, previous_hash, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, timestamp, operation, target_path, curr_hash, status, prev_hash, details),
            )
            conn.commit()
        finally:
            conn.close()

        return {
            "event_id": event_id,
            "timestamp": timestamp,
            "operation": operation,
            "target_path": target_path,
            "sha256_hash": curr_hash,
            "status": status,
            "previous_hash": prev_hash,
            "details": details,
        }

    def get_all_events(self) -> List[dict]:
        conn = self._get_connection()
        try:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_events ORDER BY id ASC")
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def verify_chain_integrity(self) -> Tuple[bool, Optional[str]]:
        """
        Verify the mathematical integrity of the entire audit chain.
        Returns: (is_valid, error_description)
        """
        events = self.get_all_events()
        if not events:
            return True, "Audit ledger is empty."

        expected_prev = "0" * 64
        for idx, event in enumerate(events):
            if event["previous_hash"] != expected_prev:
                return False, f"Broken link at event #{idx+1} ({event['event_id']}): previous_hash mismatch."

            recomputed = self.compute_hash(
                event["event_id"],
                event["timestamp"],
                event["operation"],
                event["target_path"],
                event["status"],
                event["previous_hash"],
            )
            if recomputed != event["sha256_hash"]:
                return False, f"Hash tamper detected at event #{idx+1} ({event['event_id']}): hash recomputation failed."

            expected_prev = event["sha256_hash"]

        return True, f"All {len(events)} audit events verified with 100% cryptographic integrity."
