"""
Module 6: Threat Intelligence Database
- SQLite-backed persistent store for threats, IOCs, and actions
- CRUD operations for threat log history
- IOC (Indicator of Compromise) registry
"""
import os
import sqlite3
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

DB_PATH = "data/threat_intel.db"


class ThreatDatabase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT,
                    severity TEXT,
                    method TEXT,
                    confidence REAL,
                    reason TEXT,
                    features TEXT,
                    mitigated INTEGER DEFAULT 0,
                    mitigated_at TEXT
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    threat_id INTEGER,
                    action_type TEXT,
                    target TEXT,
                    success INTEGER,
                    message TEXT,
                    FOREIGN KEY (threat_id) REFERENCES threats(id)
                );

                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL UNIQUE,
                    source TEXT,
                    confidence REAL DEFAULT 1.0,
                    created_at TEXT,
                    last_seen TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_threats_ts ON threats(timestamp);
                CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
            """)
        logger.info(f"✅ Threat database initialized at {self.db_path}")

    def record_threat(self, detection: Dict) -> int:
        with self._connect() as conn:
            cur = conn.execute("""
                INSERT INTO threats
                (timestamp, type, severity, method, confidence, reason, features)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now().isoformat(),
                detection.get("type", "unknown"),
                detection.get("severity", "unknown"),
                detection.get("method", "unknown"),
                detection.get("confidence", 0.0),
                detection.get("reason", ""),
                json.dumps(detection.get("features", {}))
            ))
            return cur.lastrowid

    def record_action(self, threat_id: int, action: Dict):
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO actions
                (timestamp, threat_id, action_type, target, success, message)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                action.get("timestamp", datetime.now().isoformat()),
                threat_id,
                action.get("action", "unknown"),
                action.get("target", ""),
                int(action.get("success", False)),
                action.get("message", "")
            ))

    def mark_mitigated(self, threat_id: int):
        with self._connect() as conn:
            conn.execute("""
                UPDATE threats SET mitigated=1, mitigated_at=?
                WHERE id=?
            """, (datetime.now().isoformat(), threat_id))

    def get_recent_threats(self, limit: int = 50) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute("""
                SELECT * FROM threats ORDER BY id DESC LIMIT ?
            """, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> Dict:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
            mitigated = conn.execute("SELECT COUNT(*) FROM threats WHERE mitigated=1").fetchone()[0]
            by_severity = {
                row[0]: row[1]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) FROM threats GROUP BY severity"
                ).fetchall()
            }
            return {
                "total_threats": total,
                "mitigated": mitigated,
                "active": total - mitigated,
                "by_severity": by_severity
            }

    # ── IOC Management ────────────────────────────────────────────────
    def add_ioc(self, ioc_type: str, value: str, source: str = "local", confidence: float = 1.0):
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO iocs
                (type, value, source, confidence, created_at, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ioc_type, value, source, confidence,
                  datetime.now().isoformat(), datetime.now().isoformat()))

    def check_ioc(self, value: str) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM iocs WHERE value=?", (value,)
            ).fetchone()
        return dict(row) if row else None

    def get_iocs(self, ioc_type: Optional[str] = None, limit: int = 100) -> List[Dict]:
        with self._connect() as conn:
            if ioc_type:
                rows = conn.execute(
                    "SELECT * FROM iocs WHERE type=? ORDER BY id DESC LIMIT ?",
                    (ioc_type, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM iocs ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    # Seed with sample known-bad IOCs
    def seed_default_iocs(self):
        sample_iocs = [
            ("ip", "185.220.101.34", "ThreatFox", 0.95),
            ("ip", "194.165.16.44", "ThreatFox", 0.90),
            ("domain", "malware-c2-server.xyz", "OpenPhish", 0.99),
            ("hash", "44d88612fea8a8f36de82e1278abb02f", "VirusTotal", 1.0),
            ("port", "4444", "Local Rules", 0.85),
        ]
        for ioc_type, value, source, conf in sample_iocs:
            self.add_ioc(ioc_type, value, source, conf)
