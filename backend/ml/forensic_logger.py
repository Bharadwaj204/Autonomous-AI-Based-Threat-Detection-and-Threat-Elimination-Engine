"""
Module 8: Forensic Logging System
- Structured JSON logs with integrity hashes (SHA-256 chain)
- Tamper-evident linked log chain
- Auto-rotation and compression
"""
import os
import json
import gzip
import hashlib
import logging
from datetime import datetime
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

FORENSIC_LOG_DIR = "data/forensics"
FORENSIC_LOG_FILE = os.path.join(FORENSIC_LOG_DIR, "forensic_chain.jsonl")
MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB before rotation


class ForensicLogger:
    """
    Tamper-evident log chain.
    Each entry contains a hash of the previous entry,
    forming a linked chain that detects any tampering.
    """

    def __init__(self):
        os.makedirs(FORENSIC_LOG_DIR, exist_ok=True)
        self._prev_hash = self._get_last_hash()
        self._in_memory: List[Dict] = []

    def _get_last_hash(self) -> str:
        """Read the last hash from the log file."""
        if not os.path.exists(FORENSIC_LOG_FILE):
            return "GENESIS"
        try:
            last_line = ""
            with open(FORENSIC_LOG_FILE, "rb") as f:
                for line in f:
                    last_line = line.decode("utf-8", errors="ignore").strip()
            if last_line:
                entry = json.loads(last_line)
                return entry.get("hash", "GENESIS")
        except Exception:
            pass
        return "GENESIS"

    def _hash_entry(self, entry: Dict) -> str:
        """Hash entry content + previous hash for chain integrity."""
        content = json.dumps(entry, sort_keys=True) + self._prev_hash
        return hashlib.sha256(content.encode()).hexdigest()

    def log(self, event_type: str, data: Dict, severity: str = "info") -> Dict:
        """Write a forensic log entry."""
        entry = {
            "seq": len(self._in_memory) + 1,
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "severity": severity,
            "data": data,
            "prev_hash": self._prev_hash
        }
        entry_hash = self._hash_entry(entry)
        entry["hash"] = entry_hash
        self._prev_hash = entry_hash

        self._in_memory.append(entry)
        self._write(entry)
        return entry

    def _write(self, entry: Dict):
        try:
            # Auto-rotate if too large
            if (os.path.exists(FORENSIC_LOG_FILE) and
                    os.path.getsize(FORENSIC_LOG_FILE) > MAX_LOG_SIZE_BYTES):
                self._rotate()

            with open(FORENSIC_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            logger.error(f"Forensic write error: {e}")

    def _rotate(self):
        """Compress and rotate the log file."""
        try:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            rotated = os.path.join(FORENSIC_LOG_DIR, f"chain_{ts}.jsonl.gz")
            with open(FORENSIC_LOG_FILE, "rb") as f_in:
                with gzip.open(rotated, "wb") as f_out:
                    f_out.write(f_in.read())
            os.remove(FORENSIC_LOG_FILE)
            logger.info(f"Forensic log rotated to {rotated}")
        except Exception as e:
            logger.error(f"Log rotation error: {e}")

    def verify_chain(self) -> Dict:
        """Verify the integrity of the entire log chain."""
        if not os.path.exists(FORENSIC_LOG_FILE):
            return {"valid": True, "entries": 0, "message": "No log file"}

        prev = "GENESIS"
        count = 0
        try:
            with open(FORENSIC_LOG_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    stored_hash = entry.pop("hash", "")
                    expected = hashlib.sha256(
                        (json.dumps(entry, sort_keys=True) + prev).encode()
                    ).hexdigest()
                    if stored_hash != expected:
                        return {
                            "valid": False,
                            "entries_checked": count,
                            "message": f"Chain broken at entry {count + 1}!"
                        }
                    prev = stored_hash
                    count += 1
            return {"valid": True, "entries": count, "message": "Chain intact ✅"}
        except Exception as e:
            return {"valid": False, "entries": count, "message": str(e)}

    def get_recent(self, n: int = 50) -> List[Dict]:
        return self._in_memory[-n:]

    def get_entries_from_file(self, limit: int = 100) -> List[Dict]:
        entries = []
        if not os.path.exists(FORENSIC_LOG_FILE):
            return entries
        try:
            with open(FORENSIC_LOG_FILE, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except Exception:
                            pass
            return entries[-limit:]
        except Exception:
            return entries
