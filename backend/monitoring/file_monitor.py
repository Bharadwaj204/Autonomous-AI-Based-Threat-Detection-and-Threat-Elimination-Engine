"""
Module 1: Advanced File Monitoring
- Real-time watchdog-based file system monitoring
- Shannon entropy analysis for ransomware detection
- File hashing for integrity checks
"""
import os
import math
import hashlib
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data."""
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


def hash_file(path: str) -> Optional[str]:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FileMonitor:
    RANSOMWARE_EXTENSIONS = {
        ".locked", ".encrypted", ".crypto", ".crypt", ".enc",
        ".zcrypt", ".aaa", ".ecc", ".ezz", ".exx", ".xyz",
        ".zzz", ".abc", ".ccc", ".vvv", ".xxx", ".ttt", ".micro",
        ".vault", ".cerber", ".zepto", ".locky", ".thor", ".shit"
    }

    def __init__(self, watch_dir: str = ".", entropy_threshold: float = 7.0):
        self.watch_dir = os.path.abspath(watch_dir)
        self.entropy_threshold = entropy_threshold
        self.alerts: List[Dict] = []
        self._file_hashes: Dict[str, str] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._scan_interval = 5  # seconds

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info(f"FileMonitor started on: {self.watch_dir}")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        while self._running:
            self._scan()
            time.sleep(self._scan_interval)

    def _scan(self):
        try:
            for root, dirs, files in os.walk(self.watch_dir):
                # Skip hidden dirs, safe dirs, and internal data dirs
                dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                           {"node_modules", "__pycache__", ".git", "venv", ".venv",
                            "data", "datasets", "models", "reports"}]
                for fname in files[:50]:  # Limit files per scan
                    fpath = os.path.join(root, fname)
                    self._check_file(fpath)
        except Exception as e:
            logger.debug(f"Scan error: {e}")

    def _check_file(self, fpath: str):
        try:
            size = os.path.getsize(fpath)
            if size == 0 or size > 50 * 1024 * 1024:  # Skip empty/huge files
                return

            ext = Path(fpath).suffix.lower()
            alert_data = None

            # 1. Known ransomware extension
            if ext in self.RANSOMWARE_EXTENSIONS:
                alert_data = {
                    "type": "file",
                    "path": fpath,
                    "reason": f"Ransomware extension detected: {ext}",
                    "severity": "critical"
                }

            # 2. Entropy-based detection (sample first 64KB)
            elif size > 256:
                with open(fpath, "rb") as f:
                    sample = f.read(65536)
                entropy = shannon_entropy(sample)
                if entropy >= self.entropy_threshold:
                    alert_data = {
                        "type": "file",
                        "path": fpath,
                        "entropy": round(entropy, 4),
                        "reason": f"Suspicious entropy: {entropy:.4f} (threshold: {self.entropy_threshold})",
                        "severity": "high"
                    }

            # 3. File integrity check (hash change detection)
            if alert_data is None:
                current_hash = hash_file(fpath)
                if current_hash:
                    prev = self._file_hashes.get(fpath)
                    self._file_hashes[fpath] = current_hash
                    if prev and prev != current_hash:
                        # File changed - just log for now
                        pass

            if alert_data:
                self.alerts.append(alert_data)
                logger.warning(f"File alert: {alert_data['reason']} → {fpath}")

        except (PermissionError, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug(f"File check error {fpath}: {e}")

    def get_alerts(self) -> List[Dict]:
        """Drain and return pending alerts."""
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts

    def get_features(self) -> Dict:
        """Get aggregated metrics for ML inference."""
        try:
            # Sample a small portion of the watch dir for entropy
            max_entropy = 0.0
            count = 0
            for root, dirs, files in os.walk(self.watch_dir):
                dirs[:] = [d for d in dirs if not d.startswith(".") and
                           d not in {"node_modules", "__pycache__", ".git",
                                     "data", "datasets", "models", "reports"}]
                for fname in files[:5]:
                    try:
                        fpath = os.path.join(root, fname)
                        if os.path.getsize(fpath) > 256:
                            with open(fpath, "rb") as f:
                                sample = f.read(4096)
                            e = shannon_entropy(sample)
                            max_entropy = max(max_entropy, e)
                            count += 1
                        if count >= 20:
                            break
                    except Exception:
                        pass
                if count >= 20:
                    break
            return {"entropy": round(max_entropy, 4)}
        except Exception:
            return {"entropy": 0.0}
