"""
Module 9 & 10: Ransomware Simulator + Demo Engine
- Simulates ransomware behavior safely (no actual damage)
- Creates fake encrypted files in a sandboxed temp directory
- Triggers all detection mechanisms for demo purposes
"""
import os
import math
import time
import random
import string
import hashlib
import logging
import threading
from datetime import datetime
from typing import Dict, List, Callable, Optional

logger = logging.getLogger(__name__)

DEMO_SANDBOX_DIR = "data/demo_sandbox"


def _high_entropy_content(size: int = 8192) -> bytes:
    """Generate pseudo-random bytes that look like encrypted data."""
    return bytes(random.getrandbits(8) for _ in range(size))


def _shannon_entropy(data: bytes) -> float:
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values() if c > 0)


class RansomwareSimulator:
    """
    Safe ransomware simulation for demonstration.
    All files are created in a sandboxed directory.
    No actual system files are touched.
    """
    RANSOM_EXTENSIONS = [".locked", ".encrypted", ".enc", ".crypt"]

    def __init__(self, sandbox_dir: str = DEMO_SANDBOX_DIR):
        self.sandbox_dir = sandbox_dir
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.created_files: List[str] = []
        os.makedirs(self.sandbox_dir, exist_ok=True)

    def simulate_attack(
        self,
        num_files: int = 5,
        on_file_created: Optional[Callable[[str, float], None]] = None
    ) -> Dict:
        """
        Run a controlled ransomware simulation.
        Creates N files with ransomware extensions and high entropy content.
        """
        results = []
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create a fake ransom note first
        note_path = os.path.join(self.sandbox_dir, f"README_DECRYPT_{ts}.txt")
        with open(note_path, "w") as f:
            f.write(
                "YOUR FILES HAVE BEEN ENCRYPTED!\n"
                "This is a SIMULATION for Autonomous AI Based Threat Detection and Threat Elimination Engine demo purposes.\n"
                "No real files were harmed.\n"
                f"Simulated at: {datetime.now().isoformat()}\n"
            )
        self.created_files.append(note_path)
        results.append({"path": note_path, "type": "ransom_note"})

        # Create fake encrypted files
        for i in range(num_files):
            ext = random.choice(self.RANSOM_EXTENSIONS)
            fname = f"document_{i:03d}{ext}"
            fpath = os.path.join(self.sandbox_dir, fname)

            content = _high_entropy_content(random.randint(1024, 16384))
            entropy = _shannon_entropy(content)

            with open(fpath, "wb") as f:
                f.write(content)

            self.created_files.append(fpath)
            results.append({
                "path": fpath,
                "entropy": round(entropy, 4),
                "size": len(content),
                "type": "encrypted_file"
            })

            if on_file_created:
                on_file_created(fpath, entropy)

            time.sleep(0.1)  # Stagger creation

        logger.warning(f"⚠️  Ransomware simulation: created {len(results)} files in {self.sandbox_dir}")

        return {
            "simulated_at": datetime.now().isoformat(),
            "sandbox": self.sandbox_dir,
            "files_created": len(results),
            "files": results
        }

    def cleanup(self) -> int:
        """Remove all simulated files."""
        removed = 0
        for fpath in self.created_files:
            try:
                if os.path.exists(fpath):
                    os.remove(fpath)
                    removed += 1
            except Exception:
                pass
        self.created_files.clear()
        try:
            if os.path.exists(self.sandbox_dir) and not os.listdir(self.sandbox_dir):
                os.rmdir(self.sandbox_dir)
        except Exception:
            pass
        logger.info(f"Ransomware simulation cleanup: removed {removed} files")
        return removed


class DemoEngine:
    """
    High-level demo orchestrator that runs the full attack simulation
    and triggers detection via callback hooks.
    """

    def __init__(self):
        self.simulator = RansomwareSimulator()
        self._demo_in_progress = False

    def run_full_demo(self, on_event: Optional[Callable[[Dict], None]] = None) -> Dict:
        """
        Full demo sequence:
        1. Simulate ransomware file creation
        2. Report events via callback
        3. Auto-cleanup after 60s
        """
        if self._demo_in_progress:
            return {"status": "demo_already_running"}

        self._demo_in_progress = True
        events = []

        def file_cb(path: str, entropy: float):
            event = {
                "type": "ransomware_file",
                "path": path,
                "entropy": entropy,
                "message": f"🔐 Ransomware file detected: {os.path.basename(path)} (entropy={entropy:.3f})",
                "severity": "critical"
            }
            events.append(event)
            if on_event:
                on_event(event)

        # Run simulation
        sim_result = self.simulator.simulate_attack(
            num_files=5,
            on_file_created=file_cb
        )

        # Schedule auto-cleanup
        def cleanup_later():
            time.sleep(60)
            self.simulator.cleanup()
            self._demo_in_progress = False
            logger.info("Demo sandbox cleaned up.")

        threading.Thread(target=cleanup_later, daemon=True).start()

        return {
            "status": "demo_started",
            "simulation": sim_result,
            "events_triggered": len(events),
            "cleanup_in_seconds": 60
        }

    @property
    def is_running(self) -> bool:
        return self._demo_in_progress
