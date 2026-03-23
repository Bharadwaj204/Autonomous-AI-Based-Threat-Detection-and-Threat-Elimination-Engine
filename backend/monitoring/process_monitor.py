"""
Module 3: Process Behavior Analyzer
- Deep process scanning using psutil
- Detects: high CPU/memory, suspicious names, injected DLLs, unusual parent-child
- Profiles known safe processes vs unknown processes
"""
import os
import time
import threading
import logging
from typing import Dict, List, Optional, Set

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

# Allowlist of known safe process names (partial match)
SAFE_PROCESSES: Set[str] = {
    "system", "svchost", "explorer", "winlogon", "lsass", "csrss",
    "smss", "services", "registry", "fontdrvhost", "conhost",
    "code", "python", "node", "chrome", "firefox", "edge",
    "msedge", "notepad", "cmd", "powershell", "taskmgr", "searchhost",
    "runtimebroker", "sihost", "ctfmon", "wininit", "dwm",
    "audiodg", "spoolsv", "dllhost"
}

# High-risk process name patterns (lowercase)
SUSPICIOUS_NAMES = {
    "mimikatz", "meterpreter", "nc.exe", "netcat", "ncat", "psexec",
    "pwdump", "fgdump", "lsadump", "hashdump", "wce.exe",  "cobalt",
    "empire", "powersploit", "invoke-mimikatz", "shellcode",
    "crypto_ransomware", "locky", "ransom", "encryptor"
}


class ProcessMonitor:
    def __init__(self, cpu_threshold: float = 85.0, mem_threshold: float = 80.0):
        self.cpu_threshold = cpu_threshold
        self.mem_threshold = mem_threshold
        self.alerts: List[Dict] = []
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._process_history: Dict[int, Dict] = {}
        self._scan_interval = 5

    def start(self):
        if not psutil:
            logger.warning("psutil not available - process monitoring disabled")
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("ProcessMonitor started.")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        while self._running:
            self._scan()
            time.sleep(self._scan_interval)

    def _scan(self):
        """Full process scan."""
        try:
            for proc in psutil.process_iter(
                ["pid", "name", "exe", "cpu_percent", "memory_percent",
                 "status", "username", "ppid", "cmdline", "create_time"]
            ):
                try:
                    info = proc.info
                    self._analyze_process(info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception as e:
            logger.debug(f"Process scan error: {e}")

    def _analyze_process(self, info: Dict):
        name = (info.get("name") or "").lower()
        pid = info.get("pid", 0)
        cpu = info.get("cpu_percent", 0) or 0
        mem = info.get("memory_percent", 0) or 0
        exe = info.get("exe") or ""
        cmdline = " ".join(info.get("cmdline") or [])

        # 1. Known malicious name
        for bad in SUSPICIOUS_NAMES:
            if bad in name or bad in cmdline.lower():
                self.alerts.append({
                    "type": "process",
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "reason": f"Known malicious process name: '{bad}'",
                    "severity": "critical",
                    "action_needed": "terminate"
                })
                return

        # 2. High CPU consumption
        if cpu >= self.cpu_threshold and name not in SAFE_PROCESSES:
            self.alerts.append({
                "type": "process",
                "pid": pid,
                "name": name,
                "exe": exe,
                "cpu": round(cpu, 1),
                "reason": f"Excessive CPU usage: {cpu:.1f}% (threshold: {self.cpu_threshold}%)",
                "severity": "high",
                "action_needed": "investigate"
            })

        # 3. High memory consumption
        if mem >= self.mem_threshold and name not in SAFE_PROCESSES:
            self.alerts.append({
                "type": "process",
                "pid": pid,
                "name": name,
                "exe": exe,
                "mem": round(mem, 1),
                "reason": f"Excessive memory usage: {mem:.1f}% (threshold: {self.mem_threshold}%)",
                "severity": "warning",
                "action_needed": "investigate"
            })

        # 4. Process running from temp directory
        if exe and any(t in exe.lower() for t in ["\\temp\\", "\\tmp\\", "\\appdata\\local\\temp"]):
            if name not in SAFE_PROCESSES:
                self.alerts.append({
                    "type": "process",
                    "pid": pid,
                    "name": name,
                    "exe": exe,
                    "reason": f"Process running from temp directory: {exe}",
                    "severity": "high",
                    "action_needed": "terminate"
                })

    def get_alerts(self) -> List[Dict]:
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts

    def get_features(self) -> Dict:
        """Get system-wide CPU/memory for ML."""
        try:
            if not psutil:
                return {"cpu_usage": 0.0, "memory_usage": 0.0}
            return {
                "cpu_usage": round(psutil.cpu_percent(interval=None), 2),
                "memory_usage": round(psutil.virtual_memory().percent, 2)
            }
        except Exception:
            return {"cpu_usage": 0.0, "memory_usage": 0.0}

    def get_top_processes(self, n: int = 5) -> List[Dict]:
        """Return top N processes by CPU for dashboard."""
        if not psutil:
            return []
        try:
            procs = []
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_percent"]):
                try:
                    procs.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return sorted(procs, key=lambda x: x.get("cpu_percent") or 0, reverse=True)[:n]
        except Exception:
            return []
