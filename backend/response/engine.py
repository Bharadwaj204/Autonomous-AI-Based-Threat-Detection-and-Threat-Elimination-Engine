"""
Module 5: Autonomous Response Engine
- Terminates malicious processes (with safe guards)
- Quarantines suspicious files
- Blocks IPs via Windows Firewall (netsh) or iptables (Linux)
- All actions logged to forensics system
"""
import os
import shutil
import subprocess
import logging
import platform
from datetime import datetime
from typing import Dict, List, Optional

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

logger = logging.getLogger(__name__)

QUARANTINE_DIR = "data/quarantine"
# Never terminate these critical system processes
PROTECTED_PROCESSES = {
    "system", "lsass.exe", "csrss.exe", "wininit.exe", "services.exe",
    "smss.exe", "registry", "svchost.exe", "winlogon.exe", "python.exe",
    "python3", "uvicorn", "node"
}


class ResponseEngine:
    def __init__(self, dry_run: bool = False):
        """
        dry_run=True: log actions but don't actually execute (safe mode)
        """
        self.dry_run = dry_run
        self.action_log: List[Dict] = []
        os.makedirs(QUARANTINE_DIR, exist_ok=True)

    def handle_threat(self, threat: Dict) -> Dict:
        """
        Dispatch appropriate response based on threat type.
        Returns action result dict.
        """
        threat_type = threat.get("type", "unknown")
        logger.info(f"Handling threat: type={threat_type}, dry_run={self.dry_run}")

        if threat_type in ("file", "simulated_threat"):
            return self._quarantine_file(threat)
        elif threat_type == "process":
            return self._terminate_process(threat)
        elif threat_type == "network":
            return self._block_network(threat)
        else:
            return self._log_only(threat)

    def _quarantine_file(self, threat: Dict) -> Dict:
        path = threat.get("path", "")
        action = {
            "action": "quarantine",
            "target": path,
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "message": "",
            "dry_run": self.dry_run
        }

        if not path or not os.path.exists(path):
            action["message"] = f"File not found or already removed: {path}"
            action["success"] = True  # Treat as success since file is gone
            return action

        try:
            if self.dry_run:
                action["message"] = f"[DRY-RUN] Would quarantine: {path}"
                action["success"] = True
            else:
                basename = os.path.basename(path)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                dest = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}")
                shutil.move(path, dest)
                action["message"] = f"File quarantined: {path} → {dest}"
                action["success"] = True
                logger.warning(f"🔒 QUARANTINED: {path} → {dest}")
        except Exception as e:
            action["message"] = f"Quarantine failed: {e}"
            action["success"] = False
            logger.error(f"Quarantine error: {e}")

        self._log_action(action)
        return action

    def _terminate_process(self, threat: Dict) -> Dict:
        pid = threat.get("pid")
        name = (threat.get("name") or "").lower()

        action = {
            "action": "terminate_process",
            "target": f"PID {pid} ({name})",
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "message": "",
            "dry_run": self.dry_run
        }

        # Safety guard
        if name in PROTECTED_PROCESSES or any(p in name for p in PROTECTED_PROCESSES):
            action["message"] = f"Process '{name}' is protected - termination refused"
            action["success"] = False
            return action

        if not pid:
            action["message"] = "No PID provided"
            return action

        try:
            if self.dry_run:
                action["message"] = f"[DRY-RUN] Would terminate PID {pid} ({name})"
                action["success"] = True
            elif PSUTIL_OK:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=3)
                action["message"] = f"Process terminated: PID {pid} ({name})"
                action["success"] = True
                logger.warning(f"💀 TERMINATED: PID={pid} name={name}")
            else:
                action["message"] = "psutil not available for process termination"
        except psutil.NoSuchProcess:
            action["message"] = f"Process PID {pid} no longer exists"
            action["success"] = True
        except Exception as e:
            action["message"] = f"Termination failed: {e}"
            logger.error(f"Process termination error: {e}")

        self._log_action(action)
        return action

    def _block_network(self, threat: Dict) -> Dict:
        ip = threat.get("ip") or threat.get("raddr", "").split(":")[0]
        port = threat.get("port", "")

        action = {
            "action": "block_network",
            "target": f"IP: {ip or 'unknown'}, Port: {port}",
            "timestamp": datetime.now().isoformat(),
            "success": False,
            "message": "",
            "dry_run": self.dry_run
        }

        if not ip and not port:
            action["message"] = "No IP or port to block"
            return action

        try:
            if self.dry_run:
                action["message"] = f"[DRY-RUN] Would block IP={ip} Port={port}"
                action["success"] = True
            else:
                sys_platform = platform.system()
                if sys_platform == "Windows" and ip:
                    cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                           f"name=ThreatSentinel_Block_{ip}",
                           "dir=in", "action=block",
                           f"remoteip={ip}"]
                    subprocess.run(cmd, check=True, capture_output=True, timeout=10)
                    action["message"] = f"Blocked IP {ip} via Windows Firewall"
                    action["success"] = True
                    logger.warning(f"🚫 BLOCKED IP: {ip}")
                elif sys_platform == "Linux" and ip:
                    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                                   check=True, capture_output=True, timeout=10)
                    action["message"] = f"Blocked IP {ip} via iptables"
                    action["success"] = True
                else:
                    action["message"] = f"[LOGGED] Network threat from {ip or port} - manual block required"
                    action["success"] = True
        except Exception as e:
            action["message"] = f"Block failed (may need elevated privileges): {e}"
            action["success"] = False

        self._log_action(action)
        return action

    def _log_only(self, threat: Dict) -> Dict:
        action = {
            "action": "logged",
            "target": threat.get("type", "unknown"),
            "timestamp": datetime.now().isoformat(),
            "success": True,
            "message": f"Threat logged for review: {threat.get('reason', 'Unknown')}",
            "dry_run": self.dry_run
        }
        self._log_action(action)
        return action

    def _log_action(self, action: Dict):
        self.action_log.append(action)
        if len(self.action_log) > 500:
            self.action_log.pop(0)

    def get_action_log(self, limit: int = 50) -> List[Dict]:
        return self.action_log[-limit:]
