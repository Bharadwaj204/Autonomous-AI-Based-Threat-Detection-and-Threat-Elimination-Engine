"""
Autonomous Response Policy Engine
Enforces safe action constraints based on risk severity and whitelists.
"""
import os
from typing import Dict, List, Any
from core.logging import setup_logger

logger = setup_logger(__name__)

class PolicyEngine:
    def __init__(self):
        # Prevent autonomous system from destroying the OS
        self.whitelisted_processes = [
            "svchost.exe", "explorer.exe", "System", "smss.exe", 
            "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", 
            "winlogon.exe", "python.exe", "node.exe"
        ]
        
        # Action mappings based on Risk Severity
        self.severity_actions = {
            "critical": ["terminate_process", "quarantine_file", "block_ip"],
            "high": ["quarantine_file", "terminate_process"],
            "warning": ["log_only"],
            "info": ["log_only"]
        }

    def evaluate_action_safety(self, action_type: str, target: Any) -> bool:
        """
        Verify if taking a specific action on a target is safe.
        """
        if action_type == "terminate_process":
            # Target is process name
            proc_name = str(target).lower()
            for safe_proc in self.whitelisted_processes:
                if safe_proc.lower() in proc_name:
                    logger.warning(f"[POLICY BLOCK] Attempted to kill whitelisted core process: {target}")
                    return False
            return True
            
        elif action_type == "quarantine_file":
            # Target is absolute path
            target_path = str(target).lower()
            if "windows\\system32" in target_path or "boot" in target_path:
                logger.warning(f"[POLICY BLOCK] Attempted to quarantine critical system path: {target}")
                return False
            return True

        elif action_type == "block_ip":
            # Target is IP string
            if target in ["127.0.0.1", "0.0.0.0", "localhost"]:
                logger.warning(f"[POLICY BLOCK] Attempted to block loopback IP: {target}")
                return False
            return True
            
        return True

    def get_recommended_actions(self, severity: str) -> List[str]:
        """Return the authorized autonomous actions for a given severity."""
        return self.severity_actions.get(severity, ["log_only"])
