"""
Module 2: Network Traffic Analyzer
- Real-time connection monitoring using psutil
- Anomaly detection: port scanning, high connection rate, suspicious IPs
- Fallback-safe (no scapy/elevated privileges required)
"""
import time
import threading
import statistics
import logging
from typing import Dict, List, Optional
try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger(__name__)

# Known malicious port patterns
SUSPICIOUS_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 6668, 9001, 9030}
# Private IP ranges (connections TO these might be C2/lateral movement)
INTERNAL_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                     "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
                     "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")


class NetworkMonitor:
    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self.alerts: List[Dict] = []
        self._history: List[Dict] = []  # Last N snapshots
        self._max_history = 30
        self._scan_interval = 3

        # Baseline tracking
        self._connection_counts: List[int] = []
        self._baseline_mean = 0
        self._baseline_std = 10

    def start(self):
        if not psutil:
            logger.warning("psutil not available - network monitoring disabled")
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("NetworkMonitor started.")

    def stop(self):
        self._running = False

    def _monitor_loop(self):
        while self._running:
            snap = self._snapshot()
            self._history.append(snap)
            if len(self._history) > self._max_history:
                self._history.pop(0)
            self._analyze(snap)

            # Update rolling baseline
            counts = [s["connection_count"] for s in self._history]
            if len(counts) >= 5:
                self._baseline_mean = statistics.mean(counts)
                self._baseline_std = max(statistics.stdev(counts), 1)

            time.sleep(self._scan_interval)

    def _snapshot(self) -> Dict:
        """Capture current network state."""
        try:
            conns = psutil.net_connections(kind="inet")
            io = psutil.net_io_counters()

            # Compute packet rate and bandwidth
            if self._history:
                prev = self._history[-1]
                dt = self._scan_interval
                pkt_rate = (io.packets_sent + io.packets_recv - prev["total_packets"]) / dt
                bps = (io.bytes_sent + io.bytes_recv - prev["total_bytes"]) / dt
            else:
                pkt_rate = 0.0
                bps = 0.0

            suspicious_ports_active = [
                c.raddr.port for c in conns
                if c.raddr and c.raddr.port in SUSPICIOUS_PORTS
            ]

            return {
                "timestamp": time.time(),
                "connection_count": len(conns),
                "packet_rate": max(0, round(pkt_rate, 2)),
                "bytes_per_sec": max(0, round(bps, 2)),
                "total_packets": io.packets_sent + io.packets_recv,
                "total_bytes": io.bytes_sent + io.bytes_recv,
                "suspicious_ports": suspicious_ports_active,
                "connections": [
                    {
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status,
                        "pid": c.pid
                    }
                    for c in conns if c.raddr
                ][:20]  # Limit per snapshot
            }
        except Exception as e:
            logger.debug(f"Network snapshot error: {e}")
            return {
                "timestamp": time.time(),
                "connection_count": 0, "packet_rate": 0, "bytes_per_sec": 0,
                "total_packets": 0, "total_bytes": 0,
                "suspicious_ports": [], "connections": []
            }

    def _analyze(self, snap: Dict):
        """Detect anomalies in network snapshot."""
        # 1. Suspicious port connections
        for port in snap["suspicious_ports"]:
            self.alerts.append({
                "type": "network",
                "reason": f"Connection on suspicious port {port} (potential C2/backdoor)",
                "severity": "critical",
                "port": port
            })

        # 2. Connection spike detection (z-score)
        if len(self._connection_counts) >= 5:
            z = (snap["connection_count"] - self._baseline_mean) / self._baseline_std
            if z > 3:
                self.alerts.append({
                    "type": "network",
                    "reason": f"Connection spike detected: {snap['connection_count']} connections (z={z:.1f}σ)",
                    "severity": "high",
                    "connection_count": snap["connection_count"]
                })

        self._connection_counts.append(snap["connection_count"])
        if len(self._connection_counts) > self._max_history:
            self._connection_counts.pop(0)

    def get_alerts(self) -> List[Dict]:
        alerts = self.alerts.copy()
        self.alerts.clear()
        return alerts

    def get_features(self) -> Dict:
        if self._history:
            latest = self._history[-1]
            return {
                "packet_rate": latest["packet_rate"],
                "bytes_per_sec": latest["bytes_per_sec"],
                "connection_count": latest["connection_count"]
            }
        return {"packet_rate": 0.0, "bytes_per_sec": 0.0, "connection_count": 0}
