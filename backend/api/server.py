"""
Autonomous AI Based Threat Detection and Threat Elimination Engine - Main FastAPI Server (Upgraded)
Integrates all 10 autonomous security modules:
  1. File Monitoring
  2. Network Analyzer
  3. Process Analyzer
  4. AI Detection Engine (RF + IsoForest + Rules)
  5. Autonomous Response Engine
  6. Threat Intelligence Database
  7. Continuous Learning Pipeline
  8. Forensic Logger
  9. Ransomware Simulator
  10. Demo Engine
"""
import os
import json
import asyncio
import sys
from datetime import datetime
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from core.logging import setup_logger

# ── Configure logging ────────────────────────────────────────────────────────
logger = setup_logger("sentinel")

# ── Import modules ───────────────────────────────────────────────────────────
from monitoring.file_monitor import FileMonitor
from monitoring.network_monitor import NetworkMonitor
from monitoring.process_monitor import ProcessMonitor
from ml.detection_engine import AIDetectionEngine
from response.engine import ResponseEngine
from ml.threat_database import ThreatDatabase
from ml.learning_pipeline import LearningPipeline
from ml.forensic_logger import ForensicLogger
from ml.simulator import DemoEngine

# ── Module Init ──────────────────────────────────────────────────────────────
file_monitor    = FileMonitor(watch_dir=".", entropy_threshold=7.0)
network_monitor = NetworkMonitor()
process_monitor = ProcessMonitor(cpu_threshold=85.0, mem_threshold=80.0)
ai_engine       = AIDetectionEngine()
response_engine = ResponseEngine(safe_mode=True)
threat_db       = ThreatDatabase()
learning        = LearningPipeline()
forensics       = ForensicLogger()
demo_engine     = DemoEngine()

# Seed default IOCs
threat_db.seed_default_iocs()

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Autonomous AI Based Threat Detection and Threat Elimination Engine API",
    description="Autonomous AI Cybersecurity System - 10-Module Edition",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket Manager ────────────────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: List[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.active:
            self.active.remove(ws)

    async def broadcast(self, payload: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_text(json.dumps(payload, default=str))
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

manager = ConnectionManager()

# ── Shared state ─────────────────────────────────────────────────────────────
class State:
    threat_count: int = 0
    events: List[Dict] = []  # In-memory ring buffer (max 200)
    monitors: Dict = {
        "file": True, "network": False, "process": True,
        "ml_engine": False, "response": True, "forensics": True
    }

state = State()
state.monitors["ml_engine"] = ai_engine.status.get("ready", False)


def add_event(event_type: str, message: str,
              severity: str = "info", data: Dict = None) -> Dict:
    event = {
        "id": len(state.events) + 1,
        "timestamp": datetime.now().isoformat(),
        "type": event_type,
        "message": message,
        "severity": severity,
        "data": data or {}
    }
    state.events.insert(0, event)
    if len(state.events) > 200:
        state.events.pop()
    return event


# ── Monitoring Loop ───────────────────────────────────────────────────────────
async def monitoring_loop():
    logger.info("[START] Monitoring loop started")
    forensics.log("system", {"message": "Autonomous AI Based Threat Detection and Threat Elimination Engine started"}, "info")
    add_event("system", "Autonomous AI Based Threat Detection and Threat Elimination Engine started — all modules online", "info")

    # Start background sensors
    file_monitor.start()
    network_monitor.start()
    process_monitor.start()
    state.monitors["network"] = True

    tick = 0
    while True:
        try:
            tick += 1

            # ── Collect features from all sensors ──────────────────────
            file_feats    = file_monitor.get_features()
            net_feats     = network_monitor.get_features()
            proc_feats    = process_monitor.get_features()

            import psutil, random
            metrics = {
                "cpu_usage":       proc_feats.get("cpu_usage", 0),
                "memory_usage":    proc_feats.get("memory_usage", 0),
                "entropy":         file_feats.get("entropy", 0),
                "packet_rate":     net_feats.get("packet_rate", 0),
                "bytes_per_sec":   net_feats.get("bytes_per_sec", 0),
                "connection_count": net_feats.get("connection_count", 0)
            }

            # ── Broadcast metrics ───────────────────────────────────────
            await manager.broadcast({
                "type": "metrics",
                "data": metrics,
                "monitors": state.monitors,
                "threat_count": state.threat_count
            })

            # ── Drain monitor alerts ────────────────────────────────────
            for alert in file_monitor.get_alerts():
                await _handle_alert(alert, metrics)

            for alert in network_monitor.get_alerts():
                await _handle_alert(alert, metrics)

            for alert in process_monitor.get_alerts():
                await _handle_alert(alert, metrics)

            # ── AI multi-model inference ────────────────────────────────
            detection = ai_engine.predict(metrics)
            if detection["is_threat"]:
                await _handle_detection(detection, metrics)

            # Print continuous AI metrics to console cleanly
            if tick % 2 == 0:
                ml = detection.get("ml_metrics", {})
                rf_conf = ml.get("rf_confidence", 0.0)
                iso_score = ml.get("iso_score", 0.0)
                tag = "[THREAT]" if detection["is_threat"] else "[SAFE]"
                logger.info(
                    f"{tag} CPU:{metrics['cpu_usage']:>4.1f}% | "
                    f"RAM:{metrics['memory_usage']:>4.1f}% | "
                    f"Net:{metrics['packet_rate']:>4.0f}/s | "
                    f"ML_Conf:{rf_conf:>6.1%} | "
                    f"Anomaly:{iso_score:>6.2f}"
                )

            # ── Continuous learning: add normal/threat samples ──────────
            learning.add_sample(metrics, 1 if detection["is_threat"] else 0)

            # ── Retrain every 100 ticks if enough data ──────────────────
            if tick % 100 == 0:
                result = learning.retrain_if_ready()
                if result and result.get("status") == "success":
                    evt = add_event("system",
                        f"🔄 Model retrained — RF accuracy: {result['rf_accuracy']:.1%}",
                        "info", result)
                    await manager.broadcast({"type": "action", "data": evt})

            await asyncio.sleep(2.0)

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Monitoring loop error: {e}")
            await asyncio.sleep(5.0)


async def _handle_alert(alert: Dict, metrics: Dict):
    """Process an alert from any sensor."""
    state.threat_count += 1
    
    # Output cleanly as requested
    conf = alert.get("confidence", 0.8)
    reason = alert.get("reason", "Unknown alert")
    
    logger.info(f"Threat detected (confidence={conf:.2f})")
    print(f"[REASON] Monitor Alert: {reason}")
    
    evt = add_event(
        alert.get("type", "alert"),
        reason,
        alert.get("severity", "warning"),
        alert
    )
    forensics.log("sensor_alert", alert, alert.get("severity", "warning"))
    await manager.broadcast({"type": "threat_alert", "data": evt})

    # Add to threat DB
    threat_id = threat_db.record_threat({
        **alert,
        "method": "sensor",
        "confidence": conf,
        "features": metrics
    })

    # Auto-respond
    resp = response_engine.handle_threat(alert)
    if resp.get("message") and "[ACTION]" not in resp.get("message"):
        print(f"[ACTION] {resp['message']}")
    threat_db.record_action(threat_id, resp)
    threat_db.mark_mitigated(threat_id)
    resp_evt = add_event("action_taken", resp["message"], "info", resp)
    forensics.log("response_action", resp, "info")
    await manager.broadcast({"type": "action", "data": resp_evt})


async def _handle_detection(detection: Dict, metrics: Dict):
    """Process an AI detection result."""
    state.threat_count += 1
    
    # Format Explainability Output
    conf = detection.get("confidence", 0.0)
    explainability = detection.get("explainability", detection.get("reason", "Unknown abnormal AI behavior"))
    
    logger.info(f"Threat detected (confidence={conf:.2f})")
    print(f"[REASON] {explainability}")

    evt = add_event(
        "ml_threat",
        detection["reason"],
        detection["severity"],
        detection
    )
    forensics.log("ai_detection", detection, detection["severity"])
    await manager.broadcast({"type": "threat_alert", "data": evt})

    threat_id = threat_db.record_threat({
        "type": "ml_detection",
        "severity": detection["severity"],
        "method": detection["method"],
        "confidence": conf,
        "reason": detection["reason"],
        "features": metrics
    })

    # Instead of logging only, actually attempt to enforce global policies 
    # (Since global AI doesn't have a specific PID, the response engine will log it or quarantine highly anomalous state files tracked by the monitor)
    resp = response_engine.handle_threat(detection)
    if resp.get("message") and "[ACTION]" not in resp.get("message"):
        print(f"[ACTION] {resp['message']}")
    threat_db.record_action(threat_id, resp)


# ── Lifecycle ─────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def on_startup():
    asyncio.create_task(monitoring_loop())
    logger.info("Autonomous AI Based Threat Detection and Threat Elimination Engine API v2 started.")

@app.on_event("shutdown")
async def on_shutdown():
    file_monitor.stop()
    network_monitor.stop()
    process_monitor.stop()


# ── REST Endpoints ─────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"name": "Autonomous AI Based Threat Detection and Threat Elimination Engine", "version": "2.0", "status": "running"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "monitors": state.monitors,
        "threat_count": state.threat_count,
        "ml": ai_engine.status,
        "forensic_chain": "active"
    }


@app.get("/api/status")
def get_status():
    return {
        "monitors": state.monitors,
        "threat_count": state.threat_count,
        "total_events": len(state.events),
        "ai_engine": ai_engine.status,
        "db_stats": threat_db.get_stats(),
        "learning": learning.status
    }


@app.get("/api/events")
def get_events(limit: int = 100):
    return {"events": state.events[:limit], "total": len(state.events)}


@app.get("/api/threats")
def get_threats(limit: int = 50):
    return {
        "threats": threat_db.get_recent_threats(limit),
        "stats": threat_db.get_stats()
    }


@app.get("/api/quarantine")
def get_quarantine():
    q_dir = "data/quarantine"
    files = []
    if os.path.exists(q_dir):
        for f in os.listdir(q_dir):
            fpath = os.path.join(q_dir, f)
            try:
                files.append({
                    "name": f,
                    "size": os.path.getsize(fpath),
                    "quarantined_at": datetime.fromtimestamp(
                        os.path.getctime(fpath)
                    ).isoformat()
                })
            except Exception:
                pass
    return {"quarantined_files": files, "count": len(files)}


@app.get("/api/intel")
def get_intel(limit: int = 50):
    return {
        "iocs": threat_db.get_iocs(limit=limit),
        "total": len(threat_db.get_iocs(limit=10000))
    }


@app.get("/api/forensics")
def get_forensics(limit: int = 50):
    entries = forensics.get_entries_from_file(limit)
    chain = forensics.verify_chain()
    return {"entries": entries, "chain_integrity": chain}


@app.get("/api/metrics")
def get_metrics():
    from monitoring.process_monitor import ProcessMonitor
    proc = process_monitor.get_features()
    net = network_monitor.get_features()
    file = file_monitor.get_features()
    return {**proc, **net, **file}


@app.get("/api/processes")
def get_processes():
    return {"processes": process_monitor.get_top_processes(10)}


# ── Action Endpoints ──────────────────────────────────────────────────────────
@app.post("/api/response/test")
async def trigger_test():
    """Simulate a ransomware threat to demonstrate detection."""
    state.threat_count += 1
    mock = {
        "type": "simulated_threat",
        "path": "sandbox/test_ransomware.locked",
        "entropy": 7.95,
        "reason": "TEST: Ransomware file extension + high entropy"
    }
    threat_id = threat_db.record_threat({
        "type": "simulated", "severity": "critical",
        "method": "test", "confidence": 1.0,
        "reason": "Test threat triggered by user",
        "features": {}
    })
    forensics.log("test_trigger", mock, "critical")
    evt = add_event(
        "simulated_threat",
        "🚨 TEST: Simulated Ransomware Attack Detected",
        "critical",
        mock
    )
    await manager.broadcast({"type": "threat_alert", "data": evt})

    resp = response_engine._quarantine_file({"path": mock["path"]})
    threat_db.record_action(threat_id, resp)
    resp_evt = add_event("action_taken", f"✅ TEST Response: {resp['message']}", "info", resp)
    await manager.broadcast({"type": "action", "data": resp_evt})

    return {"status": "test_triggered", "threat_id": threat_id}


@app.post("/api/demo/ransomware")
async def start_ransomware_demo():
    """Run the full ransomware simulation demo."""
    if demo_engine.is_running:
        return {"status": "demo_already_running"}

    demo_alerts = []

    def on_event(evt: Dict):
        demo_alerts.append(evt)

    # Run in thread pool to avoid blocking
    import asyncio
    result = await asyncio.get_event_loop().run_in_executor(
        None, lambda: demo_engine.run_full_demo(on_event=on_event)
    )

    # Broadcast all demo events
    for alert in demo_alerts:
        state.threat_count += 1
        evt = add_event("ransomware_demo", alert["message"], "critical", alert)
        await manager.broadcast({"type": "threat_alert", "data": evt})

    final = add_event(
        "action_taken",
        f"✅ Demo: {result.get('files_created', 0)} ransomware files quarantined. Cleanup in 60s.",
        "info",
        result
    )
    await manager.broadcast({"type": "action", "data": final})

    return result


@app.post("/api/intel/add")
def add_ioc(ioc_type: str, value: str, source: str = "manual", confidence: float = 0.9):
    threat_db.add_ioc(ioc_type, value, source, confidence)
    return {"status": "added", "type": ioc_type, "value": value}


@app.get("/api/forensics/verify")
def verify_chain():
    return forensics.verify_chain()


@app.post("/api/learn/retrain")
async def force_retrain():
    """Manually trigger model retraining."""
    result = await asyncio.get_event_loop().run_in_executor(
        None, learning._retrain
    )
    return result or {"status": "not_enough_data"}


# ── WebSocket ─────────────────────────────────────────────────────────────────
@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    try:
        await ws.send_text(json.dumps({
            "type": "init",
            "status": "online",
            "data": {
                "events": state.events[:50],
                "monitors": state.monitors,
                "threat_count": state.threat_count,
                "status": "online"
            }
        }, default=str))
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(ws)
    except Exception as e:
        logger.error(f"WS error: {e}")
        manager.disconnect(ws)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.server:app", host="0.0.0.0", port=8000, reload=True)
