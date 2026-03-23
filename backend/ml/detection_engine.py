"""
Module 4: AI Detection Engine
- Multi-model ensemble: RandomForest + IsolationForest + rule-based
- Real-time inference with confidence scoring
- Feature normalization and fallback heuristics
"""
import os
import pickle
import logging
import numpy as np
from typing import Dict, List, Optional, Any

try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "cpu_usage", "memory_usage", "entropy",
    "packet_rate", "bytes_per_sec", "connection_count"
]

# Hard-coded rule thresholds (always active)
RULE_THRESHOLDS = {
    "entropy": 7.2,
    "cpu_usage": 90.0,
    "memory_usage": 90.0,
    "packet_rate": 5000.0,
}


class AIDetectionEngine:
    def __init__(self, model_dir: str = "models"):
        self.model_dir = model_dir
        self.rf_model: Optional[Any] = None
        self.iso_model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.ready = False

        if SKLEARN_AVAILABLE:
            self._load_models()
        else:
            logger.warning("sklearn not available - using rule-based detection only")

    def _load_models(self):
        rf_path = os.path.join(self.model_dir, "randomforest_model.pkl")
        iso_path = os.path.join(self.model_dir, "isoforest_model.pkl")
        scaler_path = os.path.join(self.model_dir, "scaler.pkl")

        if os.path.exists(rf_path):
            with open(rf_path, "rb") as f:
                self.rf_model = pickle.load(f)
            logger.info("✅ RandomForest model loaded")
            self.ready = True
        else:
            logger.warning(f"⚠️  RF model not found at {rf_path}")

        if os.path.exists(iso_path):
            with open(iso_path, "rb") as f:
                self.iso_model = pickle.load(f)
            logger.info("✅ IsolationForest model loaded")

        if os.path.exists(scaler_path):
            with open(scaler_path, "rb") as f:
                self.scaler = pickle.load(f)

    def predict(self, features: Dict[str, float]) -> Dict:
        """
        Run multi-model inference on feature dict.
        Returns: {is_threat, confidence, method, reason}
        """
        result = {
            "is_threat": False,
            "confidence": 0.0,
            "method": "none",
            "reason": "Normal activity",
            "severity": "info",
            "features": features
        }

        # ── 1. Rule-based (always runs) ──────────────────────────────
        rule_fired = False
        if features.get("entropy", 0) >= RULE_THRESHOLDS["entropy"]:
            result.update({
                "is_threat": True, "confidence": 0.95, "method": "rule",
                "reason": f"🔐 Ransomware signature: entropy={features['entropy']:.3f}",
                "severity": "critical"
            })
            rule_fired = True
        elif features.get("packet_rate", 0) >= RULE_THRESHOLDS["packet_rate"]:
            result.update({
                "is_threat": True, "confidence": 0.90, "method": "rule",
                "reason": f"🌊 DoS attack: packet_rate={features['packet_rate']:.0f}/s",
                "severity": "critical"
            })
            rule_fired = True
        elif features.get("cpu_usage", 0) >= RULE_THRESHOLDS["cpu_usage"]:
            result.update({
                "is_threat": True, "confidence": 0.75, "method": "rule",
                "reason": f"⚡ Resource exhaustion: cpu={features['cpu_usage']:.1f}%",
                "severity": "high"
            })
            rule_fired = True

        if rule_fired or not SKLEARN_AVAILABLE:
            return result

        # ── 2. RandomForest ──────────────────────────────────────────
        if self.rf_model is not None:
            try:
                X = self._feature_vector(features)
                rf_pred = self.rf_model.predict(X)[0]
                rf_proba = self.rf_model.predict_proba(X)[0]
                rf_conf = float(rf_proba[1] if len(rf_proba) > 1 else rf_proba[0])

                if rf_pred == 1 and rf_conf > 0.65:
                    cause = self._classify_cause(features)
                    result.update({
                        "is_threat": True,
                        "confidence": round(rf_conf, 4),
                        "method": "random_forest",
                        "reason": f"🤖 AI (RF) detected: {cause} (conf: {rf_conf:.1%})",
                        "severity": "high" if rf_conf < 0.85 else "critical"
                    })
                    return result
            except Exception as e:
                logger.debug(f"RF inference error: {e}")

        # ── 3. IsolationForest (anomaly) ─────────────────────────────
        if self.iso_model is not None:
            try:
                X = self._feature_vector(features)
                iso_pred = self.iso_model.predict(X)[0]  # -1 = anomaly
                iso_score = float(self.iso_model.decision_function(X)[0])

                if iso_pred == -1 and iso_score < -0.1:
                    confidence = min(0.5 + abs(iso_score), 0.9)
                    result.update({
                        "is_threat": True,
                        "confidence": round(confidence, 4),
                        "method": "isolation_forest",
                        "reason": f"🔍 Anomaly detected (IsoForest score: {iso_score:.3f})",
                        "severity": "warning"
                    })
            except Exception as e:
                logger.debug(f"IsoForest inference error: {e}")

        return result

    def _feature_vector(self, features: Dict):
        import pandas as pd
        row = {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}
        df = pd.DataFrame([row])
        if self.scaler is not None:
            return self.scaler.transform(df)
        return df.values

    def _classify_cause(self, features: Dict) -> str:
        if features.get("entropy", 0) > 6.0:
            return "Potential Ransomware"
        if features.get("packet_rate", 0) > 1000:
            return "Potential DoS/DDoS Attack"
        if features.get("cpu_usage", 0) > 80:
            return "CPU Resource Exhaustion"
        if features.get("connection_count", 0) > 100:
            return "Port Scan / Lateral Movement"
        return "Unknown Threat Pattern"

    @property
    def status(self) -> Dict:
        return {
            "rf_loaded": self.rf_model is not None,
            "iso_loaded": self.iso_model is not None,
            "scaler_loaded": self.scaler is not None,
            "ready": self.ready or self.rf_model is not None
        }
