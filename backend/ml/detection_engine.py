"""
Module: AI Detection Engine
Refactored for Production
- Uses pathological paths (pathlib)
- Clean consistent Pandas DataFrame usage
- Combines IsoForest with RandomForest cleanly
- Centralized core.logging
"""
import pickle
import numpy as np
from typing import Dict, List, Optional, Any
from pathlib import Path

from core.logging import setup_logger

try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

logger = setup_logger(__name__)

FEATURE_COLUMNS = [
    "cpu_usage", "memory_usage", "entropy",
    "packet_rate", "bytes_per_sec", "connection_count"
]

RULE_THRESHOLDS = {
    "entropy": 7.2,
    "cpu_usage": 90.0,
    "memory_usage": 90.0,
    "packet_rate": 5000.0,
}


class AIDetectionEngine:
    def __init__(self, backend_root: Optional[Path] = None):
        if backend_root is None:
            self.backend_root = Path(__file__).resolve().parent.parent
        else:
            self.backend_root = Path(backend_root)

        self.model_dir = self.backend_root / "models"
        self.rf_model = None
        self.iso_model = None
        self.scaler = None
        self.ready = False

        if SKLEARN_AVAILABLE:
            self._load_models()
        else:
            logger.warning("[WARN] sklearn not available - using rule-based detection only")

    def _load_models(self):
        rf_path = self.model_dir / "randomforest_model.pkl"
        iso_path = self.model_dir / "isoforest_model.pkl"
        scaler_path = self.model_dir / "scaler.pkl"

        try:
            if rf_path.exists():
                with open(rf_path, "rb") as f:
                    self.rf_model = pickle.load(f)
                logger.info(f"[OK] RandomForest model loaded from {rf_path.name}")
                self.ready = True
            else:
                logger.warning(f"[WARN] RF model not found at {rf_path}")

            if iso_path.exists():
                with open(iso_path, "rb") as f:
                    self.iso_model = pickle.load(f)
                logger.info(f"[OK] IsolationForest model loaded from {iso_path.name}")

            if scaler_path.exists():
                with open(scaler_path, "rb") as f:
                    self.scaler = pickle.load(f)
                logger.info(f"[OK] Scaler loaded from {scaler_path.name}")
        except Exception as e:
            logger.error(f"[ERROR] Failed to load models cleanly: {e}")
            raise RuntimeError(f"Model loading exception: {e}")

    def predict(self, features: Dict[str, float]) -> Dict:
        """
        Run multi-model inference on feature dict.
        Combines IsolationForest anomaly scoring with RF logic.
        """
        result = {
            "is_threat": False,
            "confidence": 0.0,
            "method": "none",
            "reason": "Normal activity",
            "severity": "info",
            "features": features,
            "ml_metrics": {"rf_confidence": 0.0, "iso_score": 0.0}
        }

        # ── 1. Rule-based (always runs as safety fallback) ──
        rule_fired = False
        if features.get("entropy", 0) >= RULE_THRESHOLDS["entropy"]:
            result.update({
                "is_threat": True, "confidence": 0.95, "method": "rule",
                "reason": f"[RANSOMWARE] Signature match: entropy={features['entropy']:.3f}",
                "severity": "critical"
            })
            rule_fired = True
        elif features.get("packet_rate", 0) >= RULE_THRESHOLDS["packet_rate"]:
            result.update({
                "is_threat": True, "confidence": 0.90, "method": "rule",
                "reason": f"[DOS] High packet rate: {features['packet_rate']:.0f}/s",
                "severity": "critical"
            })
            rule_fired = True
        elif features.get("cpu_usage", 0) >= RULE_THRESHOLDS["cpu_usage"]:
            result.update({
                "is_threat": True, "confidence": 0.75, "method": "rule",
                "reason": f"[EXHAUSTION] High CPU: {features['cpu_usage']:.1f}%",
                "severity": "high"
            })
            rule_fired = True

        if not SKLEARN_AVAILABLE:
            return result

        # ── 2. RandomForest + IsolationForest Combined ──
        try:
            X_df = self._feature_vector(features)

            # Get Anomaly Score First
            iso_score = 0.0
            iso_pred = 1
            if self.iso_model is not None:
                iso_pred = self.iso_model.predict(X_df)[0]
                iso_score = float(self.iso_model.decision_function(X_df)[0])
                result["ml_metrics"]["iso_score"] = iso_score

            # Get RF Probability
            rf_conf = 0.0
            rf_pred = 0
            if self.rf_model is not None:
                rf_pred = self.rf_model.predict(X_df)[0]
                rf_proba = self.rf_model.predict_proba(X_df)[0]
                rf_conf = float(rf_proba[1] if len(rf_proba) > 1 else rf_proba[0])
                result["ml_metrics"]["rf_confidence"] = rf_conf

            # ---- NEW RISK SCORER INTEGRATION ----
            from core.risk_scoring import RiskScorer
            scorer = RiskScorer()

            # The RiskScorer does the heavy lifting of mapping raw ML metrics and anomalies into a normalized explicit 0-100 score + English explainability.
            risk_eval = scorer.calculate_risk(features, result["ml_metrics"], rule_fired, result["severity"])

            result["risk_score"] = risk_eval["risk_score"]
            result["severity"] = risk_eval["adjusted_severity"]
            result["explainability"] = risk_eval["explainability"]

            # Enforce dynamic Risk boundaries
            if result["risk_score"] >= 50.0:
                result["is_threat"] = True
                result["confidence"] = result["risk_score"] / 100.0
                result["method"] = "ensemble_AI_risk_scoring"
                result["reason"] = f"[AI THREAT] {risk_eval['explainability']}"

        except Exception as e:
            logger.error(f"[ERROR] ML inference failure: {e}")

        return result

    def _feature_vector(self, features: Dict) -> Any:
        # Use Pandas exclusively to prevent sklearn feature warnings
        row = {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}
        df = pd.DataFrame([row])
        if self.scaler is not None:
            scaled = self.scaler.transform(df)
            return pd.DataFrame(scaled, columns=FEATURE_COLUMNS)
        return df

    def _classify_cause(self, features: Dict) -> str:
        if features.get("entropy", 0) > 6.0: return "Potential Ransomware"
        if features.get("packet_rate", 0) > 1000: return "Potential DoS"
        if features.get("cpu_usage", 0) > 80: return "Resource Exhaustion"
        if features.get("connection_count", 0) > 100: return "Port Scan"
        return "Unknown Threat Pattern"

    @property
    def status(self) -> Dict:
        return {
            "rf_loaded": self.rf_model is not None,
            "iso_loaded": self.iso_model is not None,
            "scaler_loaded": self.scaler is not None,
            "ready": self.ready
        }
