"""
Risk Scoring & Explainability Module
Calculates a normalized 0-100 risk score and generates human-readable explanations.
"""
from typing import Dict, Any

class RiskScorer:
    def __init__(self):
        # Baseline multipliers
        self.weights = {
            "ml_confidence": 40.0,
            "anomaly_score": 30.0,
            "rule_severity": 30.0
        }

    def calculate_risk(self, features: Dict[str, float], ml_metrics: Dict[str, float], rule_fired: bool, base_severity: str) -> Dict[str, Any]:
        """
        Evaluate raw metrics and return a normalized risk score (0-100) and an explanation string.
        """
        score = 0.0
        explanations = []

        # 1. ML Confidence Assessment (0-40 points)
        rf_conf = ml_metrics.get("rf_confidence", 0.0)
        if rf_conf > 0.5:
            points = rf_conf * self.weights["ml_confidence"]
            score += points
            explanations.append(f"AI classifier pattern match ({rf_conf:.1%} confidence).")
        
        # 2. Anomaly Score Assessment (0-30 points)
        # IsoForest score usually ranges from -0.5 (anomaly) to +0.5 (normal).
        iso_score = ml_metrics.get("iso_score", 0.0)
        if iso_score < 0:
            # Normalize negative score to a positive multiplier
            anomaly_magnitude = min(abs(iso_score) * 2, 1.0)
            score += anomaly_magnitude * self.weights["anomaly_score"]
            explanations.append(f"High statistical deviation from baseline (Zero-day indicator).")

        # 3. Rule-based Heuristics (0-30 points)
        if rule_fired:
            score += self.weights["rule_severity"]
            if features.get("entropy", 0) > 7.0:
                explanations.append("File entropy exceeds ransomware encryption safety threshold (>7.0).")
            if features.get("packet_rate", 0) > 3000:
                explanations.append("Network packet flood detected (DoS signature).")
            if features.get("cpu_usage", 0) > 90:
                explanations.append("Critical CPU saturation (Cryptomining/Resource Exhaustion).")

        # Cap score at 100
        score = min(round(score, 1), 100.0)

        # Determine adjusted severity strictly mathematically
        if score >= 85:
            severity = "critical"
        elif score >= 65:
            severity = "high"
        elif score >= 40:
            severity = "warning"
        else:
            severity = "info"

        explanation_str = " | ".join(explanations) if explanations else "Normal system behavior."

        return {
            "risk_score": score,
            "adjusted_severity": severity,
            "explainability": explanation_str
        }
