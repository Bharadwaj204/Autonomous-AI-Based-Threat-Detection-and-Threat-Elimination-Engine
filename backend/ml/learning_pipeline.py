"""
Module 7: Continuous Learning Pipeline
- Collects confirmed threat samples with features
- Periodically retrains models with new data
- Updates model files on disk without restarting server
"""
import os
import csv
import pickle
import threading
import logging
from datetime import datetime
from typing import Dict, List, Optional

try:
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    SKLEARN_OK = True
except ImportError:
    SKLEARN_OK = False

logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "cpu_usage", "memory_usage", "entropy",
    "packet_rate", "bytes_per_sec", "connection_count"
]

ONLINE_DATA_FILE = "data/online_training_data.csv"
MODEL_DIR = "models"
MIN_SAMPLES_TO_RETRAIN = 50


class LearningPipeline:
    def __init__(self):
        self._lock = threading.Lock()
        self._pending_samples: List[Dict] = []
        self._total_added = 0
        os.makedirs(MODEL_DIR, exist_ok=True)
        os.makedirs("data", exist_ok=True)
        self._init_csv()

    def _init_csv(self):
        if not os.path.exists(ONLINE_DATA_FILE):
            with open(ONLINE_DATA_FILE, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS + ["is_threat"])
                writer.writeheader()

    def add_sample(self, features: Dict, is_threat: int):
        """Add a confirmed labeled sample to the learning queue."""
        with self._lock:
            row = {col: features.get(col, 0.0) for col in FEATURE_COLUMNS}
            row["is_threat"] = is_threat
            self._pending_samples.append(row)
            self._total_added += 1

            # Flush to CSV every 10 samples
            if len(self._pending_samples) >= 10:
                self._flush_to_csv()

    def _flush_to_csv(self):
        try:
            with open(ONLINE_DATA_FILE, "a", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS + ["is_threat"])
                writer.writerows(self._pending_samples)
            self._pending_samples.clear()
        except Exception as e:
            logger.error(f"CSV flush error: {e}")

    def retrain_if_ready(self) -> Optional[Dict]:
        """Retrain models if enough new data has accumulated."""
        if not SKLEARN_OK:
            return None

        if self._total_added < MIN_SAMPLES_TO_RETRAIN:
            return None

        return self._retrain()

    def _retrain(self) -> Optional[Dict]:
        """Full retrain combining original + new online data."""
        try:
            with self._lock:
                self._flush_to_csv()

            # Load all available data
            dfs = []
            for path in ["data/synthetic_training_data.csv", ONLINE_DATA_FILE]:
                if os.path.exists(path):
                    df = pd.read_csv(path)
                    if len(df) > 0:
                        dfs.append(df)

            if not dfs:
                return None

            data = pd.concat(dfs, ignore_index=True).dropna()
            if len(data) < 100:
                logger.info(f"Insufficient data for retraining: {len(data)} rows")
                return None

            X = data[FEATURE_COLUMNS]
            y = data["is_threat"]

            # Scale features
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)

            X_train, X_test, y_train, y_test = train_test_split(
                X_scaled, y, test_size=0.2, random_state=42
            )

            # RandomForest
            rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
            rf.fit(X_train, y_train)
            acc = accuracy_score(y_test, rf.predict(X_test))

            # IsolationForest (unsupervised on all data)
            iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
            iso.fit(X_scaled)

            # Save models
            with open(f"{MODEL_DIR}/randomforest_model.pkl", "wb") as f:
                pickle.dump(rf, f)
            with open(f"{MODEL_DIR}/isoforest_model.pkl", "wb") as f:
                pickle.dump(iso, f)
            with open(f"{MODEL_DIR}/scaler.pkl", "wb") as f:
                pickle.dump(scaler, f)

            result = {
                "retrained_at": datetime.now().isoformat(),
                "samples_used": len(data),
                "rf_accuracy": round(acc, 4),
                "status": "success"
            }
            logger.info(f"✅ Models retrained: {result}")
            self._total_added = 0
            return result

        except Exception as e:
            logger.error(f"Retraining failed: {e}")
            return {"status": "failed", "error": str(e)}

    @property
    def status(self) -> Dict:
        rows = 0
        if os.path.exists(ONLINE_DATA_FILE):
            with open(ONLINE_DATA_FILE) as f:
                rows = sum(1 for _ in f) - 1  # Subtract header
        return {
            "pending_samples": len(self._pending_samples),
            "total_added_session": self._total_added,
            "online_data_rows": rows,
            "ready_to_retrain": self._total_added >= MIN_SAMPLES_TO_RETRAIN
        }
