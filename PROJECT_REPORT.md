# Autonomous AI Based Threat Detection and Threat Elimination Engine: Complete Project Report

## 1. System Architecture Breakdown

Autonomous AI Based Threat Detection and Threat Elimination Engine operates as an autonomous, multi-tier cybersecurity defense system. It shifts away from traditional, static antivirus signature scanning toward behavioral, machine-learning-driven protection.

### High-Level Design
The system employs a **Sense → Think → Act** architecture:
1. **Sensors (Sense):** Bare-metal system monitors (Process, Network, File) collect operating telemetry locally.
2. **AI Engine (Think):** Telemetry is aggregated and mathematically scored against pre-trained ML models.
3. **Response Engine (Act):** If confidence limits are breached, local OS commands are fired instantly to neutralize the threat.
4. **Persistence (Log):** Both the event and the action are committed to a local SQLite DB and a hashed JSONL forensic chain.
5. **Dashboard:** All the above states are continuously streamed via WebSockets to a React-based frontend.

### Frontend Structure
- **Framework:** React + TypeScript + Vite. 
- **Styling:** Vanilla Tailwind-style CSS via `index.css`.
- **Components:** Managed inside a massive centralized `App.tsx` handling 5 tabs (Dashboard, Threats, Intel, Forensics, Demo).
- **Connections:** Maintains a continuous duplex `WebSocket` to `ws://localhost:8000/ws` while fetching historical states via traditional `GET` REST endpoints.

### Backend Structure
- **Framework:** Python / FastAPI / Uvicorn.
- **State Management:** Fully asynchronous server running native Python thread loops for the monitors.
- **Directories:** 
  - `/monitoring/`: The isolated sensor scripts (`psutil`, `watchdog`).
  - `/ml/`: The core brains (`detection_engine.py`, `forensic_logger.py`).
  - `/response/`: The local remediation engine (`engine.py`).
  - `/api/`: The REST/WebSocket routing (`server.py`).

### Data Flow (End-to-End)
1. `network_monitor` counts `5,000` packets in a half-second on port 80 → sends `[cpu, mem, entropy, pkt_rate=10000, bytes, connections]` to `AIDetectionEngine`.
2. `AIDetectionEngine` normalizes the vector via `StandardScaler`.
3. The vector hits the `RandomForestClassifier`. It recognizes the "DoS Hulk" network pattern from CIC-IDS2017 training. Output: `is_threat=True`, `Confidence=0.94`.
4. `AIDetectionEngine` alerts the main `server.py` loop.
5. `server.py` fires an asynchronous event to `response.engine`.
6. `response.engine` invokes the firewall (`netsh`/`iptables`) to block the offending IP address.
7. `forensic_logger` hashes the event and seals it to `forensic_chain.jsonl`.
8. The `threat_intel.db` creates a new row.
9. `server.py` broadcasts `{type: "threat_alert", payload: ...}` across the WebSocket.
10. The React Frontend turns the alert box red and plots the spike on the `Recharts` graph simultaneously.

---

## 2. Feature Documentation

### Feature 1: The Dual-Model AI Engine
- **Purpose:** Provide accurate attack categorization while remaining resilient to never-before-seen anomalies.
- **Internals:** The system features a Supervised `RandomForestClassifier` mapping 6 behavioral metrics against a massive 200,000-row sample of the CIC-IDS2017 dataset. Because attackers mutate code, the secondary `IsolationForest` runs parallel as an Unsupervised Outlier detector.
- **Files Involved:** `backend/ml/detection_engine.py`, `backend/ml/train_cicids.py`
- **I/O:** Input: 6-feature float vector. Output: `{is_threat: bool, severity: str, method: str, confidence: float}`

### Feature 2: High-Entropy Ransomware File Monitoring
- **Purpose:** Catch zero-day ransomware the moment it begins destroying files.
- **Internals:** Utilizes `watchdog` to catch every `on_created` and `on_modified` OS event in targeted folders. Instead of checking malware signatures, it runs a Shannon Entropy calculation on the file bytes. If the file is perfectly compressed/encrypted (Entropy > 7.5), it is flagged immediately as malicious.
- **Files Involved:** `backend/monitoring/file_monitor.py`
- **I/O:** Input: OS File Create Event. Output: `{cpu, mem, entropy=7.98, ...}` vector sent to AI Engine.

### Feature 3: Tamper-Evident Forensic Blockchain Logging
- **Purpose:** Ensure that if an attacker gains root access, they cannot secretly delete or modify the security logs.
- **Internals:** Every log entry calculates a SHA-256 hash containing its own data *plus* the hash of the preceding log entry. When `verify_chain()` runs, it recalculates the entire tree. If a single byte is changed historically, the mathematical chain breaks, alerting the Admin.
- **Files Involved:** `backend/ml/forensic_logger.py`
- **I/O:** Input: Threat Dict. Output: Appended row in `forensic_chain.jsonl`.

### Feature 4: Autonomous Response Engine (Level 4 System)
- **Purpose:** Eliminate the "Human Reaction Time" bottleneck during a crisis.
- **Internals:** Connects directly to OS-level administrative commands (`os.kill()`, `shutil.move()`). It contains safety-guards to ensure it doesn't accidentally kill `explorer.exe`, `system32`, or essential drivers.
- **Files Involved:** `backend/response/engine.py`

---

## 3. Tech Stack Summary

- **Languages:** Python 3.10+, TypeScript, SCSS/CSS, Node/JavaScript.
- **Frameworks:** FastAPI (Backend), ReactJS + Vite (Frontend).
- **Libraries:** 
  - *Python:* `scikit-learn`, `pandas`, `uvicorn`, `psutil`, `watchdog`.
  - *React:* `recharts` (Data visualization), `lucide-react` (Icons).
- **APIs:** WebSocket standard (`ws://`), REST HTTP (`GET`/`POST`).
- **Databases:** SQLite3 (`threat_intel.db`), JSON Lines File DB (`forensic_chain.jsonl`).
- **AI/ML Tools:** Scikit-Learn RandomForestClassifier, IsolationForest, StandardScaler.

---

## 4. Environment & Setup Checklist

1. **Python Virtual Env (Recommended):** `python -m venv venv` and `source venv/bin/activate`.
2. **Install Depdencencies:** `pip install -r requirements.txt` / `npm install`.
3. **Environment Variables:**
   - Create a `.env` in `backend/` (Optional).
   - `MODEL_PATH`: Custom path to `.pkl` files.
   - `DEMO_MODE`: Boolean to explicitly allow the `/api/demo` endpoint to fire.
   - `LOG_RETENTION_DAYS`: Controls SQLite auto-pruning.
4. **Local Execution:** Use `uvicorn api.server:app` for backend, `npm run dev` for frontend.
5. **Production Build:** Use `npm run build` in the frontend and proxy the `/dist` output using NGINX, pointing `/api` traffic to the underlying FastAPI Gunicorn workers.

---

## 5. Outputs & Results Interpretation

The system outputs real-time visual streams and persistent logs.

- **Example Output (Dashboard Console):** 
  `[CRITICAL] 2026-03-24 10:15 - Port Scan detected by random_forest (Conf: 0.88)`
- **Interpretation:** The AI evaluated high connections with low bytes across multiple ports. Severity `CRITICAL` forces the UI into a red-alert state and immediately instructs the response engine to execute an IP block.

---

## 6. Improvements & Scaling Roadmap

- **Code Quality:** Refactor the massive frontend `App.tsx` into smaller, reusable React components (`<Charts />`, `<DataTable />`, `<Terminal />`) mapping cleanly inside a `/frontend/src/components/` directory.
- **Performance:** Replace CSV-based Pandas operations in the training pipeline with `Polars` for extreme speedup.
- **Security:** Add JWT-based API authentication. Currently, the local WebSocket is fully exposed to anyone on `localhost`, which is fine for demo, but unsafe for cloud deployment.
- **Scalability:** Move SQLite to PostgreSQL and the local Python queues to an enterprise message broker like RabbitMQ or Apache Kafka to handle distributed endpoints.
