# 🛡️ Threat Sentinel: Autonomous AI Security Engine

<div align="center">
  <img src="https://img.shields.io/badge/Status-Production%20Ready-success" />
  <img src="https://img.shields.io/badge/Deployed_On-Render-black?logo=render" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue" />
  <img src="https://img.shields.io/badge/Framework-FastAPI%20%7C%20React-blueviolet" />
  <img src="https://img.shields.io/badge/ML-Scikit--Learn-orange" />
</div>

## 🌐 Live Deployment

🚀 **Experience the live dashboard right now:**
- **Frontend Dashboard:** [https://threat-sentinel-frontend.onrender.com](https://threat-sentinel-frontend.onrender.com/)
- **Backend Health API:** [https://threat-sentinel-backend.onrender.com/health](https://threat-sentinel-backend.onrender.com/)

> *⚠️ Note: This project is deployed on Render's free tier infrastructure. If the dashboard hasn't been visited in a while, the backend server may take about ~50 seconds to manually spin up before the charts start streaming data natively!*

---

## 📖 Project Overview
**Threat Sentinel** is a production-grade, autonomous Endpoint Detection and Response (EDR) system. Built for modern cybersecurity challenges, it actively monitors host operating system metrics—including process behavior, network socket aggregations, and file system entropy—in real-time.

Unlike traditional signature-based antiviruses, Threat Sentinel employs a **Dual-Model Machine Learning Pipeline**. It detects both known threats and zero-day exploits simultaneously. Once a threat is validated, the **Response Engine** natively enforces **Action Constraint Lists (ACLs)** to quarantine files, block IPs, or terminate malicious processes safely without destroying core Windows operations.

---

## ✨ Core Features

### 🧠 1. Dual-Model ML Detection
- **Random Forest Classifier:** Trained natively on external network intrusion datasets to identify known signature-based network and host anomalies with high accuracy.
- **Isolation Forest:** An unsupervised model analyzing localized baseline host densities to catch elusive zero-day deviations and behavioral outliers.

### 💬 2. Explainable AI (XAI)
The intelligent **Risk Scoring Engine** translates complex ML confidence levels and dataset anomaly thresholds into fully readable plain-English explainability parameters.
*Example: "File entropy exceeds ransomware encryption safety threshold (>7.0) | AI classifier pattern match (99.0% confidence)."*

### 🛡️ 3. Safe Autonomous Response
- **Policy Engine ACLs:** Strictly prevents the autonomous agent from terminating critical Windows kernel framework processes (`svchost.exe`, `explorer.exe`).
- **SAFE_MODE Toggle:** Built-in simulation capabilities designed to dry-run defensive maneuvers without computationally altering host system structures.

### 🌐 4. High-Frequency Websocket Dashboard
- A gorgeous **React (TypeScript) / Vite** frontend connected via high-performance HTML5 WebSockets, continuously broadcasting active computational telemetry nodes, risk indices, and incident logs dynamically.

---

## 🏗️ System Architecture

```text
[ OS Telemetry Sensors ] ---> (CPU, Memory, Packets, Entropy)
           |
           v
[ Backend Aggregator ] -----> (Pandas DataFrame Standardization)
           |
           v
[ ML Detection Engine ] ----> (RandomForest + IsolationForest)
           |
           v
[ Risk Scoring Module ] ----> (0-100 Score + Explainability Compiler)
           |
           v
[ Policy Engine ACLs ] -----> (Safety Filter: Is target system-critical?)
           |
           v
[ Threat Response ] --------> (Terminate PID / Block IP / Quarantine File)
```

---

## 📁 Directory Structure
```text
📦 Autonomous AI-Based Threat Detection
├── 📂 backend
│   ├── 📂 api          # FastAPI REST endpoints & WebSocket broadcasters
│   ├── 📂 core         # Policy Engine, Risk Scoring mechanisms, and Thread-Safe Logging
│   ├── 📂 ml           # Sklearn models, inference pipelines, training sets, prediction loops
│   ├── 📂 monitoring   # Watchdog (Files) and Psutil (Processes/Network) async sensors
│   ├── 📂 response     # Autonomous action executors (Kill, Quarantine, IP Block)
│   ├── 📂 data         # Local SQLite Threat Database & Quarantined Payload Vault
│   ├── 📂 models       # Serialized .pkl binary ML intelligence models
│   └── 📜 start_server.py # Isolated Python Backend Execution Bootstrapper
│
├── 📂 frontend
│   ├── 📂 src          # React Dashboard structures, GUI Components, CSS logic
│   └── 📜 package.json
│
├── 📂 scripts
│   └── 📜 start_sentinel.bat # Unified Complete Windows Execution Launcher
│
└── 📜 run.sh           # Unified Complete Linux/macOS Shell Launcher
```

---

## 🚀 Installation & Setup

### Prerequisites
1. **Python 3.10+** (Ensure Python is explicitly added to relative System PATH variables)
2. **Node.js (v18+)** (Required strictly to compile and serve the Vite React Dashboard)
3. **Administrator Privileges** (Strongly recommended for internal network socket binding and terminating native external processes)

### Setup Instructions
1. **Clone the Project Repository:**
   ```bash
   git clone https://github.com/yourusername/threat-sentinel.git
   cd threat-sentinel
   ```
2. **Setup the Python Backend Dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
3. **Setup the Node Frontend Packages:**
   ```bash
   cd ../frontend
   npm install
   ```

---

## 💻 How to Run

### Method 1: The One-Click Execute (Windows Native)
Navigate back to the main repository root directory and explicitly run the launch batch script representing all environments:
```batch
.\scripts\start_sentinel.bat
```
*Note: This command flushes antiquated logs safely, executes the Uvicorn Model on Port 8000 natively, and mounts the React Node server heavily on Port 5173 dynamically.*

### Method 2: The One-Click Execute (Linux / macOS Shell)
```bash
chmod +x run.sh
./run.sh
```

### Method 3: Isolated Advanced Startup
Use separated bash/command instances if you require precise execution boundaries:
**Terminal 1 (Backend Initialization):**
```bash
cd backend
python start_server.py
```
**Terminal 2 (Frontend Initialization):**
```bash
cd frontend
npm run dev
```

---

## 🖥️ Live Telemetry & Threat Logs

Threat Sentinel outputs an immaculate, professional terminal pipeline logging structure engineered precisely for presentation grading and forensics reviewing formats:

```text
[2026-03-27 18:25:00] [INFO] [sentinel] -> [SAFE] CPU:  2.1% | RAM: 60.1% | Net:   10/s | ML_Conf:  0.0% | Anomaly: +0.22
[2026-03-27 18:25:04] [INFO] [sentinel] -> Threat detected (confidence=0.98)
[REASON] File entropy exceeds ransomware encryption safety threshold (>7.0)
[ACTION] Process terminated safely: PID 1234 (malware.exe)
```

---

## ⚙️ Enterprise Configuration Settings
By default, the active agent is computationally confined by internal constraint policies to completely eradicate risks regarding bricking operating infrastructure. 

To strictly unleash full autonomous remediation procedures (Executing Real File Kills alongside standard Network Blocks):
1. Navigate directly to `backend/response/engine.py` using your editor.
2. Under `__init__`, actively modify `SAFE_MODE = True` (Dry Run Isolation) into `SAFE_MODE = False` (Active Lethal Execution).

---

## 🔮 Future Expansion Roadmaps
- **Ring-0 Kernel Driver Integration:** Rewriting tracking sensors to bypass basic user-space execution loops and interface alongside Windows kernel drivers via eCallbacks for absolute zero-latency response sequences.
- **LLM Packet Extrapolation:** Integrating highly portable Large Language Models (LLaMa 3) locally to digest blocked networking topologies mapping clear threat vectors and exploits dynamically beyond basic ML outputs.
- **Cloud Hash Threat Federation:** Pushing and pulling uniquely detected MD5 hashes automatically through highly recognized public global communities (AlienVault/MISP servers) anonymously.
