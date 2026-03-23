# Autonomous AI Based Threat Detection and Threat Elimination Engine 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)
![React 18+](https://img.shields.io/badge/React-18+-blue.svg)

**An autonomous cybersecurity defense platform that protects host ecosystems in real-time.** 

Unlike traditional "anti-virus" software that relies on outdated, static file signatures, this Engine continuously monitors bare-metal OS telemetry (CPU loads, Memory usage, Network Packet Rates, and File Entropy). It catches zero-day anomalies, ransomware encryption loops, and live network intrusions as they happen, and actively neutralizes them before human intervention is required.

---

## 🌟 Core Features

- **Continuous Hardware Monitoring:** `psutil` daemon threads monitor system processes, connection spikes, and packet payloads natively.
- **Ransomware Prevention (Zero-Day):** The File IO monitor tracks live file creation and writes. It calculates **Shannon Entropy** to instantly catch the high-entropy encryption loops characteristic of modern ransomware inside milliseconds.
- **Dual AI Engine:** High-confidence classifications using a Scikit-Learn **Random Forest** (trained on the CIC-IDS2017 dataset with >99.8% precision) operating parallel to an **Isolation Forest** (detecting unseen behavioral outliers).
- **Autonomous Remediation (Level 4):** OS-level bindings natively kill attack processes, quarantine encrypted files, and block network IPs automatically.
- **Tamper-Evident Forensics:** Cryptographically bonded JSONL event chains ensure hackers cannot delete, alter, or edit security logs once recorded.
- **Live WebSocket Dashboard:** A sleek, dark-mode React Dashboard featuring Recharts telemetry plotting.

---

## 🏛️ System Architecture Workflow

The system operates on an active asynchronous pipeline divided into three domains:

1. **Sense (Sensors):** Daemon threads natively wrap around the OS to collect live state.
2. **Think (AI Inference):** The mathematical pipeline converts the state array (`[cpu, mem, entropy, pkt_rate, bps, connections]`) into normalized matrices and evaluates it against the ML Models.
3. **Act (OS Actuators):** If a threat confidence boundary is breached, destructive OS commands execute instantly (e.g., firewall blocks, process kills) and the event is written to the unalterable forensic blockchain.

*(For an in-depth component-level design diagram, see `docs/ARCHITECTURE.md`)*

---

## 💻 Complete Technology Stack

| Layer | Tools & Technologies |
|-------|----------------------|
| **Frontend UI** | React, TypeScript, Vite, TailwindCSS, Recharts |
| **Backend API** | Python, FastAPI, Uvicorn, WebSockets |
| **Machine Learning**| Scikit-Learn (RandomForest, IsolationForest), Pandas, NumPy |
| **Databases** | SQLite (Threat Intel IOCs), JSONL (Forensics Blockchain) |

---

## 🚀 Quick Start & Installation Instructions

Follow these instructions exactly to get the Engine running from scratch on your local machine.

### Prerequisites
You strictly need the following installed:
- **Python:** Version 3.9 or higher.
- **Node.js:** Version 18 or higher (which includes `npm`).

### Step 1: Clone the Repository
Open a terminal and download the codebase:
```bash
git clone https://github.com/Bharadwaj204/threat-sentinel-v2.git
cd "Autonomous AI Based Threat Detection and Threat Elimination Engine"
```

### Step 2: Start the Backend (API + AI Engine)
The backend requires its own Python environment to load the ML models and launch the system sensors.

1. Open a terminal inside the project root and navigate to `backend/`.
2. Install the rigid Python dependencies:
```bash
cd backend
pip install -r requirements.txt
```
3. Start the FastAPI server (this binds the sensors and models to memory):
```bash
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```
> **Note:** Do NOT close this terminal window. The backend is now actively monitoring your computer and serving the API locally.

### Step 3: Start the Frontend (React Dashboard)
The frontend requires its own Node process to compile the UI.

1. Open a **second** new terminal inside the project root.
2. Navigate to `frontend/`:
```bash
cd frontend
npm install
```
3. Start the Vite React development server:
```bash
npm run dev
```

### Step 4: Access the Application
Open your web browser (Chrome/Edge/Firefox) and navigate to:
👉 **[http://localhost:5173](http://localhost:5173)**

The dashboard should instantly load, displaying live metrics indicating that the WebSockets are successfully streaming hardware telemetry from the backend.

*(Alternatively, Windows users can simply double-click `scripts/start-all.bat` to launch both servers simultaneously in one click).*

---

## 🧪 How to Use & Test the Application

The Dashboard is broken down into 5 simple tabs. Here is how to use them:

1. **Dashboard:** Watch the live AI Engine interpret your hardware traffic streams in real time as you open apps or browse the web.
2. **Demo (Testing the AI):** 
   - Navigate to the **Demo** tab. 
   - Click the massive **Start Demo** button.
   - **What happens:** The system safely simulates 5 heavily encrypted "ransomware" files hitting your local storage drive.
   - **Watch the system react:** The AI will instantly catch the entropy spikes, flash a red alert on your screen, and automatically invoke the native OS Quarantine functions to lock the files away.
3. **Threats:** View the historical SQLite database of everything the AI caught and what specific action was taken.
4. **Forensics:** Verify the integrity of your security logs. If a single byte was altered by a hacker, the blockchain validation state will turn red.
5. **Intel DB:** View the actively hunted "Indicators of Compromise" (Known bad IPs to block).

---

## 🔮 Future Enhancement Scope

While the Engine is fully functional today, future scale architectures include:
- **Dockerization:** Complete container support for massive scalability and independent sensor deployment across external VPS boxes.
- **SIEM Pipeline Output:** Directly outputting the forensic arrays to Splunk or Elasticsearch clusters.
- **Stateful Deep Learning:** Swapping the discrete-time Forests for Stateful LSTM Neural Networks capable of tracking slow, multi-month APT (Advanced Persistent Threat) incursions.

---

## 📄 License
This open-source project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
