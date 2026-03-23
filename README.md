# Autonomous AI Based Threat Detection and Threat Elimination Engine 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)
![React 18+](https://img.shields.io/badge/React-18+-blue.svg)

> AI-powered threat detection and monitoring system with full-stack architecture.

**Autonomous AI Based Threat Detection and Threat Elimination Engine** is an advanced, autonomous cybersecurity defense platform designed to protect host ecosystems in real-time. Moving beyond static "anti-virus" signatures, the system continuously monitors bare-metal OS telemetry (CPU, Memory, Packet Rates, File Entropy) to catch zero-day anomalies and live network intrusions as they happen.

It leverages a dual-engine Machine Learning architecture—utilizing a **Random Forest** trained on the massive CIC-IDS2017 dataset for known threats (>99.8% precision) parallel to an **Isolation Forest** targeting unseen behavioral outliers.

If a threat is verified, Autonomous AI Based Threat Detection and Threat Elimination Engine acts with **Level 4 Autonomy**: it terminates malicious processes, blocks network IPs via system firewalls, and safely quarantines high-entropy ransomware files. All actions are logged into a tamper-proof SHA-256 blockchain and streamed over WebSockets to a sleek React UI.

---

## 🌟 Features

- **Continuous Hardware Monitoring:** Fast `psutil` daemon threads monitor process loads, connection spikes, and packet payloads.
- **Ransomware Prevention:** Tracks live File I/O creation hashes and calculates Shannon Entropy on disk writes to catch encryption loops in milliseconds.
- **Dual AI Engine:** High-confidence classifications using Scikit-Learn `RandomForest` mixed with zero-day `IsolationForest` outlier detection.
- **Autonomous Remediation:** OS-level bindings natively kill attacks and quarantine endpoints without requiring human interaction.
- **Tamper-Evident Forensics:** Cryptographically bonded JSONL event chains ensure hackers cannot delete or edit security logs once recorded.
- **Live WebSocket Dashboard:** A beautiful, dark-mode React Dashboard featuring Recharts telemetry plotting.

---

## 🏛️ Architecture Overview

The system runs on an asynchronous Python backend wrapped with a modern web dashboard. For a detailed breakdown of the Data Flow, please see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 💻 Technology Stack

- **Frontend:** React, TypeScript, Vite, TailwindCSS, Recharts.
- **Backend API:** Python, FastAPI, Uvicorn, WebSockets.
- **Machine Learning:** Scikit-Learn (RandomForest, IsolationForest), Pandas, NumPy.
- **Databases:** SQLite (Threat Intel), JSONL (Forensics).

---

## 🚀 Installation & Setup

Ensure you have **Python 3.9+** and **Node.js 18+** installed.

### 1. Clone & Configure
```bash
git clone https://github.com/yourusername/autonomous-ai-based-threat-detection-and-threat-elimination-engine.git
cd autonomous-ai-based-threat-detection-and-threat-elimination-engine
```

*(You can copy `backend/.env.example` to `backend/.env` for explicit model staging secrets if desired).*

### 2. Run Locally

You can run the entire stack simultaneously using the automated launcher script (Windows):
```bash
./scripts/start-all.bat
```

**Manual Startup:**

```bash
# Terminal 1 - Backend
cd backend
pip install -r requirements.txt
python -m uvicorn api.server:app --port 8000
```

```bash
# Terminal 2 - Frontend
cd frontend
npm install
npm run dev
```

Navigate to **[http://localhost:5173](http://localhost:5173)** to access the dashboard.

---

## 📖 Usage Guide

When viewing the dashboard, you have full access to:
- **Live Telemetry:** Watch the AI Engine interpret your hardware traffic streams live.
- **Simulations:** By clicking "Start Demo" on the **Demo** tab, the platform will simulate 5 heavily encrypted files hitting your storage drive. You can watch the AI instantly catch the entropy spikes and automatically invoke the Quarantine functions.
- **Audit Logs:** View historical events safely on the **Threats** database view or the **Forensics** blockchain view.

---

## 🔮 Future Scope
- **Dockerization:** Container support for massive scalability and independent sensor deployment.
- **SIEM Pipeline Output:** Directly output the forensic arrays to Splunk or Elasticsearch.
- **Stateful Deep Learning:** Swapping the discrete-time Forests for Stateful LSTM neural-network models capable of tracking slow, multi-month APT incursions.

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
