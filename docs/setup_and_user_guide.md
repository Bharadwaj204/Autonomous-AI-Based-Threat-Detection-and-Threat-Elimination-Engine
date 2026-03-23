# Autonomous AI Based Threat Detection and Threat Elimination Engine — Setup and User Guide

Welcome to **Autonomous AI Based Threat Detection and Threat Elimination Engine**, an Autonomous AI-based Cybersecurity Detection and Response System. This guide provides step-by-step instructions to set up the environment, run the servers, use the dashboard, and demonstrate the system's capabilities from scratch.

---

## 🏗️ 1. Environment Setup

Before starting, ensure you have the following installed on your machine:
- **Python:** 3.9 or higher
- **Node.js:** v18 or higher
- **Tools:** `pip` (Python package manager) and `npm` (Node package manager)

### Backend Setup (Python)
Open a terminal and navigate to the project root, then run:

```bash
cd backend
pip install -r requirements.txt
```
*(This installs FastAPI, Uvicorn, Scikit-Learn, Pandas, psutil, watchdog, and other ML/System tools).*

### Frontend Setup (React/Node)
Open a second, separate terminal from the project root and run:

```bash
cd frontend
npm install
```
*(This installs React, Vite, Recharts, and Tailwind dependencies).*

---

## 📂 2. Project Structure Overview

The repository is neatly organized into specific functional layers:

- **`backend/`**: Contains the Python FastAPI server, the ML models, real-time sensors, the response engine, and SQLite databases.
- **`frontend/`**: Contains the React + Typecript + Vite dashboard application that the user interacts with.
- **`backend/datasets/`**: The raw and processed CIC-IDS2017 networking datasets used strictly for training the AI.
- **`backend/models/`**: Stores the learned AI rule weights (`.pkl` files) generated during the training phases.
- **`backend/data/`**: Runtime storage for the forensic logging chains (JSONL) and the system threat intelligence database (SQLite).

---

## 🚀 3. Running the Backend

The backend is responsible for monitoring your system, running the AI inference, acting automatically on threats, and serving APIs.

In your backend terminal, run:

```bash
cd backend
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload
```

**What happens next?**
1. The server binds to port `8000`.
2. The AI models (Random Forest and Isolation Forest) are explicitly loaded into memory.
3. The 6 physical sensors (`file_monitor`, `network_monitor`, `process_monitor`, `ml_engine`, `response`, `forensics`) start running in background threads to watch your system.
4. The WebSocket broadcaster arms itself to send live stats to the frontend.

---

## 💻 4. Running the Frontend

The frontend is the visual dashboard providing real-time telemetry and control.

In your frontend terminal, run:

```bash
cd frontend
npm run dev
```

**How to access it:**
- Open your browser and navigate to: **[http://localhost:5173](http://localhost:5173)**
- The frontend will automatically connect to the backend over HTTP (for data requests) and WebSockets (for live streaming).

---

## 🩺 5. Verifying System Health

Before using the dashboard, it's good practice to verify the core API engines are healthy.

Open your browser to: **[http://localhost:8000/health](http://localhost:8000/health)**

**Expected Output (JSON):**
```json
{
  "status": "ok",
  "monitors": {
    "file": true,
    "network": true,
    "process": true,
    "ml_engine": true,
    "response": true,
    "forensics": true
  }
}
```
If you see `true` for all monitors, the system is fully armed and watching.

---

## 🎛️ 6. Using the Application (The Dashboard)

The Autonomous AI Based Threat Detection and Threat Elimination Engine Dashboard is divided into 5 simple tabs:

1. **Dashboard (Live Monitoring):** Displays live system metrics (CPU, Memory, Packet Rate) updating every 2 seconds. Also shows real-time security events natively scrolling in a terminal view.
2. **Threats (Stored Threats):** Shows a historical database table of every detected threat that required action, providing timestamps and severity.
3. **Intel DB:** Displays the system's "Indicators of Compromise" (IOCs)—the known bad IP addresses, bad process names, and malicious file hashes it is actively hunting for.
4. **Forensics:** Shows the secure, tamper-proof blockchain-style logs ensuring hackers cannot delete their tracks. Also reports if the chain is "Valid" and unbroken.
5. **Demo:** A safe, sandboxed playground specifically designed for reviewers/faculty to watch the system catch a ransomware attack automatically.

---

## 🎯 7. Running Test Scenarios (Demoing the System)

### Scenario A: Normal System Behavior
Just open the **Dashboard** tab. Watch the charts organically move up and down as your computer idles or opens apps. Verify no critical red alerts are violently flashing.

### Scenario B: Ransomware Simulation
1. Go to the **Demo** tab in the dashboard.
2. Click the highly visible **"Start Simulation"** button.
3. **What happens:** The backend safely generates 5 fake "encrypted" files in a sandbox folder.
4. **Expected Output:**
   - The AI immediately detects the massive spike in file entropy.
   - A critical red `threat_alert` fires on the Dashboard terminal.
   - The Autonomous Response Engine automatically grabs the 5 encrypted files and locks them in a `quarantine/` folder safely.
   - The event is logged in the **Threats** database tab.

---

## 🧠 8. Machine Learning Explanation (Simple)

The AI in this product works via 3 fast runtime steps:

1. **Feature Extraction:** Every 2 seconds, the sensors convert raw system stats into 6 numbers (e.g., `cpu_usage: 45`, `entropy: 7.2`).
2. **Prediction (The AI):** The 6 numbers are simultaneously passed to a **Random Forest** (detecting known threats by matching signatures) and an **Isolation Forest** (detecting completely new, weird behaviors by finding outliers).
3. **Decision Making:** If either AI model returns a confidence score high enough, the `AIDetectionEngine` stamps the packet as a `"Threat"` with a severity level (`high` or `critical`).

---

## 🛠️ 9. Troubleshooting Guide

| Issue | Cause | Solution |
|-------|-------|----------|
| **Backend terminal crashes immediately** | Port 8000 in use | Close other apps or run: `python -m uvicorn api.server:app --port 8001` |
| **Frontend says "Disconnected" (Red status)** | Backend isn't running | Start the backend terminal first, then refresh the browser. |
| **Models fail to load / Error `scikit-learn`** | Missing dependencies | Run `pip install -r requirements.txt` again inside the backend folder. |
| **Charts aren't moving** | WebSocket blocked | Disable strict ad-blockers for localhost or check backend terminal for WebSocket drops. |

---

## 🚀 10. Deployment (Optional Production Mode)

To run the frontend in a faster, optimized production state rather than "developer mode":

```bash
cd frontend
npm run build
npm run preview
```
*(This serves the frontend exactly how it would exist on a real web server).*

To run the backend strictly without dev-mode reloads:
```bash
cd backend
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```
