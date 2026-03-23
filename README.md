# Autonomous AI Based Threat Detection and Threat Elimination Engine 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Python 3.9+](https://img.shields.io/badge/Python-3.9+-blue.svg)
![React 18+](https://img.shields.io/badge/React-18+-blue.svg)

**A smart, self-driving cybersecurity system that protects your computer in real-time.** 

Traditional antivirus software only looks for known threats using a checklist. This system is different. It acts like a live security guard—constantly watching how your computer's memory, CPU, and internet behave. By using Artificial Intelligence, it can catch brand new hacker attacks and ransomware the second they happen, and it automatically stops the attack before any humans need to intervene.

---

## 🌟 How It Protects You (Core Features)

- **24/7 Hardware Watcher:** The system runs quietly in the background, keeping a close eye on your computer processes and internet traffic.
- **Instant Ransomware Catching:** It watches files as they are saved or changed. By doing quick math (called *entropy*), it can instantly tell if a file is being heavily encrypted by ransomware, and it stops it immediately.
- **Two AI Brains:** We use two smart models:
  1. **The Detective (Random Forest):** Trained on a massive dataset of real-world hacks to quickly spot known attacks.
  2. **The Guard Dog (Isolation Forest):** Looks for completely new "weird" behavior to catch zero-day attacks that nobody has ever seen before.
- **Automatic Defense Response:** When the AI catches a hacker, it doesn't just send you a warning—it acts. It automatically kills the hacker's program, locks away the bad files, and blocks their internet connection.
- **Un-hackable Logs (Blockchain):** Every time the system stops a threat, it writes the event into a highly secure, tamper-proof logbook. Hackers cannot delete or edit their tracks.
- **Live User Dashboard:** A beautiful, dark-mode website (built in React) where you can watch the AI working in real-time.

---

## 🏛️ How It Works (3 Simple Steps)

1. **Sense (Gathering Data):** Background sensors collect live information about what the computer is doing right now.
2. **Think (AI Checking):** The AI brain looks at that data. If the numbers look like an attack, it calculates a "Threat Score".
3. **Act (Taking Action):** If the score is high, the system immediately deletes the bad program and permanently records the event in the un-hackable log.

---

## 💻 Technology Stack

| Part | Tools Used |
|-------|----------------------|
| **Website Dashboard** | React, TypeScript, Vite, TailwindCSS |
| **Server Engine** | Python, FastAPI, WebSockets |
| **AI Brain**| Scikit-Learn (Machine Learning), Pandas |
| **Databases** | SQLite (Threat memory), JSONL (Secure Logs) |

---

## 🚀 How to Install and Run Locally

Follow these basic steps to get the system running on your own computer.

### What you need:
- **Python:** Version 3.9 or higher.
- **Node.js:** Version 18 or higher (which comes with `npm`).

### Step 1: Download the Project
Open your command prompt or terminal and download the code:
```bash
git clone https://github.com/Bharadwaj204/threat-sentinel-v2.git
cd "Autonomous AI Based Threat Detection and Threat Elimination Engine"
```

### Step 2: Start the AI Backend
The backend is the "brain" that runs the sensors and the AI models.

1. Open a terminal inside the project folder and go to `backend/`.
2. Install the required Python tools:
```bash
cd backend
pip install -r requirements.txt
```
3. Start the server:
```bash
python -m uvicorn api.server:app --host 0.0.0.0 --port 8000
```
> **Note:** Leave this terminal open. The AI is now actively protecting your machine.

### Step 3: Start the Website Dashboard
The frontend is the visual website you see on your screen.

1. Open a **brand new terminal** inside the main project folder.
2. Go into the `frontend/` folder:
```bash
cd frontend
npm install
```
3. Start the website:
```bash
npm run dev
```

### Step 4: Open the Application!
Open your Google Chrome or web browser and go to:
👉 **[http://localhost:5173](http://localhost:5173)**

You will instantly see the live dashboard streaming your computer's health stats.

---

## 🧪 How to Test the Project (Ransomware Demo)

There are 5 simple tabs on the website. Here is how you can test that the AI actually works:

1. **Dashboard:** Watch the live charts move up and down as your computer works.
2. **Demo Tab (Testing the AI):** 
   - Click the **Start Demo** button.
   - **What happens:** The system safely creates 5 fake "ransomware" encrypted files on your hard drive to see if the AI notices.
   - **Watch the system react:** The AI will instantly catch the dangerous files, flash a red alert on your screen, and automatically invoke the Quarantine function to lock the fake ransomware away safely.
3. **Threats Tab:** View the database of every attack the AI has ever caught.
4. **Forensics Tab:** Check the secure blockchain logs. If the chain is "Valid", you know the logs haven't been tampered with.
5. **Intel DB:** View the actively hunted "Indicators of Compromise" (Known bad IPs to block).

---

## 📄 License
This open-source project is available under the MIT License - see the [LICENSE](LICENSE) file for details.
