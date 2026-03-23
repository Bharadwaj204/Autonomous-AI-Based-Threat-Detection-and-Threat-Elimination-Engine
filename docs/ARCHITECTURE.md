# Autonomous AI Based Threat Detection and Threat Elimination Engine Architecture

Autonomous AI Based Threat Detection and Threat Elimination Engine is an autonomous AI-powered cybersecurity defense system designed to protect hosts in real-time. It completely replaces the notion of traditional "signature-scanning" with an active behavioral-monitoring AI loop.

## 1. System Design
The system operates on an active asynchronous pipeline divided into three domains:
- **Sensors:** Daemon threads natively wrapped around the OS to collect live state.
- **Inference:** The mathematical pipeline converting state arrays into normalized matrices for the models.
- **Actuators:** The destructive OS-level hooks connecting the AI's decision to instantaneous active defense actions (firewall blocks, process kills).

## 2. Component Diagram
```text
[ OS Environment ]
       │
       ▼
┌──────────────────────────────────────────────┐
│  Continuous Hardware Sensors (psutil, etc)   │
│  - Process Monitor   - Network Monitor       │
│  - File I/O Monitor  - Entropy Calculator    │
└──────────────────────┬───────────────────────┘
                       │ (JSON Telemetry Stream)
       ┌───────────────▼───────────────┐
       │   AI Detection Engine (I/O)   │
       │                               │
       │  [ StandardScaler Normalizer] │
       │               │               │
       │       ┌───────┴───────┐       │
       │       ▼               ▼       │
       │  Random Forest   Isolation    │
       │  (Known Attacks)  Forest      │
       │                  (Zero Day)   │
       └───────────────┬───────────────┘
                       │ (Threat Confidence Matrix)
       ┌───────────────▼───────────────┐
       │     Response Orchestrator     │
       └──────┬─────────────────┬──────┘
              │                 │   
      [ OS Actuators ]    [ Persistence ]
      - Kill Process      - Forensic JSONL Hash Chain
      - Quarantine File   - SQLite Threat DB
      - Block Port IP     - WebSocket Broadcast
              │
      ┌───────▼───────┐
      │ React Vite UI │
      └───────────────┘
```

## 3. Data Flow Execution

1. **Ingestion Level:** Sensors fire every `2000ms`. When the File Monitor detects a newly created binary on disk, it calculates the Shannon Entropy (`H(X) = -Σ P(x)log₂P(x)`).
2. **Feature Mapping:** The metric is assembled into an exact `1x6` array: `[cpu, mem, entropy, pkt_rate, bps, connections]`.
3. **Machine Learning Level:** The `AIDetectionEngine` catches the vector.
   - The array is normalized against a previously fit `StandardScaler` to align with the `CIC-IDS2017` dataset topology.
   - The array runs through the massive `RandomForestClassifier`.
4. **Scoring Level:** If the RF logic gates classify the behavior as heavily skewed towards `BENIGN=0, ATTACK=1` mapping, a `confidence` interval is generated (e.g., `0.95`).
5. **Enforcement Level:** A `ThreatEvent` is dispatched asynchronously to `response.engine`. 
   - Based on the signature, the Engine maps to a predefined OS command (e.g. `quarantine_file`).
   - The `ForensicLogger` captures the state, calculates a cryptography hash bounding the previous state's signature, and appends to disk.

## 4. The ML Training Pipeline
The AI was trained natively on 200,000 strategically balanced feature extractions generated from the **CIC-IDS2017** dataset. This dataset features dozens of background traffic permutations interacting directly against real-world DDOS, PortScan, and Application-layer exploits. Features were specifically compressed from 79 raw headers down to 6 behavioral proxies to allow real-time (sub-10ms) inference speeds without locking the Python event loop.
