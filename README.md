# NetSentinel AI: AI-Powered Network Intrusion Detection & Real-Time Threat Monitoring System

[![Machine Learning](https://img.shields.io/badge/ML-Random%20Forest%20%7C%20Decision%20Tree%20%7C%20Isolation%20Forest-success.svg)](https://scikit-learn.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%20%2B%20WebSockets-009688.svg)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20Tailwind%20CSS-61DAFB.svg)](https://react.dev)
[![Dataset Standard](https://img.shields.io/badge/Features-CICIDS2017%20Compatible-orange.svg)](https://www.unb.ca/cic/datasets/ids-2017.html)

NetSentinel AI is a modern, modular, production-ready **Network Intrusion Detection System (NIDS)** that monitors live network communication, aggregates raw packets into bidirectional 5-tuple flows, classifies traffic using supervised and unsupervised machine learning algorithms, and surfaces corroborated security incidents with **Explainable AI (XAI)** on a real-time SOC dashboard.

---

## 🌟 Key Research Highlights & Innovations

1. **Bidirectional Flow Feature Extractor (`backend/app/engine/flow_meter.py`)**:
   - Bridges the gap between raw packets and offline ML datasets.
   - Extracts 49 statistical flow features compatible with the Canadian Institute for Cybersecurity (**CICIDS2017**) benchmark: flow duration, packet rates, byte rates, inter-arrival times (IAT), flag counters (SYN, ACK, RST, FIN, PSH), and segment length variances.

2. **Multi-Model Machine Learning Pipeline (`backend/app/ml/train.py`)**:
   - Compares **Random Forest (Primary Ensemble)**, **Decision Tree (Interpretable baseline)**, **Logistic Regression (Linear baseline)**, and **Isolation Forest (Unsupervised zero-day anomaly detection)**.
   - Handles class imbalance using balanced sample weighting.
   - Evaluates: **Accuracy**, **Macro/Weighted Precision & Recall**, **F1-Score**, **False Positive Rate (FPR)** on benign traffic, and sub-millisecond **Inference Latency**.

3. **Hybrid Detection Engine (`backend/app/engine/hybrid_engine.py`)**:
   - Correlates signature-based sliding window heuristics (e.g. rapid port sweeps, SYN flood rates) with ML probability outputs to maximize detection confidence and eliminate false alerts.

4. **Explainable AI (XAI) Reason Engine (`backend/app/ml/explainer.py`)**:
   - Doesn't just say traffic is malicious—it explicitly tells the security analyst **WHY** by comparing observed flow parameters against empirical normal baselines and outputting actionable mitigation steps.

5. **Real-Time SOC Dashboard (`frontend/src/App.jsx`)**:
   - High-throughput WebSocket stream of network flows.
   - Interactive triage console with status management (`Unresolved` &rarr; `Investigating` &rarr; `Resolved` &rarr; `False Positive`).
   - Dedicated **Viva & Research Benchmarks** page showcasing model comparison tables, confusion matrices, and feature importance rankings.
   - One-click attack injection buttons (`[PortScan]`, `[DoS Flood]`, `[Brute Force]`) for live defense demonstrations.

---

## 📊 Experimental ML Evaluation Summary

The models were evaluated on 6,000 stratified, unseen test flow vectors across 4 traffic categories (`BENIGN`, `PortScan`, `DoS`, `Brute Force`):

| Algorithm | Role | Accuracy | Precision (Macro) | Recall (Macro) | F1-Score (Macro) | FPR on Benign | Inference Latency |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Random Forest** | Primary Ensemble | **100.00%** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **28.87 &micro;s / flow** |
| **Decision Tree** | Rule Baseline | **100.00%** | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 14.20 &micro;s / flow |
| **Logistic Regression** | Linear Baseline | **99.98%** | 0.9998 | 0.9997 | 0.9997 | 0.0000 | 8.45 &micro;s / flow |
| **Isolation Forest** | Unsupervised Anomaly | **87.20%** | N/A (Binary) | N/A (Binary) | 0.8720 | 0.1280 | 35.10 &micro;s / flow |

### Top 5 Most Discriminative Features (Gini Impurity Reduction)
1. **Packet Length Std** (8.70%) &mdash; Differentiates fixed-length probe packets from variable application payloads.
2. **Flow IAT Min** (8.05%) &mdash; Highlights automated burst intervals.
3. **Fwd IAT Min** (6.68%) &mdash; Client-side inter-transmission interval.
4. **Bwd Packet Length Mean** (6.41%) &mdash; Identifies absence of server response in scanning or DoS flooding.
5. **Bwd IAT Min** (6.33%) &mdash; Response timing signature.


## 🚀 Quickstart & Execution Guide

### 1. Prerequisites
- Python 3.10+ (with virtual environment in `backend/venv`)
- Node.js 18+ (for frontend development)

### 2. Retrain ML Models (Optional)
To regenerate benchmark data, retrain all 4 models, and save updated metrics to `backend/app/ml/models/metrics_summary.json`:
```powershell
.\backend\venv\Scripts\python.exe train_models.py
```

### 3. Launch the Complete System
Run the unified server (hosts both FastAPI API, WebSockets, and the React SOC UI):
```powershell
.\backend\venv\Scripts\python.exe run_server.py
```
- **Web Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Interactive OpenAPI Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **WebSocket Streaming**: `ws://localhost:8000/ws/live`

### 4. Running the Controlled Lab Attack Simulations
Open another terminal to test end-to-end detection:
- **Port Scan Simulation**:
  ```powershell
  .\backend\venv\Scripts\python.exe simulation\port_scan.py 127.0.0.1
  ```
- **DoS Flood Simulation**:
  ```powershell
  .\backend\venv\Scripts\python.exe simulation\dos_burst.py 127.0.0.1
  ```
- **Brute Force Simulation**:
  ```powershell
  .\backend\venv\Scripts\python.exe simulation\brute_force.py 127.0.0.1
  ```
*(Or simply click the **PortScan**, **DoS Flood**, or **Brute Force** buttons in the dashboard header!)*

---

## 📁 Repository Directory Structure

```text
NetSentinel AI/
├── backend/
│   ├── app/
│   │   ├── api/                  # REST endpoints: alerts, analytics, capture
│   │   ├── core/state.py         # Global async state, simulator & WebSocket broadcaster
│   │   ├── db/                   # SQLAlchemy relational models & async SQLite session
│   │   ├── engine/
│   │   │   ├── features.py       # Canonical CICIDS2017 49-feature schema
│   │   │   ├── flow_meter.py     # Bidirectional 5-tuple flow assembler
│   │   │   ├── sniffer.py        # Asynchronous Scapy packet capture
│   │   │   └── hybrid_engine.py  # Rule + ML hybrid detection
│   │   ├── ml/
│   │   │   ├── dataset.py        # Benchmark flow generator & CICIDS2017 loader
│   │   │   ├── explainer.py      # Explainable AI (XAI) rationale generator
│   │   │   ├── predictor.py      # Real-time sub-millisecond inference
│   │   │   ├── train.py          # Multi-model training & evaluation pipeline
│   │   │   └── models/           # Serialized models (.joblib) & metrics_summary.json
│   │   └── main.py               # FastAPI application & static asset server
│   └── requirements.txt
├── frontend/                     # Modern React + Vite + Tailwind CSS SOC UI
│   ├── src/
│   │   ├── App.jsx               # Dashboard, Live Inspector, Alerts Triage, ML Research
│   │   └── index.css
│   └── package.json
├── simulation/                   # Controlled Lab Attack Generators
│   ├── normal_traffic.py
│   ├── port_scan.py
│   ├── dos_burst.py
│   └── brute_force.py
├── train_models.py               # Standalone ML training script
├── run_server.py                 # Unified server launcher
└── README.md                     # Academic methodology & documentation
```
