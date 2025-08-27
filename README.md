# Anomalyze.io 🧠📡  
**AI-Powered Real-Time Network Anomaly Detection**

Anomalyze.io is a self-learning, real-time threat detection agent that uses live packet sniffing, adaptive machine learning, and an interactive dashboard to identify anomalies in network traffic — with no retraining required.

---

## 🚀 Features

- **Live Packet Monitoring** with [Scapy](https://scapy.net)
- **Online Machine Learning** with `river` (HalfSpaceTrees)
- **Anomaly Scoring & Logging** per packet
- **Auto-refreshing Dashboard** built in [Streamlit](https://streamlit.io)
- **Data Visualization** using Altair & pandas
- **Modular & Extensible** architecture

---

## 🧰 Tech Stack

| Layer | Tools |
|------|-------|
| Packet Sniffing | `scapy` |
| AI Model | `river`, `IsolationForest` |
| Dashboard | `streamlit`, `altair` |
| Data Logging | `pandas`, `csv` |

---

## 🧪 How It Works

1. `NetdetectionAgent.py` continuously sniffs live network traffic
2. Each packet is scored by a self-learning model (`HalfSpaceTrees`)
3. Anomalies are flagged and logged in `anomaly_log.csv`
4. `dashboard.py` displays results in real-time with auto-refresh

---
