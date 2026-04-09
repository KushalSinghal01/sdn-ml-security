# SDN ML Security System 🔐

ML-Based Attack Detection and Mitigation System using Software Defined Networking (SDN)

## Project Overview

This project implements a real-time DDoS attack detection and mitigation system using:
- **POX SDN Controller** — Network traffic management
- **Machine Learning** — Random Forest model for attack detection
- **Mininet** — Network topology simulation
- **Flask Dashboard** — Real-time monitoring and control

## Architecture
```
Mininet (Network Simulation)
        ↓
POX Controller (ml_mitigation.py)
        ↓
Flask Server (dashboard_server.py)
        ↓
Browser Dashboard (dashboard.html)
```
## Features

- Real-time attack detection (SYN, UDP, ICMP, HTTP Flood)
- ML-based traffic classification
- Automatic attacker IP blocking
- Live dashboard with cyber theme
- IP unblock functionality
- Redundant controller topology (No SPOF)

## Project Files

| File | Description |
|------|-------------|
| `ml_mitigation.py` | POX controller module — attack detection & blocking |
| `dashboard.html` | Cyber-themed web dashboard |
| `dashboard_server.py` | Flask REST API server |
| `sdn_redundant.py` | Redundant topology — 2 controllers, 4 switches, 6 hosts |
| `sdn_new_topology.py` | Hybrid mesh-tree topology — 4 controllers, 5 switches, 18 hosts |
| `sdn_rf_model.pkl` | Trained Random Forest ML model |
| `sdn_ml_model.py` | ML model training script |
| `dataset_sdn.csv` | SDN traffic dataset |

## Requirements

- Ubuntu 22.04
- Python 3.x
- Mininet
- POX Controller
- Flask, Flask-CORS
- scikit-learn, pandas, numpy

## Installation

```bash
# Install dependencies
pip install flask flask-cors scikit-learn pandas numpy

# Clone repository
git clone https://github.com/KushalSinghal01/sdn-ml-security.git
cd sdn-ml-security
```

## How to Run

### Step 1 — Start Flask Dashboard Server
```bash
python3 dashboard_server.py
```

### Step 2 — Start POX Controllers
```bash
# Controller 1
cd ~/Desktop/pox
python3 pox.py log.level --DEBUG ext.ml_mitigation openflow.of_01 --port=6633

# Controller 2
python3 pox.py log.level --DEBUG ext.ml_mitigation openflow.of_01 --port=6634
```

### Step 3 — Start Mininet Topology
```bash
sudo mn -c
sudo python3 sdn_redundant.py
```

### Step 4 — Open Dashboard
open dashboard.html directly in Firefox browser.
### Step 5 — Test Attacks
```bash
# SYN Flood
h5 hping3 -S --flood -p 80 10.0.0.6

# UDP Flood
h5 hping3 --udp --flood -p 80 10.0.0.6

# ICMP Flood
h5 hping3 --icmp --flood 10.0.0.6

# HTTP Flood
h5 hping3 -A --flood -p 80 10.0.0.6
```

## Dashboard Access

Dashboard is password protected.
Contact the project team for access credentials.
## Topology

### Redundant Topology (sdn_redundant.py)
### Hybrid Mesh-Tree Topology (sdn_new_topology.py)
## Team

- Kushal Singhal
- Sneha
- Mannat

## License

MIT License
