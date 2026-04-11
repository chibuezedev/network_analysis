# NIDS — Network Intrusion Detection System

A real-time network security monitoring system combining deep learning-based traffic classification with a live packet capture engine and a desktop management interface.

---

## What This System Does

NIDS monitors every device connected to your network in real time. It captures network traffic, extracts 76 statistical features from each flow, and sends them to a trained BiLSTM+Attention deep learning model that classifies the traffic as benign or one of 9 attack types. When an attack is detected above the confidence threshold, an alert is raised immediately in the UI with a sound notification. Administrators can then block, whitelist, or ignore the detected threat directly from the interface.

---

## System Architecture
```
┌─────────────────────────────────────────────────────────────┐
│                    DESKTOP APPLICATION                       │
│                    main.py  (Tkinter UI)                     │
│                                                              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │Dashboard │ │  Live    │ │  Alerts  │ │  Whitelist / │  │
│  │& Logs    │ │ Traffic  │ │  Panel   │ │  Blocked     │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────────┘  │
│                      │                                       │
│              MonitorService                                  │
│              RealCapture (Scapy)                             │
│              ↓ ARP / DHCP / TCP / UDP flows                 │
└─────────────────────────────────────────────────────────────┘
         │ HTTP POST /predict              ↑ Webhook :8001
         ▼                                │
┌─────────────────────────────────────────────────────────────┐
│                  ML API SERVER  (FastAPI :8000)              │
│                  api_server.py                               │
│                                                              │
│  BiLSTM+Attention Model  ←  AdvancedPreprocessor            │
│  /predict  /predict/batch  /inject-attack  /status          │
└─────────────────────────────────────────────────────────────┘
         ↑
    Phone / browser hits /inject-attack to simulate attacks
```

---

## Project Structure
```
network_analysis/
├── main.py                        # Entry point — starts UI + webhook listener
├── attack_sim.py                  # Standalone attack traffic simulator
├── db/
│   └── database.py                # SQLite — devices, alerts, whitelist, blocked
├── services/
│   └── monitor.py                 # Capture engine + MonitorService
├── ui/
│   ├── main_window.py             # Sidebar navigation, start/stop, sound toggle
│   ├── dashboard.py               # Live stats, event log
│   ├── devices.py                 # Live traffic — all seen devices
│   ├── alerts.py                  # Threat alerts — block/whitelist/ignore
│   ├── blocked.py                 # Blocked IPs management
│   ├── whitelist.py               # Trusted devices management
│   └── theme.py                   # Dark theme, colours, fonts
└── ../network_ids_system/         # ML training + API
    ├── api/
    │   └── api_server.py          # FastAPI ML server
    ├── preprocessors/
    │   └── advanced_preprocessor.py
    ├── models/
    │   └── architectures.py
    ├── outputs/
    │   ├── production_model.h5    # Trained BiLSTM+Attention model
    │   ├── model_metadata.json
    │   └── preprocessors/
    │       └── preprocessor.pkl
    └── train_pipeline.py
```

---

## Running the System

### 1. Start the ML API Server
```bash
cd network_ids_system/api
python api_server.py
# Runs on http://0.0.0.0:8000
```

### 2. Start the Desktop Application
```bash
# Simulation mode (no admin needed — good for demos)
python main.py

# Live capture mode (requires admin/root)
python main.py --live
```

> On Windows, run as Administrator for live capture and firewall blocking to work.

---

## Modes of Operation

### Simulation Mode
Generates random device activity and attack events internally. No network access required. Useful for demonstrating the UI and alert system without a live network.

### Live Capture Mode
Uses Scapy to sniff real packets on the best available interface. Automatically prefers hotspot/LAN interfaces (`192.168.x.x`, `172.16–31.x.x`, `10.x.x.x`). Processes ARP, DHCP, TCP, and UDP traffic. Only local IP addresses are tracked — internet server IPs are filtered out.

---

## How Traffic is Classified

1. **Packet arrives** → Scapy captures it on the selected interface
2. **Flow tracking** → Packets are grouped into flows by (src_ip, dst_ip, sport, dport, proto)
3. **Flow expires** → After 10 seconds of inactivity, the flow is finalised
4. **Feature extraction** → 76 statistical features are computed (packet counts, byte counts, inter-arrival times, TCP flags, window sizes, etc.)
5. **Model prediction** → Features are preprocessed and sent to the BiLSTM+Attention model via `/predict`
6. **Alert decision** → If predicted class ≠ Benign and confidence ≥ 60%, an alert is raised
7. **UI update** → Alert appears in the Alerts panel with sound, badge updates, and dashboard log entry

### Hotspot/NAT Handling
Phones connected via mobile hotspot have their traffic NAT'd through the host laptop. The system handles this by snooping DHCP ACK packets to learn phone IP→MAC mappings, tracking ARP broadcasts to register phone presence, and periodically synthesising a feature vector for ARP-only devices so they still appear in the device list.

---

## Attack Types Detected

| Class | Description |
|---|---|
| Benign | Normal traffic — no action |
| Analysis | Traffic analysis / probing |
| Backdoor | Unauthorised persistent access |
| DoS | Denial of Service flood |
| Exploits | Vulnerability exploitation |
| Fuzzers | Random malformed payload injection |
| Generic | Generic cryptographic/protocol attacks |
| Reconnaissance | Port scanning, network mapping |
| Shellcode | Code injection attempts |
| Worms | Self-propagating malware behaviour |

---

## Attack Injection (Demo)

Simulate any attack from a phone browser while NIDS is running:
```
http://<HOST_IP>:8000/inject-attack?attack=dos&src_ip=172.20.10.5
http://<HOST_IP>:8000/inject-attack?attack=recon&src_ip=172.20.10.5
http://<HOST_IP>:8000/inject-attack?attack=fuzzer&src_ip=172.20.10.5
http://<HOST_IP>:8000/inject-attack?attack=backdoor&src_ip=172.20.10.5
http://<HOST_IP>:8000/inject-attack?attack=shellcode&src_ip=172.20.10.5
http://<HOST_IP>:8000/inject-attack?attack=generic&src_ip=172.20.10.5
```

Replace `HOST_IP` with the laptop's hotspot IP (e.g. `172.20.10.4`). Set `src_ip` to any non-whitelisted IP to appear as the attacker in the UI. Do not use the host machine's own IP — it is whitelisted and alerts will be suppressed.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Server health check |
| GET | `/status` | Model info and metrics |
| POST | `/predict` | Single flow classification |
| POST | `/predict/batch` | Batch classification |
| GET | `/classes` | All attack class descriptions |
| GET | `/inject-attack` | Inject simulated attack into NIDS |
| POST | `/debug-predict` | Debug — raw + processed features with result |

---

## Model

**Architecture:** Bidirectional LSTM with Attention pooling  
**Dataset:** CIC-UNSW-NB15 — 448,915 network flows, 10 classes  
**Input:** 76 features per flow  
**Preprocessing:** StandardScaler via AdvancedPreprocessor  
**Confidence threshold:** 60% (live capture) / 20% (injected attacks)  

---

## Ports

| Port | Service |
|---|---|
| 8000 | ML API Server — accessible from all hotspot devices |
| 8001 | NIDS Webhook listener — internal only (127.0.0.1) |

---

## Dependencies
```bash
pip install scapy numpy requests fastapi uvicorn tensorflow pydantic
```