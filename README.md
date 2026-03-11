# AIOPS2026 🛡️

> **AI-Powered IT Operations Platform** — BSc Information Technology Final Project  
> Kirinyaga University | 2026

---

## Overview

AIOPS2026 is an open-source AIOps platform built on top of **Wazuh**, designed to monitor, detect, and respond to security and operational incidents across heterogeneous environments (Ubuntu + Windows endpoints) using AI/ML techniques.

This project demonstrates how Artificial Intelligence for IT Operations (AIOps) can be applied in real-world infrastructure to:
- Detect anomalies and security threats in real-time
- Automate incident response
- Predict failures before they occur
- Centralize log management across multiple machines

---

## Architecture

```
Ubuntu Laptop (AIOps Server)
├── Wazuh Manager       — Core analysis & detection engine
├── Wazuh Indexer       — Data storage layer (OpenSearch)
├── Wazuh Dashboard     — Web visualization interface
├── Filebeat            — Log shipping pipeline
└── ML Anomaly Layer    — Custom Python anomaly detection
        │
        ├── Windows Endpoint 1 (Wazuh Agent)
        ├── Windows Endpoint 2 (Wazuh Agent)
        └── Windows Endpoint 3 (Wazuh Agent)
```

---

## Features

- 🔍 **Real-time threat detection** across Ubuntu and Windows machines
- 📊 **Centralized dashboard** with live metrics and alerts
- 🤖 **ML anomaly detection** layer on top of Wazuh
- 🔧 **Automated remediation** scripts for common incidents
- 📋 **Vulnerability assessment** and configuration auditing
- 📁 **File integrity monitoring** across all endpoints
- 🚨 **Custom alert rules** tailored for the environment

---

## Project Structure

```
AIOPS2026/
├── agents/             # Agent configuration & deployment guides
├── dashboard/          # Companion app & dashboard configs
│   └── wazuh-companion.html  # Presentation day launcher app
├── docs/               # Documentation & research notes
├── research/           # Research paper, findings & references
├── scripts/            # Automation & utility scripts
│   └── wazuh-launch.sh       # One-click service launcher
└── install-files/      # Original Wazuh installation files
```

---

## Getting Started

### Prerequisites
- Ubuntu 22.04 / 24.04 LTS
- Minimum 4GB RAM (8GB+ recommended)
- 50GB free disk space
- Internet connection

### Installation

**1. Clone the repository:**
```bash
git clone https://github.com/rickster-commits/AIOPS2026.git
cd AIOPS2026
```

**2. Install Wazuh (all-in-one):**
```bash
curl -sO https://packages.wazuh.com/4.11/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

**3. Launch all services:**
```bash
chmod +x scripts/wazuh-launch.sh
sudo bash scripts/wazuh-launch.sh
```

**4. Access the dashboard:**
```
URL:      https://localhost
Username: admin
Password: [generated during install]
```

---

## Connecting Windows Agents

1. Download the Wazuh Windows agent from the dashboard
2. Run the installer on the Windows machine
3. Point it to your Ubuntu server IP
4. Agent appears in dashboard within 60 seconds

Full guide: [`agents/windows-agent-setup.md`](agents/windows-agent-setup.md)

---

## Tech Stack

| Component | Technology |
|---|---|
| SIEM / XDR | Wazuh 4.11 |
| Data Storage | OpenSearch (Wazuh Indexer) |
| Visualization | Wazuh Dashboard |
| Log Shipping | Filebeat |
| ML Layer | Python 3.12, scikit-learn |
| Scripting | Bash |
| OS | Ubuntu 24.04 LTS |

---

## Research

This project accompanies a research paper exploring the integration of ML techniques with Wazuh for enhanced anomaly detection. Key research areas:

- AIOps frameworks and methodologies
- ML-based anomaly detection in SIEM systems
- Automated incident response patterns
- Performance evaluation of detection accuracy

Paper: [`research/aiops2026-paper.pdf`](research/aiops2026-paper.pdf) *(coming soon)*

---

## Author

**Alfrick Achoki (Ricky)**  
BSc Information Technology  
Kirinyaga University  
Registration: CT100/G/14089/89  
GitHub: [@rickster-commits](https://github.com/rickster-commits)

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

> *Built with 🔥 on Ubuntu 24.04 — because real AIOps runs on real iron.*
