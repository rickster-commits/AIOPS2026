<div align="center">

# 🤖 AIOPS2026
### AI-Powered IT Operations Platform

*Intelligent endpoint monitoring · ML anomaly detection · Zero commercial tooling*

[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.3-0066CC?style=for-the-badge&logo=data:image/png;base64,iVBORw0KGgo=)](https://wazuh.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![GitHub](https://img.shields.io/badge/GitHub-rickster--commits-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/rickster-commits/AIOPS2026)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

---

> 🎓 **Final Year Research Project** — BSc Information Technology  
> Kirinyaga University · 2026 · Supervisor: Jotham Wasike

</div>

---

## 📌 Overview

**AIOPS2026** is an open-source AIOps platform that layers a **machine learning anomaly detection engine** on top of [Wazuh](https://wazuh.com) SIEM/XDR. It monitors heterogeneous Windows and Linux endpoints, computes per-endpoint vulnerability risk scores, detects cross-endpoint behavioral anomalies using **Z-score statistical analysis**, and triggers custom alert rules mapped to the **MITRE ATT&CK framework** — all with **zero external Python dependencies**.

Built specifically for small-to-medium enterprises that lack the budget for commercial AIOps platforms but still need intelligent, adaptive threat detection.

---

## ⚡ Key Results

<div align="center">

| 📊 Metric | 🔢 Value |
|-----------|---------|
| Anomalies detected (single scan) | **7** |
| Windows endpoints monitored | **2** |
| CVEs detected (ELITEBOOK) | **156** |
| CVEs detected (MICROTOWER) | **169** |
| ELITEBOOK risk score | **402** |
| MICROTOWER risk score | **433** |
| Ubuntu server risk score | **0 ✅** |
| Full scan duration | **< 2 seconds** |
| External Python dependencies | **0** |

</div>

---

## 🏗️ Architecture

```
╔═════════════════════════════════════════════════════════╗
║                  PRESENTATION LAYER                     ║
║          Wazuh Dashboard  ·  Companion App              ║
╠═════════════════════════════════════════════════════════╣
║                   ANALYSIS LAYER                        ║
║       Wazuh Manager  ·  aiops_analyzer.py (ML)          ║
╠═════════════════════════════════════════════════════════╣
║                    STORAGE LAYER                        ║
║         Wazuh Indexer  (OpenSearch  ·  :9200)           ║
╠═════════════════════════════════════════════════════════╣
║                  COLLECTION LAYER                       ║
║           Wazuh Agents on Windows Endpoints             ║
╚═════════════════════════════════════════════════════════╝

  🖥️  Obsidian     Ubuntu 24.04 LTS    192.168.0.100   [Server]
  💻  ELITEBOOK    Windows 10 Ent.     192.168.0.102   [Agent 001 ✅]
  🖥️  MICROTOWER   Windows 10 Ent.     192.168.0.125   [Agent 002 ⚠️]
```

---

## ✨ Features

- 🔍 **Vulnerability Risk Scoring** — aggregates CVEs per endpoint using `(Critical×10) + (High×3) + (Medium×1)`
- 📊 **Z-Score Anomaly Detection** — flags endpoints that are statistical outliers vs. their peer group
- 🚨 **Absolute Threshold Rules** — catches endpoints with critical CVEs or risk scores above safe limits regardless of peers
- 🔔 **10 Custom Alert Rules** — agent connectivity, brute force, privilege escalation, malware, PowerShell, compound threats
- 🛡️ **MITRE ATT&CK Mapping** — rules linked to T1562.001 (Defense Evasion) and other tactics
- ⚡ **Zero External Dependencies** — ML engine uses Python 3.12 stdlib only
- 🚀 **Full Scan in < 2 Seconds** — across the entire monitored environment
- 📋 **JSON Output** — results persisted to `anomaly_report.json` for downstream integrations
- 🌐 **Open Source** — fully replicable on commodity hardware at zero licensing cost

---

## 📁 Repository Structure

```
AIOPS2026/
│
├── 📂 scripts/
│   ├── 🤖 aiops_analyzer.py       # ML anomaly detection engine (main)
│   ├── 📜 local_rules.xml         # Custom Wazuh alert rules (100000–100060)
│   └── 🚀 wazuh-launch.sh         # One-click Wazuh service launcher
│
├── 📂 dashboard/
│   └── 🖥️  wazuh-companion.html   # Presentation day companion app
│
├── 📂 docs/
│   ├── 📄 AIOPS2026_Research_Paper.docx
│   └── 📊 AIOPS2026_Presentation.pptx
│
├── 📂 agents/
│   └── 📋 windows-agent-setup.md  # Windows agent enrollment guide
│
├── 📂 research/                   # Supporting literature & references
│
└── 📄 README.md
```

---

## 🚀 Quick Start

### Prerequisites

- Ubuntu 24.04 LTS
- 8GB+ RAM (16GB recommended)
- 50GB+ free disk space
- Python 3.12+

### Step 1 — Install Wazuh (all-in-one)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

### Step 2 — Launch all services

```bash
sudo bash scripts/wazuh-launch.sh
```

> 🌐 Dashboard available at `https://localhost`

### Step 3 — Enroll Windows agents

Follow [`agents/windows-agent-setup.md`](agents/windows-agent-setup.md) for step-by-step instructions.

### Step 4 — Load custom alert rules

```bash
sudo cp scripts/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

Verify rules loaded:
```bash
sudo grep "AIOPS2026" /var/ossec/logs/ossec.log | tail -5
```

### Step 5 — Run the ML engine

```bash
python3 scripts/aiops_analyzer.py
```

Results print to terminal and are saved to `anomaly_report.json`. ✅

---

## 🧠 ML Engine — How It Works

```
┌─────────────────────────────────────────────────────┐
│  1️⃣   Authenticate with Wazuh REST API (:55000)      │
│  2️⃣   Enumerate all enrolled agents                  │
│  3️⃣   Query Wazuh Indexer for CVE state data (:9200) │
│       POST /wazuh-states-vulnerabilities-*/_search   │
│  4️⃣   Compute risk score per endpoint                │
│       Score = (Critical×10) + (High×3) + (Medium×1) │
│  5️⃣   Z-score cross-endpoint analysis                │
│       Z = (Score − Mean) ÷ StdDev                   │
│       🚩 Flag if Z > 2.5 standard deviations         │
│  6️⃣   Apply absolute threshold rules                 │
│       🚩 Any Critical CVE present                    │
│       🚩 High CVE count > 50                         │
│       🚩 Risk score > 200                            │
│  7️⃣   Output color-coded terminal report             │
│  8️⃣   Write anomaly_report.json                      │
└─────────────────────────────────────────────────────┘
```

---

## 🔔 Custom Alert Rules

| Rule ID | Level | Description | MITRE ATT&CK |
|---------|:-----:|-------------|:------------:|
| 100001 | 🔴 12 | Agent disconnected — endpoint requires attention | T1562.001 |
| 100002 | 🔴 12 | Agent stopped — possible service disruption | T1562.001 |
| 100003 | 🟢 6 | Agent reconnected after disconnection | — |
| 100010 | 🟠 10 | Multiple failed logins — possible brute force | T1110 |
| 100020 | 🔴 12 | New user account created on endpoint | T1136 |
| 100021 | 🔴 14 | User added to Administrators group | T1078 |
| 100030 | 🔴 15 | Malware detected by Windows Defender | T1587 |
| 100040 | 🔴 12 | Suspicious PowerShell execution detected | T1059.001 |
| 100060 | 🔴 14 | 5+ anomalies on same endpoint in 5 minutes | Compound |

> All rules live in `scripts/local_rules.xml` under the `aiops2026` rule group.  
> Validated in Wazuh Dashboard under **Server Management → Rules → search "AIOPS2026"**

---

## 🧪 Vulnerability Assessment Results

| Endpoint | 🔴 Critical | 🟠 High | 🟡 Medium | Risk Score | Verdict |
|----------|:-----------:|:-------:|:---------:|:----------:|---------|
| ELITEBOOK | 1 | 119 | 35 | **402** | ⚠️ At Risk |
| MICROTOWER | 1 | 129 | 36 | **433** | ⚠️ At Risk |
| Obsidian (Server) | 0 | 0 | 0 | **0** | ✅ Clean |

**Cross-endpoint Z-score stats:** Mean = 278.3 · Std Dev = 197.2

---

## 👥 Team

| Name | Registration No. |
|------|-----------------|
| **Alfrick Achoki** | CT100/G/14089/21 |
| Shadrack Kithua Ndunguu | CT100/G/15934/22 |
| Maureen Mwangi | CT100/G/17587/22 |
| Njuguna Peter | CT100/G/15912/22 |
| Kimutai Nahashon | CT100/G/15975/22 |

**🎓 Supervisor:** Jotham Wasike  
**🏫 Institution:** Kirinyaga University — BSc Information Technology  

---

## 📚 References

1. Wazuh Inc., *Wazuh Documentation v4.14*, 2026. https://documentation.wazuh.com
2. Y. Dang, Q. Lin, P. Huang, "AIOps: Real-World Challenges and Research Innovations," *ICSE-SEIP*, 2019.
3. P. Notaro, J. Cardoso, M. Gerndt, "A Survey of AIOps Methods for Failure Management," *ACM TIST*, 2021.
4. V. Chandola, A. Banerjee, V. Kumar, "Anomaly Detection: A Survey," *ACM Computing Surveys*, 2009.
5. F. T. Liu, K. M. Ting, Z. H. Zhou, "Isolation Forest," *ICDM*, 2008.
6. NIST, *National Vulnerability Database*. https://nvd.nist.gov

---

<div align="center">

*Built with ❤️ using Wazuh · Python · Ubuntu · No commercial tools required*

⭐ Star this repo if you found it useful!

</div>
