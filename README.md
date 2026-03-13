<div align="center">

# 🤖 AIOPS2026
### AI-Powered IT Operations Platform

*Intelligent endpoint monitoring · ML anomaly detection · Zero commercial tooling*

[![Wazuh](https://img.shields.io/badge/Wazuh-4.14.3-0066CC?style=for-the-badge)](https://wazuh.com)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04_LTS-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Cron](https://img.shields.io/badge/Auto--Scan-Every_15_min-blueviolet?style=for-the-badge)]()
[![Inspired](https://img.shields.io/badge/Inspired_by-keephq%2Fkeep-ff6b6b?style=for-the-badge)](https://github.com/keephq/keep)

---

> 🎓 **Final Year Research Project** — BSc Information Technology
> Kirinyaga University · 2026 · Supervisor: Jotham Wasike

</div>

---

## 📌 Overview

**AIOPS2026** is an open-source AIOps platform that layers a **machine learning anomaly detection engine** on top of [Wazuh](https://wazuh.com) SIEM/XDR. It monitors heterogeneous Windows and Linux endpoints, computes per-endpoint vulnerability risk scores, detects cross-endpoint behavioral anomalies using **Z-score statistical analysis**, and triggers custom alert rules mapped to the **MITRE ATT&CK framework** — all with **zero external Python dependencies**.

Inspired by [Keep](https://github.com/keephq/keep) — a Y Combinator-backed AIOps platform with 11K+ GitHub stars — AIOPS2026 implements the same core intelligence patterns (deduplication, incident correlation, enrichment, workflow automation) in a lightweight form that runs on a single laptop with no cloud infrastructure required.

---

## ⚡ Key Results

<div align="center">

| 📊 Metric | 🔢 Value |
|-----------|---------|
| Anomalies detected (single scan) | **7** |
| Windows endpoints monitored | **2** |
| CVEs detected — ELITEBOOK | **156** |
| CVEs detected — MICROTOWER | **169** |
| ELITEBOOK risk score | **402** |
| MICROTOWER risk score | **433** |
| Ubuntu server risk score | **0 ✅** |
| Scan duration | **< 1 second** |
| Auto-scan interval | **Every 15 minutes** |
| External Python dependencies | **0** |

</div>

---

## 🏗️ Architecture

```
╔═════════════════════════════════════════════════════════╗
║               PRESENTATION LAYER                        ║
║     Wazuh Dashboard  ·  Companion App (Live Results)    ║
╠═════════════════════════════════════════════════════════╣
║               WORKFLOW LAYER  (Keep-inspired)           ║
║     workflow_engine.py  ·  YAML Workflow Files          ║
╠═════════════════════════════════════════════════════════╣
║               ANALYSIS LAYER                            ║
║     Wazuh Manager  ·  aiops_analyzer.py (ML Engine v3)  ║
╠═════════════════════════════════════════════════════════╣
║               STORAGE LAYER                             ║
║     Wazuh Indexer (OpenSearch · :9200)                  ║
║     scan_history.json  ·  anomaly_report.json           ║
╠═════════════════════════════════════════════════════════╣
║               COLLECTION LAYER                          ║
║     Wazuh Agents on Windows Endpoints                   ║
╚═════════════════════════════════════════════════════════╝

  🖥️  Obsidian     Ubuntu 24.04 LTS    192.168.0.100   [Server]
  💻  ELITEBOOK    Windows 10 Ent. N   192.168.0.102   [Agent 001 ✅]
  🖥️  MICROTOWER   Windows 10 Ent.     192.168.0.125   [Agent 002 ⚠️]
```

---

## ✨ Features

### Core ML Engine
- 🔍 **Vulnerability Risk Scoring** — `(Critical×10) + (High×3) + (Medium×1)` per endpoint
- 📊 **Z-Score Anomaly Detection** — flags statistical outliers across the peer group
- 🚨 **Absolute Threshold Rules** — catches endpoints with critical CVEs regardless of peers
- ⏰ **Scheduled Auto-Scan** — cron job runs every 15 minutes automatically

### Keep-Inspired Intelligence Layer
- 🔁 **Alert Deduplication** — same anomaly on same agent only fires once per scan
- 📈 **Noise Ranking** — critical alerts always surface above low-priority ones
- 🗂️ **Incident Correlation** — individual anomalies grouped into named incidents per agent
- 🔍 **Alert Enrichment** — every incident carries OS build, Wazuh version, last keepalive, group
- 📉 **Trend Tracking** — `▲ +5` or `▼ -12` vs previous scan per endpoint
- 🔕 **Alert Silencing** — suppress known/accepted alerts from recurring in every scan
- ✅ **Auto-Resolve** — incidents automatically close and log when conditions clear

### Workflow Automation
- ⚙️ **YAML Workflow Engine** — declarative `when → then` automated responses
- 📋 **4 Built-in Workflows** — critical CVE, agent disconnect, high risk, vulnerability spike
- 📝 **Remediation Logging** — every workflow action saved to `logs/remediation_log.json`

### Alert & Monitoring
- 🔔 **10 Custom Alert Rules** — mapped to MITRE ATT&CK framework
- 🛡️ **MITRE ATT&CK Mapping** — T1562.001, T1110, T1136, T1078, T1587, T1059.001
- 🌐 **Live Dashboard Tab** — companion app renders incidents visually from JSON
- ⚡ **Full Scan in < 1 Second** — across entire monitored environment
- 📋 **Scan History** — full timeline of every scan saved to `scan_history.json`

---

## 🆚 How AIOPS2026 Compares

> Keep (keephq/keep) is a Y Combinator-backed open-source AIOps platform with 11K+ GitHub stars. It validates the exact problem AIOPS2026 solves — but targets startups with cloud infrastructure. AIOPS2026 targets SMEs and resource-constrained environments.

| Feature | Keep (keephq) | AIOPS2026 |
|---------|:-------------:|:---------:|
| Alert management | ✅ | ✅ |
| Incident correlation | ✅ | ✅ |
| Alert enrichment | ✅ | ✅ |
| Alert deduplication | ✅ | ✅ |
| Alert silencing | ✅ | ✅ |
| YAML workflow engine | ✅ | ✅ |
| Auto-resolve incidents | ✅ | ✅ |
| Vulnerability risk scoring | ❌ | ✅ |
| MITRE ATT&CK mapping | ❌ | ✅ |
| Z-score anomaly detection | ❌ | ✅ |
| Scan history & trends | ❌ | ✅ |
| Zero Python dependencies | ❌ | ✅ |
| Runs on a single laptop | ❌ Needs Docker/K8s | ✅ |
| Infrastructure cost | Free (heavy infra) | Free (zero infra) |
| Target environment | Startups / enterprise | SME / academia |

---

## 📁 Repository Structure

```
AIOPS2026/
│
├── 📂 scripts/
│   ├── 🤖 aiops_analyzer.py       # ML anomaly detection engine v3 (main)
│   ├── ⚙️  workflow_engine.py      # Keep-inspired YAML workflow engine
│   ├── 📜 local_rules.xml         # Custom Wazuh alert rules (100000–100060)
│   └── 🚀 wazuh-launch.sh         # One-click Wazuh service launcher
│
├── 📂 workflows/
│   ├── 🔴 critical-cve.yml        # Respond to critical CVEs automatically
│   ├── 🟡 agent-disconnect.yml    # Respond to agent connectivity loss
│   ├── 🟠 high-risk-endpoint.yml  # Flag endpoints exceeding risk threshold
│   └── 🟡 vulnerability-spike.yml # Alert on unusual CVE count spikes
│
├── 📂 dashboard/
│   └── 🖥️  wazuh-companion.html   # Presentation day companion app (5 tabs)
│
├── 📂 docs/
│   ├── 📄 AIOPS2026_Research_Paper.docx
│   └── 📊 AIOPS2026_Presentation.pptx
│
├── 📂 logs/
│   ├── 📋 scan.log                # Cron scan output log
│   └── 📋 remediation_log.json   # Workflow action history
│
├── 📂 agents/
│   └── 📋 windows-agent-setup.md
│
├── 📄 anomaly_report.json         # Latest ML scan output
├── 📄 scan_history.json           # Full scan timeline
└── 📄 README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Ubuntu 24.04 LTS · 8GB+ RAM (16GB recommended) · 50GB+ disk · Python 3.12+

### Step 1 — Install Wazuh
```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

### Step 2 — Clone repo & launch
```bash
git clone https://github.com/rickster-commits/AIOPS2026.git
cd AIOPS2026
sudo bash scripts/wazuh-launch.sh
```

### Step 3 — Enroll Windows agents
Follow [`agents/windows-agent-setup.md`](agents/windows-agent-setup.md)

### Step 4 — Load custom rules
```bash
sudo cp scripts/local_rules.xml /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
```

### Step 5 — Set up auto-scan (every 15 min)
```bash
mkdir -p logs
(crontab -l; echo "*/15 * * * * cd ~/AIOPS2026 && python3 scripts/aiops_analyzer.py >> logs/scan.log 2>&1") | crontab -
```

### Step 6 — Run ML engine
```bash
python3 scripts/aiops_analyzer.py
```

### Step 7 — Run workflow engine
```bash
python3 scripts/workflow_engine.py
```

---

## 🧠 ML Engine — How It Works

```
┌─────────────────────────────────────────────────────────┐
│  1️⃣  Authenticate with Wazuh REST API (:55000)           │
│  2️⃣  Enumerate all enrolled agents + enrich context      │
│  3️⃣  Query Wazuh Indexer for CVE state data (:9200)      │
│      POST /wazuh-states-vulnerabilities-*/_search        │
│  4️⃣  Compute risk score per endpoint                     │
│      Score = (Critical×10) + (High×3) + (Medium×1)      │
│  5️⃣  Show trend vs previous scan (▲ ▼ →)                 │
│  6️⃣  Z-score cross-endpoint analysis                     │
│      Z = (Score − Mean) ÷ StdDev                        │
│      🚩 Flag if Z > 2.5 standard deviations              │
│  7️⃣  Apply absolute threshold rules                      │
│  8️⃣  Deduplicate → Silence → Rank → Correlate incidents  │
│  9️⃣  Output color-coded terminal report                  │
│  🔟  Write anomaly_report.json + append scan_history     │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ Workflow Engine — How It Works

```
┌─────────────────────────────────────────────────────────┐
│  1️⃣  Load anomaly_report.json                           │
│  2️⃣  Load all .yml files from workflows/                │
│  3️⃣  For each workflow — evaluate trigger + filters      │
│  4️⃣  If match found — execute all actions               │
│      → notify   (print alert message)                   │
│      → remediate (log fix instructions)                  │
│      → tag      (label the endpoint)                    │
│      → log      (append to remediation_log.json)        │
│  5️⃣  Write full action history to logs/                 │
└─────────────────────────────────────────────────────────┘
```

**Example workflow:**
```yaml
id: critical-cve-response
description: Immediate response when a critical CVE is detected

trigger:
  type: anomaly
  filters:
    - key: type
      value: CRITICAL CVE

actions:
  - name: notify
    message: "CRITICAL CVE on {agent} ({ip}) — patch immediately"
  - name: remediate
    message: "Run Windows Update on {agent} — OS: {os}"
  - name: log
    file: logs/remediation_log.json
```

---

## 🔔 Custom Alert Rules

| Rule ID | Level | Description | MITRE ATT&CK |
|---------|:-----:|-------------|:------------:|
| 100001 | 🔴 12 | Agent disconnected | T1562.001 |
| 100002 | 🔴 12 | Agent stopped | T1562.001 |
| 100003 | 🟢 6 | Agent reconnected | — |
| 100010 | 🟠 10 | Multiple failed logins — brute force | T1110 |
| 100020 | 🔴 12 | New user account created | T1136 |
| 100021 | 🔴 14 | User added to Administrators group | T1078 |
| 100030 | 🔴 15 | Malware detected by Windows Defender | T1587 |
| 100040 | 🔴 12 | Suspicious PowerShell execution | T1059.001 |
| 100060 | 🔴 14 | 5+ anomalies on endpoint in 5 minutes | Compound |

---

## 🧪 Vulnerability Assessment Results

| Endpoint | 🔴 Critical | 🟠 High | 🟡 Medium | Risk Score | Verdict |
|----------|:-----------:|:-------:|:---------:|:----------:|---------|
| ELITEBOOK | 1 | 119 | 35 | **402** | ⚠️ At Risk |
| MICROTOWER | 1 | 129 | 36 | **433** | ⚠️ At Risk |
| Obsidian (Server) | 0 | 0 | 0 | **0** | ✅ Clean |

**Z-score stats:** Mean = 278.3 · Std Dev = 197.2

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
6. M. Fortis et al., "Keep — Open Source Alert Management & AIOps," GitHub, 2024. https://github.com/keephq/keep
7. NIST, *National Vulnerability Database*. https://nvd.nist.gov

---

<div align="center">

*Built with ❤️ using Wazuh · Python · Ubuntu · Inspired by keephq/keep*

⭐ Star this repo if you found it useful!

</div>
