**AIOPS2026 — AI-Powered IT Operations Platform**  
*A final year BSc Information Technology project — Kirinyaga University, 2026*  
   
   
   
   
   
 [![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAADUlEQVR4nGP4//8/AwAI/AL+p5qgoAAAAABJRU5ErkJggg==)  
](LICENSE "LICENSE")  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AUBBAsUeCE4yeIiT9CRVMWGAjJK2CbjNzVGcAAPzF2qu7Wl9PAAB47XoA/vcF8exqpY4AAAAASUVORK5CYII=)  
**What is AIOPS2026?**  
AIOPS2026 is an open-source AIOps platform that layers a machine learning anomaly detection engine on top of [Wazuh SIEM/XDR. It monitors heterogeneous endpoints, computes risk scores, detects behavioral anomalies using Z-score analysis, and fires custom alert rules mapped to MITRE ATT&CK — all with zero external Python dependencies.](https://wazuh.com "https://wazuh.com")  
Built for small-to-medium enterprises that need intelligent IT operations without commercial tooling costs.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsad4EjtY9fewnUms4E2ELcGWmTmrKwAA/uLeqrU6vp4AAPDa/gDzWAM6QQXRdAAAAABJRU5ErkJggg==)  
**Architecture**  
┌─────────────────────────────────────────────────────┐  
 │              PRESENTATION LAYER                     │  
 │       Wazuh Dashboard  +  Companion App             │  
 ├─────────────────────────────────────────────────────┤  
 │               ANALYSIS LAYER                        │  
 │     Wazuh Manager  +  aiops_analyzer.py (ML)        │  
 ├─────────────────────────────────────────────────────┤  
 │               STORAGE LAYER                         │  
 │        Wazuh Indexer (OpenSearch, :9200)            │  
 ├─────────────────────────────────────────────────────┤  
 │              COLLECTION LAYER                       │  
 │         Wazuh Agents on Windows Endpoints           │  
 └─────────────────────────────────────────────────────┘  
   
 Server:     Obsidian     Ubuntu 24.04 LTS   192.168.0.100  
 Agent 001:  ELITEBOOK    Windows 10 Ent.    192.168.0.102  
 Agent 002:  MICROTOWER   Windows 10 Ent.    192.168.0.125  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsScYxpg/h5VMYARvRrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA224BcUMk6pDAAAAAElFTkSuQmCC)  
**Features**  
🔍**Vulnerability Risk Scoring** — aggregates CVEs per endpoint using (Critical×10) + (High×3) + (Medium×1)  
📊**Z-Score Anomaly Detection** — flags endpoints that are statistical outliers vs. their peer group  
🚨**Absolute Threshold Rules** — catches endpoints with critical CVEs or scores above safe limits regardless of peers  
🔔**10 Custom Alert Rules** — agent connectivity, brute force, privilege escalation, malware, PowerShell, compound threats  
🛡️**MITRE ATT&CK Mapping** — rules linked to T1562.001 and other tactics  
⚡**Zero Dependencies** — ML engine uses Python 3.12 stdlib only  
🚀**Full Scan in < 2 seconds** — across the 3-endpoint test environment  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANElEQVR4nO3OQQmAABRAsSdYxKY/jbnMIJ7FCt5E2BJsmZmt2gMA4C+Otbqr8+sJAACvXQ85TgYRMv3/cwAAAABJRU5ErkJggg==)  
**Results**  
| | | | | | |  
|-|-|-|-|-|-|  
| **Endpoint** | **Critical** | **High** | **Medium** | **Risk Score** | **Status** |   
| ELITEBOOK | 1 | 119 | 35 | **402** | ⚠️ At Risk |   
| MICROTOWER | 1 | 129 | 36 | **433** | ⚠️ At Risk |   
| Obsidian (Server) | 0 | 0 | 0 | **0** | ✅ Clean |   
   
**7 anomalies detected** in a single scan · Mean risk score: 278.3 · Std dev: 197.2  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAM0lEQVR4nO3OUQmAQBBAwSdcjsu6HYxoDsEK/okwk2COmdnVGQAAf3GtalX76wkAAK/dDxFWBDkFf6+SAAAAAElFTkSuQmCC)  
**Repository Structure**  
AIOPS2026/  
 ├── scripts/  
 │   ├── aiops_analyzer.py       # ML anomaly detection engine  
 │   ├── local_rules.xml         # Custom Wazuh alert rules (100000–100060)  
 │   └── wazuh-launch.sh         # One-click service launcher  
 ├── dashboard/  
 │   └── wazuh-companion.html    # Presentation day companion app  
 ├── docs/  
 │   ├── AIOPS2026_Research_Paper.docx  
 │   └── AIOPS2026_Presentation.pptx  
 ├── agents/  
 │   └── windows-agent-setup.md  # Agent enrollment guide  
 ├── research/                   # Supporting literature  
 └── README.md  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OQQmAABRAsSfYxZo/jVEMYQLPJrCCNxG2BFtmZquOAAD4i3Ot7mr/egIAwGvXA4rLBc059ysnAAAAAElFTkSuQmCC)  
**Quick Start**  
**1. Prerequisites**  
- Ubuntu 24.04 LTS  
- 8GB+ RAM (16GB recommended)  
- 50GB+ free disk space  
**2. Install Wazuh (all-in-one)**  
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh  
 sudo bash wazuh-install.sh -a  
   
**3. Launch services**  
sudo bash scripts/wazuh-launch.sh  
   
Dashboard available at https://localhost  
**4. Enroll Windows agents**  
Follow the guide in [agents/windows-agent-setup.md](agents/windows-agent-setup.md "agents/windows-agent-setup.md")  
**5. Load custom rules**  
sudo cp scripts/local_rules.xml /var/ossec/etc/rules/local_rules.xml  
 sudo systemctl restart wazuh-manager  
   
**6. Run the ML anomaly detection engine**  
python3 scripts/aiops_analyzer.py  
   
Results are printed to terminal and saved to anomaly_report.json.  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhZscYahheJwqQgQU2QtIq6DIze3UGAMBf3Gu1VcfXEwAAXrseoqcEQXyAWBgAAAAASUVORK5CYII=)  
**ML Engine — How It Works**  
1. Authenticate with Wazuh REST API (port 55000)  
 2. Enumerate all active agents  
 3. Query Wazuh Indexer for vulnerability state data  
    POST https://localhost:9200/wazuh-states-vulnerabilities-*/_search  
 4. Compute risk score per endpoint  
    Risk Score = (Critical × 10) + (High × 3) + (Medium × 1)  
 5. Run Z-score cross-endpoint analysis  
    Z = (Score − Mean) ÷ Std Dev   →   Flag if Z > 2.5  
 6. Apply absolute threshold rules  
    - Any Critical CVE present → flag  
    - High CVE count > 50     → flag  
    - Risk score > 200        → flag  
 7. Output report + write anomaly_report.json  
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSPBCUZfE2IYmVDBhAU2QtIq6DIzW7UHAMBfnGt1V8fXEwAAXrse/xcF7U7sx4wAAAAASUVORK5CYII=)  
**Custom Alert Rules**  
| | | | |  
|-|-|-|-|  
| **Rule ID** | **Level** | **Description** | **MITRE** |   
| 100001 | 12 | Agent disconnected | T1562.001 |   
| 100002 | 12 | Agent stopped | T1562.001 |   
| 100003 | 6 | Agent reconnected | — |   
| 100010 | 10 | Multiple failed logins (brute force) | T1110 |   
| 100020 | 12 | New user account created | T1136 |   
| 100021 | 14 | User added to Administrators group | T1078 |   
| 100030 | 15 | Malware detected by Windows Defender | T1587 |   
| 100040 | 12 | Suspicious PowerShell execution | T1059.001 |   
| 100060 | 14 | 5+ anomalies on same endpoint within 5 min | Compound |   
   
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OQQ2AQBAAsSE5CbzRujLwhwQMYIEfIWkVdJuZozoDAOAvrlWtav96AgDAa/cDEXQEKquakOYAAAAASUVORK5CYII=)  
**Team**  
| | |  
|-|-|  
| **Name** | **Reg No** |   
| Alfrick Achoki | CT100/G/14089/21 |   
| Shadrack Kithua Ndunguu | CT100/G/15934/22 |   
| Maureen Mwangi | CT100/G/17587/22 |   
| Njuguna Peter | CT100/G/15912/22 |   
| Kimutai Nahashon | CT100/G/15975/22 |   
   
**Supervisor:** Jotham Wasike  
   
 **Institution:** Kirinyaga University — BSc Information Technology  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANUlEQVR4nO3OMQ2AABAAsSNhZscVjnidKEAGFtgISaugy8zs1RkAAH9xr9VWHV9PAAB47XoAor8EPg1yCpUAAAAASUVORK5CYII=)  
**References**  
1. Wazuh Inc., "Wazuh Documentation v4.14," 2026. [https://documentation.wazuh.com](https://documentation.wazuh.com "https://documentation.wazuh.com")  
2. Y. Dang, Q. Lin, P. Huang, "AIOps: Real-World Challenges and Research Innovations," ICSE-SEIP, 2019.  
3. P. Notaro, J. Cardoso, M. Gerndt, "A Survey of AIOps Methods for Failure Management," ACM TIST, 2021.  
4. V. Chandola, A. Banerjee, V. Kumar, "Anomaly Detection: A Survey," ACM Computing Surveys, 2009.  
5. F. T. Liu, K. M. Ting, Z. H. Zhou, "Isolation Forest," ICDM, 2008.  
6. NIST, "National Vulnerability Database," [https://nvd.nist.gov](https://nvd.nist.gov "https://nvd.nist.gov")  
![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAnEAAAACCAYAAAA3pIp+AAAABmJLR0QA/wD/AP+gvaeTAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAANklEQVR4nO3OMQ2AABAAsSNBCkLfFR7wwIgHRiywEZJWQZeZ2ao9AAD+4lyruzq+ngAA8Nr1AOIEBeX8aGZPAAAAAElFTkSuQmCC)  
*Built with Wazuh · Python · Ubuntu · No commercial tools required*  
