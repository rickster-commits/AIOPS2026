#!/usr/bin/env python3
"""
AIOPS2026 - ML Anomaly Detection Engine
========================================
BSc IT Project - Kirinyaga University
Author: Alfrick Achoki (Ricky)

Connects to Wazuh API + Indexer, pulls security data,
and uses statistical anomaly detection across all endpoints.
"""

import json
import urllib.request
import ssl
import base64
import sys
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────
WAZUH_HOST    = "https://localhost:55000"
WAZUH_USER    = "wazuh-wui"
WAZUH_PASS    = "TRwBQ.RY0Wx3AyURnWKg214xmIeXD0Y8"

INDEXER_HOST  = "https://localhost:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "Wazuh2026-"   # Update if you changed your password

# Anomaly thresholds
ALERT_SPIKE_THRESHOLD = 2.5   # Z-score above this = anomaly
RISK_SCORE_LIMIT      = 200   # Risk score above this = critical

# ── COLORS ────────────────────────────────────────────────
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ── SSL (ignore self-signed cert) ─────────────────────────
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode    = ssl.CERT_NONE

# ══════════════════════════════════════════════════════════
#   HELPERS
# ══════════════════════════════════════════════════════════
def get_token():
    print(f"{CYAN}[*] Authenticating with Wazuh API...{RESET}")
    creds = base64.b64encode(f"{WAZUH_USER}:{WAZUH_PASS}".encode()).decode()
    req   = urllib.request.Request(
        f"{WAZUH_HOST}/security/user/authenticate?raw=true",
        method="POST",
        headers={"Authorization": f"Basic {creds}"}
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            token = r.read().decode().strip()
            print(f"{GREEN}[✓] Authenticated successfully{RESET}")
            return token
    except Exception as e:
        print(f"{RED}[✗] Auth failed: {e}{RESET}")
        sys.exit(1)

def api_get(token, endpoint):
    req = urllib.request.Request(
        f"{WAZUH_HOST}{endpoint}",
        headers={"Authorization": f"Bearer {token}"}
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"{RED}    [✗] API error: {e}{RESET}")
        return None

def indexer_vulns(agent_id):
    """Query Wazuh Indexer directly for vulnerability data."""
    creds   = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()
    payload = json.dumps({
        "size": 500,
        "query": {"match": {"agent.id": agent_id}}
    }).encode()
    req = urllib.request.Request(
        f"{INDEXER_HOST}/wazuh-states-vulnerabilities-*/_search?pretty",
        data=payload,
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type":  "application/json"
        }
    )
    try:
        with urllib.request.urlopen(req, context=ctx) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"{RED}    [✗] Indexer error: {e}{RESET}")
        return None

# ══════════════════════════════════════════════════════════
#   MAIN ANALYSIS
# ══════════════════════════════════════════════════════════
def run_analysis():
    token  = get_token()

    print(f"\n{CYAN}[*] Fetching agents...{RESET}")
    data   = api_get(token, "/agents?pretty=true")
    if not data:
        print(f"{RED}[✗] Could not fetch agents{RESET}")
        sys.exit(1)

    agents = data["data"]["affected_items"]
    print(f"{GREEN}[✓] Found {len(agents)} agents{RESET}")

    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    AIOPS2026 - ML ANOMALY DETECTION ENGINE{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Scan Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    Agents    : {len(agents)}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    anomalies    = []
    risk_scores  = {}

    for agent in agents:
        aid   = agent["id"]
        name  = agent["name"]
        stat  = agent["status"]
        os    = agent.get("os", {}).get("name", "Unknown")
        ip    = agent.get("ip", "N/A")

        print(f"{BOLD}  > Agent: {name} (ID:{aid}){RESET}")
        print(f"    OS     : {os}")
        print(f"    IP     : {ip}")

        if stat == "active":
            print(f"    Status : {GREEN}Active{RESET}")
        elif stat == "disconnected":
            print(f"    Status : {YELLOW}Disconnected{RESET}")
            disc_time = agent.get("disconnection_time", "unknown")
            anomalies.append({
                "agent"   : name,
                "type"    : "CONNECTIVITY",
                "severity": "MEDIUM",
                "detail"  : f"Agent disconnected at {disc_time}",
                "action"  : "Restart WazuhSvc on the endpoint"
            })
        else:
            print(f"    Status : {RED}{stat}{RESET}")

        # Pull vulnerabilities from Indexer
        print(f"    {CYAN}[*] Fetching vulnerabilities...{RESET}", end=" ", flush=True)
        vdata = indexer_vulns(aid)

        if vdata and vdata.get("hits", {}).get("total", {}).get("value", 0) > 0:
            total    = vdata["hits"]["total"]["value"]
            hits     = [h["_source"] for h in vdata["hits"]["hits"]]

            def sev(s):
                return sum(1 for h in hits if h.get("vulnerability", {}).get("severity") == s)

            critical = sev("Critical")
            high     = sev("High")
            medium   = sev("Medium")
            low      = sev("Low")

            # Risk score: Critical x10 + High x3 + Medium x1
            score = (critical * 10) + (high * 3) + (medium * 1)
            risk_scores[name] = score

            print(f"{GREEN}done ({total} CVEs){RESET}")
            print(f"    {'-'*44}")
            print(f"    Critical : {RED}{critical}{RESET}")
            print(f"    High     : {YELLOW}{high}{RESET}")
            print(f"    Medium   : {CYAN}{medium}{RESET}")
            print(f"    Low      : {GREEN}{low}{RESET}")
            print(f"    Risk Score: {BOLD}{score}{RESET}")

            if critical > 0:
                anomalies.append({
                    "agent"   : name,
                    "type"    : "CRITICAL CVE",
                    "severity": "CRITICAL",
                    "detail"  : f"{critical} critical CVE(s) — patch immediately",
                    "action"  : "Run Windows Update and apply all critical patches"
                })
            if high > 50:
                anomalies.append({
                    "agent"   : name,
                    "type"    : "VULNERABILITY SPIKE",
                    "severity": "HIGH",
                    "detail"  : f"{high} high-severity CVEs — unusually high count",
                    "action"  : "Schedule urgent patching cycle"
                })
            if score > RISK_SCORE_LIMIT:
                anomalies.append({
                    "agent"   : name,
                    "type"    : "HIGH RISK ENDPOINT",
                    "severity": "HIGH",
                    "detail"  : f"Risk score {score} exceeds safe threshold ({RISK_SCORE_LIMIT})",
                    "action"  : "Perform full security audit on this endpoint"
                })
        else:
            risk_scores[name] = 0
            print(f"{YELLOW}no vulnerability data{RESET}")

        print()

    # Cross-Agent Z-Score Analysis
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    CROSS-AGENT STATISTICAL ANALYSIS{RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    scores = list(risk_scores.values())
    if len(scores) > 1:
        mean     = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev  = variance ** 0.5

        print(f"    Mean Risk Score : {mean:.1f}")
        print(f"    Std Deviation   : {std_dev:.1f}\n")

        for agent_name, score in risk_scores.items():
            z    = (score - mean) / std_dev if std_dev > 0 else 0
            bar  = "#" * min(int(score / 5), 40)

            if z > ALERT_SPIKE_THRESHOLD:
                flag = f"  {RED}ANOMALY (z={z:.2f}){RESET}"
                anomalies.append({
                    "agent"   : agent_name,
                    "type"    : "STATISTICAL ANOMALY",
                    "severity": "HIGH",
                    "detail"  : f"Risk score {score} is {z:.1f} std deviations above average",
                    "action"  : "Investigate why this endpoint is riskier than peers"
                })
            elif score == 0:
                flag = f"  {GREEN}Clean{RESET}"
            else:
                flag = f"  {GREEN}Normal (z={z:.2f}){RESET}"

            print(f"    {agent_name:<15} [{bar:<40}] {score:>4}{flag}")

    # Anomaly Report
    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    ANOMALY REPORT{RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    if not anomalies:
        print(f"    {GREEN}No anomalies detected. All systems normal.{RESET}\n")
    else:
        print(f"    {RED}{len(anomalies)} anomaly/anomalies detected:{RESET}\n")
        for i, a in enumerate(anomalies, 1):
            color = RED if a["severity"] in ["CRITICAL", "HIGH"] else YELLOW
            print(f"    [{i}] {color}{a['severity']} - {a['type']}{RESET}")
            print(f"        Agent  : {a['agent']}")
            print(f"        Detail : {a['detail']}")
            print(f"        Action : {a['action']}")
            print()

    # Summary
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    SUMMARY{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Agents Scanned  : {len(agents)}")
    print(f"    Anomalies Found : {len(anomalies)}")
    print(f"    Scan Completed  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    # Save JSON report
    report = {
        "scan_time"      : datetime.now().isoformat(),
        "agents_scanned" : len(agents),
        "anomalies"      : anomalies,
        "risk_scores"    : risk_scores
    }
    with open("anomaly_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"    {GREEN}Report saved to anomaly_report.json{RESET}\n")


if __name__ == "__main__":
    run_analysis()
