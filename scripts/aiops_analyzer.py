#!/usr/bin/env python3
"""
AIOPS2026 - ML Anomaly Detection Engine
========================================
BSc IT Project - Kirinyaga University
Author: Alfrick Achoki (Ricky)

Connects to Wazuh API + Indexer, pulls security data,
and uses statistical anomaly detection across all endpoints.

Keep-inspired improvements (v3):
  - Alert deduplication       (no repeated noise)
  - Noise ranking             (sort by severity weight)
  - Incident correlation      (group anomalies per agent)
  - Scan history + trends     (append every scan to history)
  - Alert enrichment          (full agent context per incident)
  - Alert silencing           (suppress known/accepted alerts)
  - Auto-resolve              (close incidents when condition clears)
  - Scheduled via cron        (runs every 15 minutes automatically)
"""

import json
import urllib.request
import ssl
import base64
import sys
import hashlib
import os
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────
WAZUH_HOST    = "https://localhost:55000"
WAZUH_USER    = "wazuh-wui"
WAZUH_PASS    = "TRwBQ.RY0Wx3AyURnWKg214xmIeXD0Y8"

INDEXER_HOST  = "https://localhost:9200"
INDEXER_USER  = "admin"
INDEXER_PASS  = "Wazuh2026-"

# Anomaly thresholds
ALERT_SPIKE_THRESHOLD = 2.5
RISK_SCORE_LIMIT      = 200
HIGH_CVE_THRESHOLD    = 50

# Output files
REPORT_FILE   = "anomaly_report.json"
HISTORY_FILE  = "scan_history.json"
SILENCE_FILE  = "silenced_alerts.json"
RESOLVED_FILE = "resolved_incidents.json"

# Severity weights for noise ranking
SEVERITY_WEIGHTS = {
    "CRITICAL CVE"       : 10,
    "HIGH RISK ENDPOINT" : 7,
    "VULNERABILITY SPIKE": 5,
    "STATISTICAL ANOMALY": 4,
    "CONNECTIVITY"       : 3,
}

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

# ── COLORS ────────────────────────────────────────────────
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BLUE   = '\033[94m'
BOLD   = '\033[1m'
RESET  = '\033[0m'

# ── SSL ───────────────────────────────────────────────────
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
#   KEEP-INSPIRED: ALERT ENRICHMENT
#   Pulls full agent context from Wazuh API and attaches
#   it to every incident — OS build, version, group, etc.
# ══════════════════════════════════════════════════════════

def enrich_agent(agent):
    """Extract rich context from the Wazuh agent object."""
    os_info   = agent.get("os", {})
    os_name   = os_info.get("name", "Unknown")
    os_build  = os_info.get("build", "")
    os_ver    = os_info.get("version", "")
    os_full   = f"{os_name} {os_ver} (build {os_build})" if os_build else os_name

    return {
        "name"          : agent.get("name", "Unknown"),
        "id"            : agent.get("id", "?"),
        "ip"            : agent.get("ip", "N/A"),
        "status"        : agent.get("status", "unknown"),
        "os"            : os_full,
        "version"       : agent.get("version", "N/A"),
        "group"         : ", ".join(agent.get("group", ["default"])),
        "last_keepalive": agent.get("lastKeepAlive", "N/A"),
        "registered_ip" : agent.get("registerIP", "N/A"),
        "node_name"     : agent.get("node_name", "N/A"),
    }


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: DEDUPLICATION
# ══════════════════════════════════════════════════════════

def deduplicate(anomalies):
    seen   = set()
    unique = []
    for a in anomalies:
        fp = hashlib.md5(f"{a['agent']}-{a['type']}".encode()).hexdigest()
        if fp not in seen:
            seen.add(fp)
            unique.append(a)
    removed = len(anomalies) - len(unique)
    if removed > 0:
        print(f"    {CYAN}[i] Deduplication removed {removed} duplicate alert(s){RESET}")
    return unique


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: ALERT SILENCING
#   Suppresses known/accepted alerts so they don't clutter
#   every scan. Silences are stored in silenced_alerts.json
# ══════════════════════════════════════════════════════════

def load_silences():
    if not os.path.exists(SILENCE_FILE):
        return []
    try:
        with open(SILENCE_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def is_silenced(anomaly, silences):
    for s in silences:
        if s.get("agent") == anomaly["agent"] and s.get("type") == anomaly["type"]:
            return True
    return False


def apply_silencing(anomalies):
    silences  = load_silences()
    if not silences:
        return anomalies, 0
    active    = [a for a in anomalies if not is_silenced(a, silences)]
    silenced  = len(anomalies) - len(active)
    if silenced > 0:
        print(f"    {BLUE}[i] Silencing suppressed {silenced} known alert(s){RESET}")
    return active, silenced


def silence_alert(agent, alert_type):
    """Call this to silence a specific alert type for an agent."""
    silences = load_silences()
    entry    = {"agent": agent, "type": alert_type, "silenced_at": datetime.now().isoformat()}
    silences.append(entry)
    with open(SILENCE_FILE, "w") as f:
        json.dump(silences, f, indent=2)
    print(f"{GREEN}[✓] Silenced '{alert_type}' for agent '{agent}'{RESET}")


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: NOISE RANKING
# ══════════════════════════════════════════════════════════

def rank_by_severity(anomalies):
    return sorted(
        anomalies,
        key=lambda x: SEVERITY_WEIGHTS.get(x["type"], 0),
        reverse=True
    )


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: INCIDENT CORRELATION + ENRICHMENT
#   Groups anomalies per agent and attaches full context.
# ══════════════════════════════════════════════════════════

def correlate_incidents(anomalies, enrichment_map):
    incidents = {}
    for a in anomalies:
        agent = a["agent"]
        if agent not in incidents:
            incidents[agent] = {
                "agent"           : agent,
                "enrichment"      : enrichment_map.get(agent, {}),
                "anomaly_count"   : 0,
                "highest_severity": "LOW",
                "anomaly_types"   : [],
                "anomalies"       : [],
                "opened_at"       : datetime.now().isoformat(),
                "status"          : "OPEN"
            }
        inc = incidents[agent]
        inc["anomalies"].append(a)
        inc["anomaly_count"] += 1
        inc["anomaly_types"].append(a["type"])
        if SEVERITY_RANK.get(a["severity"], 0) > SEVERITY_RANK.get(inc["highest_severity"], 0):
            inc["highest_severity"] = a["severity"]
    return incidents


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: AUTO-RESOLVE
#   Compares current incidents against the last scan.
#   If an incident no longer appears, it is auto-resolved
#   and logged to resolved_incidents.json
# ══════════════════════════════════════════════════════════

def auto_resolve(current_incidents):
    if not os.path.exists(HISTORY_FILE):
        return []

    try:
        with open(HISTORY_FILE) as f:
            history = json.load(f)
        if len(history) < 2:
            return []
        last_incidents = history[-2].get("incidents", {})
    except Exception:
        return []

    resolved = []
    for agent, inc in last_incidents.items():
        if agent not in current_incidents:
            resolved.append({
                "agent"      : agent,
                "resolved_at": datetime.now().isoformat(),
                "was_severity": inc.get("highest_severity", "UNKNOWN"),
                "anomaly_types": inc.get("anomaly_types", [])
            })

    if resolved:
        # Save resolved incidents
        existing = []
        if os.path.exists(RESOLVED_FILE):
            try:
                with open(RESOLVED_FILE) as f:
                    existing = json.load(f)
            except Exception:
                existing = []
        existing.extend(resolved)
        with open(RESOLVED_FILE, "w") as f:
            json.dump(existing, f, indent=2)

    return resolved


# ══════════════════════════════════════════════════════════
#   KEEP-INSPIRED: SCAN HISTORY + TREND
# ══════════════════════════════════════════════════════════

def save_history(report):
    history = []
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                history = json.load(f)
        except Exception:
            history = []
    history.append(report)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)
    print(f"    {GREEN}History updated → {HISTORY_FILE} ({len(history)} scan(s) recorded){RESET}")


def get_trend(agent_name):
    if not os.path.exists(HISTORY_FILE):
        return None
    try:
        with open(HISTORY_FILE) as f:
            history = json.load(f)
        if len(history) < 2:
            return None
        return history[-2].get("risk_scores", {}).get(agent_name)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════
#   MAIN ANALYSIS
# ══════════════════════════════════════════════════════════

def run_analysis():
    scan_start   = datetime.now()
    token        = get_token()

    print(f"\n{CYAN}[*] Fetching agents...{RESET}")
    data = api_get(token, "/agents?pretty=true")
    if not data:
        print(f"{RED}[✗] Could not fetch agents{RESET}")
        sys.exit(1)

    agents = data["data"]["affected_items"]
    print(f"{GREEN}[✓] Found {len(agents)} agents{RESET}")

    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    AIOPS2026 - ML ANOMALY DETECTION ENGINE  v3{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Scan Time : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"    Agents    : {len(agents)}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    raw_anomalies = []
    risk_scores   = {}
    enrichment_map = {}

    # ── PER-AGENT ANALYSIS ──────────────────────────────
    for agent in agents:
        aid  = agent["id"]
        name = agent["name"]
        stat = agent["status"]

        # Build enrichment context
        enriched = enrich_agent(agent)
        enrichment_map[name] = enriched

        print(f"{BOLD}  > Agent: {name} (ID:{aid}){RESET}")
        print(f"    OS       : {enriched['os']}")
        print(f"    IP       : {enriched['ip']}")
        print(f"    Version  : {enriched['version']}")
        print(f"    Group    : {enriched['group']}")
        print(f"    Keepalive: {enriched['last_keepalive']}")

        if stat == "active":
            print(f"    Status   : {GREEN}Active{RESET}")
        elif stat == "disconnected":
            disc_time = agent.get("disconnection_time", "unknown")
            print(f"    Status   : {YELLOW}Disconnected{RESET}")
            raw_anomalies.append({
                "agent"   : name,
                "type"    : "CONNECTIVITY",
                "severity": "MEDIUM",
                "detail"  : f"Agent disconnected at {disc_time}",
                "action"  : "Restart WazuhSvc on the endpoint"
            })
        else:
            print(f"    Status   : {RED}{stat}{RESET}")

        print(f"    {CYAN}[*] Fetching vulnerabilities...{RESET}", end=" ", flush=True)
        vdata = indexer_vulns(aid)

        if vdata and vdata.get("hits", {}).get("total", {}).get("value", 0) > 0:
            total = vdata["hits"]["total"]["value"]
            hits  = [h["_source"] for h in vdata["hits"]["hits"]]

            def sev(s):
                return sum(1 for h in hits if h.get("vulnerability", {}).get("severity") == s)

            critical = sev("Critical")
            high     = sev("High")
            medium   = sev("Medium")
            low      = sev("Low")
            score    = (critical * 10) + (high * 3) + (medium * 1)
            risk_scores[name] = score

            # Trend
            prev = get_trend(name)
            if prev is not None:
                diff = score - prev
                if diff > 0:
                    trend_str = f"  ({RED}▲ +{diff} since last scan{RESET})"
                elif diff < 0:
                    trend_str = f"  ({GREEN}▼ {diff} since last scan{RESET})"
                else:
                    trend_str = f"  ({CYAN}→ no change{RESET})"
            else:
                trend_str = "  (first scan)"

            print(f"{GREEN}done ({total} CVEs){RESET}")
            print(f"    {'-'*44}")
            print(f"    Critical : {RED}{critical}{RESET}")
            print(f"    High     : {YELLOW}{high}{RESET}")
            print(f"    Medium   : {CYAN}{medium}{RESET}")
            print(f"    Low      : {GREEN}{low}{RESET}")
            print(f"    Risk Score: {BOLD}{score}{RESET}{trend_str}")

            if critical > 0:
                raw_anomalies.append({
                    "agent": name, "type": "CRITICAL CVE", "severity": "CRITICAL",
                    "detail": f"{critical} critical CVE(s) — patch immediately",
                    "action": "Run Windows Update and apply all critical patches"
                })
            if high > HIGH_CVE_THRESHOLD:
                raw_anomalies.append({
                    "agent": name, "type": "VULNERABILITY SPIKE", "severity": "HIGH",
                    "detail": f"{high} high-severity CVEs — unusually high count",
                    "action": "Schedule urgent patching cycle"
                })
            if score > RISK_SCORE_LIMIT:
                raw_anomalies.append({
                    "agent": name, "type": "HIGH RISK ENDPOINT", "severity": "HIGH",
                    "detail": f"Risk score {score} exceeds safe threshold ({RISK_SCORE_LIMIT})",
                    "action": "Perform full security audit on this endpoint"
                })
        else:
            risk_scores[name] = 0
            print(f"{YELLOW}no vulnerability data{RESET}")

        print()

    # ── CROSS-AGENT Z-SCORE ──────────────────────────────
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    CROSS-AGENT STATISTICAL ANALYSIS{RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    scores = list(risk_scores.values())
    mean = std_dev = 0
    if len(scores) > 1:
        mean     = sum(scores) / len(scores)
        variance = sum((s - mean) ** 2 for s in scores) / len(scores)
        std_dev  = variance ** 0.5

        print(f"    Mean Risk Score : {mean:.1f}")
        print(f"    Std Deviation   : {std_dev:.1f}\n")

        for agent_name, score in risk_scores.items():
            z   = (score - mean) / std_dev if std_dev > 0 else 0
            bar = "#" * min(int(score / 5), 40)
            if z > ALERT_SPIKE_THRESHOLD:
                flag = f"  {RED}ANOMALY (z={z:.2f}){RESET}"
                raw_anomalies.append({
                    "agent": agent_name, "type": "STATISTICAL ANOMALY", "severity": "HIGH",
                    "detail": f"Risk score {score} is {z:.1f} std deviations above average",
                    "action": "Investigate why this endpoint is riskier than peers"
                })
            elif score == 0:
                flag = f"  {GREEN}Clean{RESET}"
            else:
                flag = f"  {GREEN}Normal (z={z:.2f}){RESET}"
            print(f"    {agent_name:<15} [{bar:<40}] {score:>4}{flag}")

    # ── KEEP-INSPIRED PIPELINE ───────────────────────────
    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    PROCESSING PIPELINE  (Keep-inspired){RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Raw alerts collected : {len(raw_anomalies)}")

    # Step 1: Deduplicate
    anomalies = deduplicate(raw_anomalies)
    print(f"    After deduplication  : {len(anomalies)}")

    # Step 2: Silence known alerts
    anomalies, silenced_count = apply_silencing(anomalies)
    print(f"    After silencing      : {len(anomalies)}")

    # Step 3: Rank by severity
    anomalies = rank_by_severity(anomalies)
    print(f"    Ranked by severity   : ✓")

    # Step 4: Correlate into enriched incidents
    incidents = correlate_incidents(anomalies, enrichment_map)
    print(f"    Incidents identified : {len(incidents)}")

    # Step 5: Auto-resolve cleared incidents
    resolved = auto_resolve(incidents)
    if resolved:
        print(f"    {GREEN}Auto-resolved        : {len(resolved)} incident(s){RESET}")
        for r in resolved:
            print(f"    {GREEN}  ✓ {r['agent']} — resolved at {r['resolved_at']}{RESET}")

    # ── ANOMALY REPORT ───────────────────────────────────
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

    # ── ENRICHED INCIDENT SUMMARY ────────────────────────
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    INCIDENT SUMMARY  (Keep-style enriched){RESET}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    if not incidents:
        print(f"    {GREEN}No incidents raised.{RESET}\n")
    else:
        for i, (agent, inc) in enumerate(incidents.items(), 1):
            sev   = inc["highest_severity"]
            color = RED if sev in ["CRITICAL", "HIGH"] else YELLOW
            e     = inc["enrichment"]
            types = ", ".join(set(inc["anomaly_types"]))

            print(f"    {color}{'─'*54}{RESET}")
            print(f"    {color}INC-{i:03d}  [{sev}]  {agent}  [{inc['status']}]{RESET}")
            print(f"    {'─'*54}")
            print(f"    OS        : {e.get('os', 'N/A')}")
            print(f"    IP        : {e.get('ip', 'N/A')}")
            print(f"    Version   : {e.get('version', 'N/A')}")
            print(f"    Group     : {e.get('group', 'N/A')}")
            print(f"    Keepalive : {e.get('last_keepalive', 'N/A')}")
            print(f"    Anomalies : {inc['anomaly_count']}")
            print(f"    Types     : {types}")
            print(f"    Opened    : {inc['opened_at']}")
            print()

    # ── SUMMARY ──────────────────────────────────────────
    scan_end = datetime.now()
    duration = (scan_end - scan_start).total_seconds()

    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    SUMMARY{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Agents Scanned  : {len(agents)}")
    print(f"    Raw Alerts      : {len(raw_anomalies)}")
    print(f"    After Dedup     : {len(anomalies) + silenced_count}")
    print(f"    Silenced        : {silenced_count}")
    print(f"    Active Alerts   : {len(anomalies)}")
    print(f"    Incidents       : {len(incidents)}")
    print(f"    Auto-Resolved   : {len(resolved)}")
    print(f"    Scan Duration   : {duration:.2f}s")
    print(f"    Scan Completed  : {scan_end.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    # ── SAVE ─────────────────────────────────────────────
    report = {
        "scan_time"      : scan_start.isoformat(),
        "scan_duration_s": round(duration, 2),
        "agents_scanned" : len(agents),
        "raw_alerts"     : len(raw_anomalies),
        "silenced"       : silenced_count,
        "anomalies"      : anomalies,
        "incidents"      : incidents,
        "resolved"       : resolved,
        "risk_scores"    : risk_scores,
        "stats"          : {"mean": round(mean, 1), "std_dev": round(std_dev, 1)}
    }

    with open(REPORT_FILE, "w") as f:
        json.dump(report, f, indent=2)
    print(f"    {GREEN}Report saved → {REPORT_FILE}{RESET}")

    save_history(report)


# ══════════════════════════════════════════════════════════
#   CLI — silence an alert from command line
#   Usage: python3 aiops_analyzer.py --silence ELITEBOOK CONNECTIVITY
# ══════════════════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--silence":
        silence_alert(sys.argv[2], sys.argv[3])
    else:
        run_analysis()
