#!/usr/bin/env python3
"""
AIOPS2026 - Workflow Engine
============================
BSc IT Project - Kirinyaga University
Author: Alfrick Achoki (Ricky)

Keep-inspired declarative YAML workflow engine.
Reads workflow files from workflows/ directory and
executes matching actions when anomaly conditions are met.

Usage:
  python3 scripts/workflow_engine.py              # run all workflows
  python3 scripts/workflow_engine.py --list       # list loaded workflows
"""

import json
import os
import sys
import re
from datetime import datetime

# ── CONFIG ────────────────────────────────────────────────
REPORT_FILE      = "anomaly_report.json"
WORKFLOWS_DIR    = "workflows"
REMEDIATION_LOG  = "logs/remediation_log.json"

# ── COLORS ────────────────────────────────────────────────
RED    = '\033[91m'
YELLOW = '\033[93m'
GREEN  = '\033[92m'
CYAN   = '\033[96m'
BLUE   = '\033[94m'
BOLD   = '\033[1m'
RESET  = '\033[0m'


# ══════════════════════════════════════════════════════════
#   MINIMAL YAML PARSER
#   Handles our simple workflow format without any deps.
# ══════════════════════════════════════════════════════════

def parse_yaml(text):
    """Parse a simple key: value YAML structure into a dict."""
    result  = {}
    current = result
    stack   = [(0, result)]
    lines   = text.splitlines()
    i       = 0

    while i < len(lines):
        line = lines[i]
        stripped = line.rstrip()
        if not stripped or stripped.lstrip().startswith('#'):
            i += 1
            continue

        indent = len(line) - len(line.lstrip())

        # Pop stack to correct indent level
        while len(stack) > 1 and stack[-1][0] >= indent:
            stack.pop()
        current = stack[-1][1]

        stripped = stripped.strip()

        # List item
        if stripped.startswith('- '):
            val = stripped[2:].strip()
            # Find the key this list belongs to (last key in parent)
            parent = stack[-1][1]
            # The parent should have a list already started
            for k in reversed(list(parent.keys())):
                if isinstance(parent[k], list):
                    # Check if it's a sub-object list
                    if ':' in val:
                        # Might be start of dict in list — simple handling
                        obj = {}
                        parts = val.split(':', 1)
                        obj[parts[0].strip()] = parts[1].strip() if len(parts) > 1 else ''
                        parent[k].append(obj)
                    else:
                        parent[k].append(val)
                    break
            i += 1
            continue

        # Key: value or Key: (dict start)
        if ':' in stripped:
            parts = stripped.split(':', 1)
            key   = parts[0].strip()
            val   = parts[1].strip() if len(parts) > 1 else ''

            if val == '':
                # Start of nested dict
                new_dict = {}
                current[key] = new_dict
                stack.append((indent + 2, new_dict))
            elif val == '[]':
                current[key] = []
            else:
                # Check if next non-empty line is a list item
                j = i + 1
                while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith('#')):
                    j += 1
                if j < len(lines) and lines[j].strip().startswith('- '):
                    current[key] = []
                    stack.append((indent + 2, {f'__list_key__': key, '__parent__': current}))
                    # Simpler: just pre-create the list and parse items next
                    # We'll handle list items by attaching to this key
                    stack[-1] = (indent + 2, current)
                    # Actually let's keep it simple
                    stack.pop()
                    new_list = []
                    current[key] = new_list
                    # Parse list items
                    i += 1
                    while i < len(lines):
                        lline = lines[i]
                        ls    = lline.strip()
                        if not ls or ls.startswith('#'):
                            i += 1
                            continue
                        lindent = len(lline) - len(lline.lstrip())
                        if lindent <= indent and not ls.startswith('-'):
                            break
                        if ls.startswith('- '):
                            item_val = ls[2:].strip()
                            if ':' in item_val:
                                # Dict inside list
                                obj  = {}
                                p    = item_val.split(':', 1)
                                obj[p[0].strip()] = p[1].strip()
                                # Check for more keys at same level
                                i += 1
                                while i < len(lines):
                                    nl    = lines[i]
                                    nls   = nl.strip()
                                    nind  = len(nl) - len(nl.lstrip())
                                    if not nls or nls.startswith('#'):
                                        i += 1
                                        continue
                                    if nind > lindent and ':' in nls and not nls.startswith('-'):
                                        np = nls.split(':', 1)
                                        obj[np[0].strip()] = np[1].strip()
                                        i += 1
                                    else:
                                        break
                                new_list.append(obj)
                                continue
                            else:
                                new_list.append(item_val)
                        i += 1
                    continue
                else:
                    # Strip quotes
                    if (val.startswith('"') and val.endswith('"')) or \
                       (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    current[key] = val
        i += 1

    return result


# ══════════════════════════════════════════════════════════
#   WORKFLOW LOADER
# ══════════════════════════════════════════════════════════

def load_workflows():
    """Load all .yml workflow files from the workflows/ directory."""
    if not os.path.exists(WORKFLOWS_DIR):
        os.makedirs(WORKFLOWS_DIR)
        return []

    workflows = []
    for fname in sorted(os.listdir(WORKFLOWS_DIR)):
        if not fname.endswith('.yml'):
            continue
        path = os.path.join(WORKFLOWS_DIR, fname)
        try:
            with open(path) as f:
                text = f.read()
            wf = parse_yaml(text)
            wf['_file'] = fname
            workflows.append(wf)
        except Exception as e:
            print(f"{RED}[✗] Failed to load {fname}: {e}{RESET}")
    return workflows


# ══════════════════════════════════════════════════════════
#   CONDITION EVALUATOR
#   Checks if an anomaly matches a workflow's filters.
# ══════════════════════════════════════════════════════════

def evaluate_filters(anomaly, filters):
    """Return True if anomaly matches ALL filters."""
    if not filters:
        return True
    for f in filters:
        key   = f.get('key', '')
        value = f.get('value', '')
        actual = anomaly.get(key, '')
        # Support wildcard *
        if value == '*':
            continue
        if str(actual).upper() != str(value).upper():
            return False
    return True


def evaluate_trigger(workflow, report):
    """Return list of (anomaly, incident) pairs that match this workflow."""
    trigger = workflow.get('trigger', {})
    ttype   = trigger.get('type', '')
    filters = trigger.get('filters', [])

    matches = []

    if ttype == 'anomaly':
        for a in report.get('anomalies', []):
            if evaluate_filters(a, filters):
                # Find matching incident
                inc = report.get('incidents', {}).get(a.get('agent'), {})
                matches.append((a, inc))

    elif ttype == 'incident':
        for agent, inc in report.get('incidents', {}).items():
            fake_a = {
                'agent'   : agent,
                'type'    : inc.get('highest_severity', ''),
                'severity': inc.get('highest_severity', '')
            }
            if evaluate_filters(fake_a, filters):
                matches.append((fake_a, inc))

    elif ttype == 'schedule':
        # Schedule workflows always fire
        matches.append(({}, {}))

    return matches


# ══════════════════════════════════════════════════════════
#   ACTION EXECUTOR
# ══════════════════════════════════════════════════════════

def interpolate(template, anomaly, incident):
    """Replace {placeholders} in action strings with actual values."""
    enrichment = incident.get('enrichment', {})
    ctx = {
        'agent'    : anomaly.get('agent', 'UNKNOWN'),
        'type'     : anomaly.get('type', ''),
        'severity' : anomaly.get('severity', ''),
        'detail'   : anomaly.get('detail', ''),
        'action'   : anomaly.get('action', ''),
        'ip'       : enrichment.get('ip', 'N/A'),
        'os'       : enrichment.get('os', 'N/A'),
        'version'  : enrichment.get('version', 'N/A'),
        'keepalive': enrichment.get('last_keepalive', 'N/A'),
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
    }
    for key, val in ctx.items():
        template = template.replace('{' + key + '}', str(val))
    return template


def execute_action(action, anomaly, incident, wf_name):
    """Execute a single workflow action."""
    atype   = action.get('name', '')
    message = action.get('message', '')
    logfile = action.get('file', '')
    tag     = action.get('tag', '')

    result = {
        'workflow'  : wf_name,
        'action'    : atype,
        'agent'     : anomaly.get('agent', ''),
        'triggered_at': datetime.now().isoformat(),
    }

    if atype == 'notify':
        msg = interpolate(message, anomaly, incident)
        print(f"    {BLUE}[→] NOTIFY:{RESET} {msg}")
        result['message'] = msg

    elif atype == 'log':
        msg = interpolate(message or f"Workflow fired for {anomaly.get('agent')}", anomaly, incident)
        result['message'] = msg
        print(f"    {GREEN}[→] LOG:{RESET} {msg}")
        if logfile:
            _append_log(logfile, result)

    elif atype == 'tag':
        tval = interpolate(tag, anomaly, incident)
        print(f"    {CYAN}[→] TAG:{RESET} {anomaly.get('agent')} → {tval}")
        result['tag'] = tval

    elif atype == 'remediate':
        msg = interpolate(message, anomaly, incident)
        print(f"    {YELLOW}[→] REMEDIATE:{RESET} {msg}")
        result['message'] = msg
        _append_log(REMEDIATION_LOG, result)

    return result


def _append_log(filepath, entry):
    """Append an entry to a JSON log file."""
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
    data = []
    if os.path.exists(filepath):
        try:
            with open(filepath) as f:
                data = json.load(f)
        except Exception:
            data = []
    data.append(entry)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)


# ══════════════════════════════════════════════════════════
#   MAIN RUNNER
# ══════════════════════════════════════════════════════════

def run_workflows():
    # Load anomaly report
    if not os.path.exists(REPORT_FILE):
        print(f"{RED}[✗] {REPORT_FILE} not found. Run aiops_analyzer.py first.{RESET}")
        sys.exit(1)

    with open(REPORT_FILE) as f:
        report = json.load(f)

    workflows = load_workflows()

    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    AIOPS2026 - WORKFLOW ENGINE  (Keep-inspired){RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Workflows loaded : {len(workflows)}")
    print(f"    Anomalies in report : {len(report.get('anomalies', []))}")
    print(f"    Incidents in report : {len(report.get('incidents', {}))}")
    print(f"{BOLD}{'='*62}{RESET}\n")

    if not workflows:
        print(f"{YELLOW}[!] No workflows found in '{WORKFLOWS_DIR}/' directory.{RESET}")
        print(f"    Create .yml files there to define automated responses.\n")
        return

    total_fired = 0

    for wf in workflows:
        wf_id   = wf.get('id', wf['_file'])
        wf_desc = wf.get('description', '')
        actions = wf.get('actions', [])

        print(f"{BOLD}  ▶ Workflow: {wf_id}{RESET}")
        if wf_desc:
            print(f"    Description: {wf_desc}")

        matches = evaluate_trigger(wf, report)

        if not matches:
            print(f"    {GREEN}[✓] No matching conditions — workflow skipped{RESET}\n")
            continue

        print(f"    {YELLOW}[!] {len(matches)} match(es) found — executing actions{RESET}")

        for anomaly, incident in matches:
            agent = anomaly.get('agent', 'UNKNOWN')
            print(f"\n    {CYAN}Agent: {agent}{RESET}")
            for action in actions:
                execute_action(action, anomaly, incident, wf_id)
                total_fired += 1

        print()

    print(f"{BOLD}{'='*62}{RESET}")
    print(f"{BOLD}    SUMMARY{RESET}")
    print(f"{BOLD}{'='*62}{RESET}")
    print(f"    Workflows evaluated : {len(workflows)}")
    print(f"    Actions fired       : {total_fired}")
    print(f"    Remediation log     : {REMEDIATION_LOG}")
    print(f"    Completed           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*62}{RESET}\n")


def list_workflows():
    workflows = load_workflows()
    print(f"\n{BOLD}Loaded Workflows ({len(workflows)}){RESET}")
    for wf in workflows:
        print(f"  • {wf.get('id', wf['_file'])} — {wf.get('description', '')}")
    print()


if __name__ == "__main__":
    if '--list' in sys.argv:
        list_workflows()
    else:
        run_workflows()
