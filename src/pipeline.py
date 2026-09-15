import json
import random
from pathlib import Path
from datetime import datetime,timezone

BASE_DIR=Path(__file__).resolve().parent

LIVE_ALERTS = []
LIVE_COUNTER = 1200


SEVERITY_MAP = {
    "low": 1,
    "medium": 3,
    "high": 4,
    "critical": 5
}

ASSET_MAP = {
    "low": 1,
    "medium": 2,
    "high": 4,
    "critical": 5
}


def load_alerts():
    file_path=BASE_DIR/"data"/"sample_alerts_1200.json"

    with open(file_path,"r",encoding="utf-8") as f:
        data=json.load(f)

    alerts=[]

    for a in data:
        alerts.append({
            "id":a["id"],
            "timestamp":a["timestamp"],
            "source":a["source"],
            "src_ip":a["src_ip"],
            "target":a["target"] or "Unknown",
            "severity":SEVERITY_MAP[a["raw_severity"].lower()],
            "asset_value":ASSET_MAP[a["asset_value"].lower()],
            "description":a["description"]
        })

    return alerts


ALERTS = load_alerts()

ALERTS = [
  {
    "id": "A001",
    "timestamp": "2026-09-14T10:01:00",
    "source": "SIEM",
    "src_ip": "10.20.4.18",
    "target": "Server-01",
    "severity": 5,
    "asset_value": 5,
    "description": "Repeated failed authentication followed by successful login from unusual source."
  },
  {
    "id": "A002",
    "timestamp": "2026-09-14T10:04:00",
    "source": "CyberSensor",
    "src_ip": "10.20.4.18",
    "target": "Server-01",
    "severity": 4,
    "asset_value": 5,
    "description": "Suspicious command execution observed after remote session establishment."
  },
  {
    "id": "A003",
    "timestamp": "2026-09-14T10:08:00",
    "source": "SatelliteFeed",
    "src_ip": "10.20.4.18",
    "target": "Area-7",
    "severity": 5,
    "asset_value": 5,
    "description": "Anomalous outbound communication pattern detected from linked infrastructure."
  },
  {
    "id": "A004",
    "timestamp": "2026-09-14T10:12:00",
    "source": "IntelReport",
    "src_ip": "10.20.4.18",
    "target": "Server-01",
    "severity": 5,
    "asset_value": 5,
    "description": "Intelligence report associates source infrastructure with suspected command-and-control activity."
  },
  {
    "id": "A005",
    "timestamp": "2026-09-14T10:20:00",
    "source": "SIEM",
    "src_ip": "10.20.4.18",
    "target": "Server-01",
    "severity": 4,
    "asset_value": 5,
    "description": "Encoded HTTP traffic detected to an external destination."
  },
  {
    "id": "A006",
    "timestamp": "2026-09-14T10:16:00",
    "source": "CyberSensor",
    "src_ip": "172.16.8.44",
    "target": "Gateway-02",
    "severity": 2,
    "asset_value": 1,
    "description": "Possible denial-of-service traffic spike observed."
  },
  {
    "id": "A007",
    "timestamp": "2026-09-14T11:02:00",
    "source": "SIEM",
    "src_ip": "192.168.40.9",
    "target": "Web-02",
    "severity": 3,
    "asset_value": 4,
    "description": "Unusual web request pattern followed by suspicious outbound connection."
  },
  {
    "id": "A008",
    "timestamp": "2026-09-14T11:11:00",
    "source": "CyberSensor",
    "src_ip": "192.168.40.9",
    "target": "Web-02",
    "severity": 4,
    "asset_value": 4,
    "description": "Application-layer communication with known suspicious destination."
  },
  {
    "id": "A009",
    "timestamp": "2026-09-14T12:21:00",
    "source": "SIEM",
    "src_ip": "203.0.113.77",
    "target": "User-17",
    "severity": 1,
    "asset_value": 2,
    "description": "Multiple password failures detected."
  },
  {
    "id": "A010",
    "timestamp": "2026-09-14T12:26:00",
    "source": "IntelReport",
    "src_ip": "203.0.113.77",
    "target": "User-17",
    "severity": 1,
    "asset_value": 2,
    "description": "Low-confidence report mentions credential guessing activity."
  },
  {
    "id": "A011",
    "timestamp": "2026-09-14T13:03:00",
    "source": "SIEM",
    "src_ip": "198.51.100.24",
    "target": "Web-03",
    "severity": 3,
    "asset_value": 4,
    "description": "Attempt to exploit a public-facing application detected."
  },
  {
    "id": "A012",
    "timestamp": "2026-09-14T13:10:00",
    "source": "CyberSensor",
    "src_ip": "198.51.100.24",
    "target": "Web-03",
    "severity": 3,
    "asset_value": 4,
    "description": "Repeated exploit pattern observed against public-facing service."
  }
]

MITRE = {
  "T1021": {
    "name": "Remote Services",
    "tactic": "Lateral Movement"
  },
  "T1041": {
    "name": "Exfiltration Over C2 Channel",
    "tactic": "Exfiltration"
  },
  "T1059": {
    "name": "Command and Scripting Interpreter",
    "tactic": "Execution"
  },
  "T1071": {
    "name": "Application Layer Protocol",
    "tactic": "Command and Control"
  },
  "T1078": {
    "name": "Valid Accounts",
    "tactic": "Defense Evasion"
  },
  "T1110": {
    "name": "Brute Force",
    "tactic": "Credential Access"
  },
  "T1190": {
    "name": "Exploit Public-Facing Application",
    "tactic": "Initial Access"
  },
  "T1498": {
    "name": "Network Denial of Service",
    "tactic": "Impact"
  }
}

KEYWORDS = {
    "T1021": ["remote session", "remote service"],
    "T1041": ["outbound communication", "exfiltration"],
    "T1059": ["command execution"],
    "T1071": ["http", "application-layer", "communication"],
    "T1078": ["successful login", "valid account"],
    "T1110": ["password failures", "credential guessing", "brute force"],
    "T1190": ["exploit", "public-facing"],
    "T1498": ["denial-of-service", "traffic spike"]
}

def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)

def correlate(alerts, window_minutes=30):
    remaining = set(a["id"] for a in alerts)
    groups = []
    by_id = {a["id"]: a for a in alerts}
    while remaining:
        seed_id = next(iter(remaining))
        group = [by_id[seed_id]]
        remaining.remove(seed_id)
        changed = True
        while changed:
            changed = False
            for aid in list(remaining):
                a = by_id[aid]
                if any(a["src_ip"] == g["src_ip"] and abs((parse_time(a["timestamp"])-parse_time(g["timestamp"])).total_seconds()) <= window_minutes*60 for g in group):
                    group.append(a)
                    remaining.remove(aid)
                    changed = True
        groups.append(group)
    return groups

def map_mitre(group):
    text = " ".join(a["description"].lower() for a in group)
    ids = []
    for tid, words in KEYWORDS.items():
        if any(w in text for w in words):
            ids.append(tid)
    return ids

def score(group):
    max_sev = max(a["severity"] for a in group)
    max_asset = max(a["asset_value"] for a in group)
    corroboration = len(group)
    return round(max_sev * max_asset * (1 + 0.3 * (corroboration - 1)), 1)

def verdict(s):
    if s >= 20: return "CRITICAL"
    if s >= 10: return "HIGH"
    if s >= 5: return "MEDIUM"
    return "LOW"

def bluf(group, s, v, techniques):
    sources = sorted(set(a["source"] for a in group))
    target = max(set(a["target"] for a in group), key=[a["target"] for a in group].count)
    if v == "CRITICAL":
        bottom = f"Likely coordinated hostile activity is targeting {target}. Multiple independent sources corroborate the activity; immediate investigation is recommended."
        action = "Isolate or tightly monitor the affected asset, investigate related credentials and outbound connections, and escalate to the incident commander."
    elif v == "HIGH":
        bottom = f"High-confidence suspicious activity is affecting {target}. Correlated alerts indicate a common source and warrant analyst investigation."
        action = "Validate the source, inspect the affected service, and investigate related network connections."
    elif v == "MEDIUM":
        bottom = f"Potentially malicious activity was detected against {target}, but additional validation is required."
        action = "Enrich the alert, check nearby events, and monitor the target for escalation."
    else:
        bottom = f"Low-confidence activity was observed around {target}. Current evidence is insufficient to confirm a genuine threat."
        action = "Continue monitoring and look for corroborating indicators."
    return {
        "bottom_line": bottom,
        "action": action,
        "sources": sources,
        "target": target,
        "alert_count": len(group),
        "techniques": techniques
    }

def generate_live_alerts(n=5):
    global LIVE_COUNTER

    sources = [
        "SIEM",
        "CyberSensor",
        "SatelliteFeed",
        "IntelReport"
    ]

    targets = [
        "auth-server-01",
        "auth-server-02",
        "file-server-03",
        "web-app-02",
        "db-server-01",
        "vpn-gateway-01"
    ]

    descriptions = [
        ("Multiple failed login attempts detected", 3),
        ("Suspicious PowerShell activity detected", 4),
        ("Lateral movement attempt detected", 4),
        ("Outbound connection to suspicious external IP", 4),
        ("Large data transfer detected", 5),
        ("Known malicious IP communication detected", 5),
        ("Routine vulnerability scan detected", 1)
    ]

    new_alerts = []

    for _ in range(n):

        LIVE_COUNTER += 1

        description, severity = random.choice(descriptions)

        alert = {
            "id": f"A{LIVE_COUNTER:04d}",
            "source": random.choice(sources),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "src_ip": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            "target": random.choice(targets),
            "severity": severity,
            "asset_value": random.choice([2,3,4,5]),
            "description": description
        }

        LIVE_ALERTS.append(alert)
        new_alerts.append(alert)

    return new_alerts

def get_dashboard_data():

    alerts = ALERTS + LIVE_ALERTS

    groups = correlate(alerts)

    incidents = []

    for i, group in enumerate(
        sorted(groups, key=score, reverse=True),
        1
    ):

        s = score(group)
        v = verdict(s)
        techniques = map_mitre(group)
        b = bluf(group, s, v, techniques)

        incidents.append({
            "id": f"INC-{2400+i}",
            "score": s,
            "verdict": v,
            "alerts": group,
            "techniques": techniques,
            **b
        })

    counts = {
        v: sum(
            1 for x in incidents
            if x["verdict"] == v
        )
        for v in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    }

    return {
        "alerts": alerts,

        "incidents": incidents,

        "summary": {
            "total_alerts": len(alerts),
            "live_alerts": len(LIVE_ALERTS),
            "total_incidents": len(incidents),

            **{
                k.lower(): v
                for k, v in counts.items()
            },

            "sources": len(
                set(a["source"] for a in alerts)
            )
        },

        "mitre": MITRE
    }