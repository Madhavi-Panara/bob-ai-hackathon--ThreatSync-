"""
Generates a large, realistic sample_alerts.json for the Signal Deck demo.

Run: python generate_alerts.py
Produces sample_alerts.json with ~1000+ alerts: a mix of multi-stage
attack chains (correlated, high severity), isolated suspicious alerts,
and background noise/false positives - so the correlation + scoring
pipeline has plenty to chew on for a convincing demo.
"""

import json
import random
from datetime import datetime, timedelta

random.seed(42)  # reproducible output

SOURCES = ["SIEM", "CyberSensor", "SatelliteFeed", "IntelReport"]
ASSET_VALUES = ["low", "medium", "high", "critical"]

INTERNAL_SUBNETS = ["192.168.{}.{}", "10.0.{}.{}", "172.16.{}.{}"]
TARGETS = [
    "auth-server-01", "auth-server-02", "file-server-03", "file-server-04",
    "web-app-02", "web-app-05", "db-server-01", "print-server-02",
    "comm-relay-07", "vpn-gateway-01", "mail-server-01", "backup-server-02",
]

NOISE_DESCRIPTIONS = [
    ("Routine antivirus definition update triggered scan alert", "low"),
    ("Single failed login attempt, common user typo pattern", "low"),
    ("Scheduled backup job completed with warnings", "low"),
    ("Certificate renewal reminder triggered monitoring alert", "low"),
    ("Non-standard port usage by known internal application", "low"),
    ("User password expiry notification triggered by IAM system", "low"),
    ("Scheduled vulnerability scan detected on internal subnet", "medium"),
    ("Unusual but explainable login time (approved night shift)", "medium"),
]

ATTACK_CHAIN_TEMPLATES = [
    [
        ("Multiple failed login attempts ({n} in 2 min) from internal host", "medium"),
        ("Successful login after failed attempts, unusual hour", "high"),
        ("Process spawned unexpected child process (cmd.exe -> powershell.exe)", "high"),
        ("Lateral movement: SMB connection from {src_target} to {target}", "high"),
        ("Large outbound data transfer ({gb} GB) to unknown external IP", "critical"),
    ],
    [
        ("SQL injection pattern detected in web request logs", "high"),
        ("Web application error spike (500s) immediately after suspicious request", "medium"),
        ("Unexpected database export query triggered by web-app service account", "high"),
    ],
    [
        ("Threat intel: IP {ip} associated with known APT infrastructure", "medium"),
        ("Outbound connection from {target} to flagged external IP {ip}", "high"),
        ("Encrypted C2-like beaconing pattern detected at regular intervals", "critical"),
    ],
    [
        ("Signal jamming detected near {target}, low confidence", "low"),
        ("Satellite uplink signal degradation on same relay", "medium"),
    ],
]


def random_internal_ip():
    template = random.choice(INTERNAL_SUBNETS)
    return template.format(random.randint(1, 254), random.randint(1, 254))


def random_external_ip():
    return f"{random.randint(20,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def generate_attack_chain(base_time, alert_counter):
    template = random.choice(ATTACK_CHAIN_TEMPLATES)
    src_ip = random_internal_ip()
    ext_ip = random_external_ip()
    target = random.choice(TARGETS)
    src_target = random.choice(TARGETS)
    asset_value = random.choice(["high", "critical"])
    t = base_time
    alerts = []
    for desc_template, severity in template:
        t = t + timedelta(seconds=random.randint(30, 400))
        desc = desc_template.format(
            n=random.randint(6, 20),
            src_target=src_target,
            target=target,
            gb=round(random.uniform(0.5, 5.0), 1),
            ip=ext_ip,
        )
        alert_counter[0] += 1
        alerts.append({
            "id": f"A{alert_counter[0]:04d}",
            "source": random.choice(SOURCES),
            "timestamp": iso(t),
            "src_ip": src_ip if "external" not in desc else ext_ip,
            "target": target,
            "asset_value": asset_value,
            "description": desc,
            "raw_severity": severity,
        })
    return alerts


def generate_noise(base_time, alert_counter):
    desc, severity = random.choice(NOISE_DESCRIPTIONS)
    alert_counter[0] += 1
    return {
        "id": f"A{alert_counter[0]:04d}",
        "source": random.choice(SOURCES),
        "timestamp": iso(base_time),
        "src_ip": random_internal_ip(),
        "target": random.choice(TARGETS + [None]),
        "asset_value": random.choice(ASSET_VALUES),
        "description": desc,
        "raw_severity": severity,
    }


def main(total_alerts=1000, attack_chain_ratio=0.15):
    alert_counter = [0]
    all_alerts = []
    start = datetime(2026, 9, 15, 6, 0, 0)

    # Rough budget: attack chains contribute ~3-5 alerts each
    approx_chain_alerts = int(total_alerts * attack_chain_ratio)
    num_chains = max(5, approx_chain_alerts // 4)

    for _ in range(num_chains):
        base_time = start + timedelta(seconds=random.randint(0, 16 * 3600))
        all_alerts.extend(generate_attack_chain(base_time, alert_counter))

    while len(all_alerts) < total_alerts:
        t = start + timedelta(seconds=random.randint(0, 16 * 3600))
        all_alerts.append(generate_noise(t, alert_counter))

    all_alerts.sort(key=lambda a: a["timestamp"])

    with open("sample_alerts.json", "w") as f:
        json.dump(all_alerts, f, indent=2)

    print(f"Generated {len(all_alerts)} alerts -> sample_alerts.json")
    print(f"  Attack-chain alerts: ~{approx_chain_alerts} across {num_chains} chains")
    print(f"  Noise/background alerts: ~{len(all_alerts) - approx_chain_alerts}")


if __name__ == "__main__":
    main(total_alerts=1200, attack_chain_ratio=0.15)
