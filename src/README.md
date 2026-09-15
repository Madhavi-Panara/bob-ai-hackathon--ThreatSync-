# ThreatSYNC — Commander's Threat Intelligence Dashboard

## What this builds
ThreatSYNC is a hackathon-ready web dashboard for the D2 problem:
- ingest alerts from SIEM, cyber sensors, satellite feeds and intelligence reports
- normalize them into a common alert structure
- correlate related alerts into incidents
- calculate an explainable priority score
- classify incidents as Critical / High / Medium / Low
- map detected behavior to MITRE ATT&CK
- generate BLUF (Bottom Line Up Front) summaries and recommended actions

## Dashboard
1. Command Center
2. Incident Management
3. Alert Intelligence
4. MITRE ATT&CK
5. BLUF Reports

## Run with Python
1. Install Python 3.
2. Open this folder in VS Code.
3. Open Terminal.
4. Run:
   pip install flask
5. Then:
   python app.py
6. Open:
   http://127.0.0.1:5000

## Project structure
- app.py — Flask server/API
- pipeline.py — correlation, scoring, MITRE mapping and BLUF logic
- static/index.html — dashboard shell
- static/app.js — dashboard interactions
- static/style.css — dashboard styling
- data/sample_alerts.json — sample multi-source alerts
- data/mitre_lookup.json — ATT&CK reference data

## Demo flow for judges
Raw alerts → Normalize → Correlate → Prioritize → MITRE → BLUF → Commander

The included sample produces multiple correlated incidents so the dashboard can demonstrate the full workflow without external APIs.

## Future upgrades
- real SIEM/API ingestion
- satellite and cyber-sensor adapters
- PostgreSQL/SQLite persistence
- LLM-powered BLUF generation
- analyst feedback loop
- authentication and role-based access
- live ATT&CK STIX updates
