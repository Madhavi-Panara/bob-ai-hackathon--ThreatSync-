# Solution Overview

## What We Built

--ThreatSYNC is a web dashboard that takes a flood of raw security alerts — coming from different tools like SIEM systems, cyber sensors, satellite feeds, and intelligence reports — and automatically turns them into a short, ranked list of real incidents. Instead of an analyst having to manually notice that five separate "minor" alerts across four different tools are actually one coordinated attack, ThreatSYNC groups them together itself, scores how serious the combined incident is, tags it with the relevant attack technique, and writes a short plain-English summary a commander can read in seconds.

## How It Works

1. Raw alerts are ingested from multiple simulated sources (SIEM, CyberSensor, SatelliteFeed, IntelReport) and normalized into one common format.
2. The correlation engine groups alerts that share the same source IP within a rolling time window into a single incident — turning, for example, 12 scattered alerts into 5 real incidents.
3. Each incident is scored using a weighted formula (severity × asset value × number of corroborating alerts), and classified as CRITICAL, HIGH, MEDIUM, or LOW.
4. Each incident is matched against a MITRE ATT&CK technique lookup table using keyword analysis of the alert descriptions.
5. A BLUF (Bottom Line Up Front) report is generated for each incident — a short "what happened / how serious / what to do" summary — and shown in the dashboard, ranked highest-risk first.
6. Analysts view everything through a live dashboard: raw alert feed on one side, prioritized incidents on the other, with a click-through detail view for each incident's full evidence trail.

## Architecture Diagram

[Alert Sources: SIEM, CyberSensor, SatelliteFeed, IntelReport]
              ↓
       [Flask Backend: pipeline.py]
       (Correlate → Score → Map ATT&CK → Generate BLUF)
              ↓
       [REST API: /api/alerts, /api/incidents, /api/summary]
              ↓
       [Dashboard Frontend: HTML/JS or React]


## Key Design Decisions

Key Design Decisions

1. Rule-based correlation and scoring (instead of a trained ML model)
This keeps the system fully explainable — when asked "why was this flagged?", we can point to the exact formula (severity × asset value × corroborating alert count) rather than a black-box prediction. It also runs instantly with zero training data, which mattered given our timeline.

2. Swappable BLUF report generation function
Rather than hardcoding one approach, we isolated report generation into a single function. This let the system run fully offline for a reliable live demo, while the prompt-building logic is already structured to plug directly into an LLM like watsonx.ai for richer, more natural summaries — the integration code exists and is documented, even though the live demo uses the offline path.

3. Static, generated sample dataset (instead of live security feeds)
This let us demonstrate the full pipeline convincingly without needing access to real production SIEM systems, which wouldn't have been available or appropriate for a hackathon setting anyway.

4. Flask backend with a simple REST API
This kept development fast and decoupled the frontend from the correlation logic, so either side could be modified or replaced independently without touching the other.


## IBM Technologies Used

--watsonx.ai (architected for, not yet connected): The BLUF report generation is deliberately isolated in a single function (generate_bluf_report() / bluf()) designed to call watsonx.ai's Granite model — the full REST integration code (IAM auth, prompt construction, JSON parsing) is written and included in the repo. Due to IBM Cloud's account verification requirements and hackathon time constraints, the live demo runs on the offline rule-based fallback, which produces equivalent structured output (bottom line, details, recommended action) with zero external dependencies — ensuring a reliable demo.
