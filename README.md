# 🚀 ThreatSYNC — Threat Intelligence & Alert Prioritisation

> A threat intelligence platform that transforms thousands of noisy security alerts into prioritised, correlated incidents and commander-ready BLUF reports.
---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | ThreatSYNC |
| **Track** |  AI |
| **Team Lead** | Margi Patel - 25dit058@charusat.edu.in |
| **Members** | Nishi Patel , Dhruvi Senjaliya , Madhavi Panara |

---

## 🎯 Problem Statement

Defence and security analysts receive thousands of alerts every day from different sources such as SIEM systems, cyber sensors, satellite feeds, and intelligence reports. These alerts are often noisy, duplicated, and presented in different formats, making it difficult to quickly identify genuine high-risk threats while avoiding false positives.

ThreatSYNC addresses this problem by automatically processing, correlating, prioritising, and summarising these alerts.

---

## 💡 Solution

ThreatSYNC is a web-based threat intelligence platform that ingests multi-source alerts and converts them into a common format. It correlates related alerts into incidents, calculates an explainable risk score, maps relevant threats to the MITRE ATT&CK framework, and generates concise BLUF (Bottom Line Up Front) reports.

This allows analysts and commanders to focus on the most important threats instead of manually reviewing thousands of individual alerts.

---

## ✨ Key Features

- **Multi-Source Alert Ingestion:** Processes alerts from SIEM, CyberSensor, SatelliteFeed, and IntelReport sources.
- **Alert Correlation:** Groups related alerts based on common indicators such as source IP and time window to reduce alert noise.
- **Risk Scoring & Prioritisation:** Uses an explainable scoring system based on severity, asset value, and corroborating alerts to classify incidents as LOW, MEDIUM, HIGH, or CRITICAL.
- **MITRE ATT&CK Mapping:** Maps detected threat behaviour to relevant MITRE ATT&CK techniques.
- **BLUF Reports:** Generates concise Bottom Line Up Front summaries with recommended actions for faster decision-making.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python, JavaScript, HTML, CSS |
| **Frameworks** | Flask API |
| **IBM Technologies** | watsonx.ai |
| **Databases** |  |
| **Other** | MITRE ATT&CK, GitHub |

---

## 📁 Repository Structure

```
├── data/
│   ├── mitre_lookup.json
│   └── sample_alerts_1200.json
│
├── static/
│   ├── app.js
│   ├── index.html
│   └── style.css
│
├── app.py
├── pipeline.py
├── generate_alerts.py
├── README.md
├── requirements.txt
└── START_HERE.txt

---

## ⚡ How to Run

1. Clone the repository
git clone https://github.com/Madhavi-Panara/bob-ai-hackathon--ThreatSync-.git
cd bob-ai-hackathon--ThreatSync-

2. Install dependencies
pip install -r requirements.txt

3. Run the Flask application
python app.py

4. Open the dashboard
Open this in your browser:
http://127.0.0.1:5000

---

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/slides.pdf](presentation/) |

---

## ⚠️ Known Limitations

--The current prototype uses generated/simulated threat-alert data rather than live enterprise security feeds.
--Alert correlation and risk scoring are currently rule-based and designed to be explainable.
--BLUF generation is currently rule-based and structured to be ready for future integration with an LLM such as watsonx.ai.
--The current prototype is intended as a demonstration and is not a production-grade security monitoring system.

## 🏅 What We're Most Proud Of

We are most proud of building an end-to-end threat intelligence pipeline that transforms a large volume of noisy alerts into a smaller number of prioritised incidents.

ThreatSYNC combines ingestion, normalization, correlation, explainable risk scoring, MITRE ATT&CK mapping, and BLUF generation into one dashboard, allowing decision-makers to quickly understand what happened, how serious it is, and what action should be taken.

--still needed to implement the watson.ai in the project.

---
