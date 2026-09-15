# Setup Guide

> **ThreatSYNC is a Flask-based cybersecurity threat intelligence correlation
and alert prioritisation assistant.

The prototype ingests synthetic security alerts from multiple sources,
correlates related alerts, assigns risk scores, maps activity to MITRE
ATT&CK techniques, and generates BLUF (Bottom Line Up Front) incident
summaries.**

## Prerequisites

Before running ThreatSYNC, install:

- Python 3.10 or newer
- Git

No Node.js, Docker, PostgreSQL, or external database is required for the
current prototype.

The demo uses synthetic alert data stored in JSON files.

## Environment Variables

The current prototype can run without external credentials.

An environment-variable template is provided at:

```text
src/.env.example

```bash
cp src/.env.example src/.env
```

| Variable | Description | Required |
|---|---|---|
| `WATSONX_API_KEY` | IBM watsonx.ai API key for future AI integration | No |
| `WATSONX_PROJECT_ID` | IBM watsonx.ai project ID | No |
| `DATABASE_URL` | Database connection string for future database integration | No |
| `SLACK_WEBHOOK_URL` | Optional Slack notification webhook | No |

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/[your-org]/[your-repo].git
cd [your-repo]

# 2. Install backend dependencies
[your command — e.g.: pip install -r requirements.txt]

# 3. Install frontend dependencies (if applicable)
[your command — e.g.: cd frontend && npm install]

# 4. Set up the database (if applicable)
[your command — e.g.: python manage.py migrate]
```

## Running the Application

```bash
From the repository root:

python src/app.py

The Flask development server will start locally.

Open:

http://localhost:8000

If the application reports a different port in the terminal, use the port
shown by Flask.
The application will be available at: `http://localhost:5000`

## Running Tests

```bash
[your test command — e.g.: pytest tests/ -v]

Application Structure
src/
├── app.py
├── pipeline.py
├── generate_alerts.py
├── requirements.txt
├── .env.example
├── data/
└── static/
```

## Quick Demo (Optional)

Start the application:
python src/app.py
Open the dashboard:
http://localhost:8000
Review the generated security alerts and prioritised incidents.
Use the dashboard to inspect correlated alerts, risk levels, MITRE
ATT&CK mappings, and BLUF summaries.
If the application provides a simulation/generate-alert control, use it
to create additional synthetic alerts and refresh the analysis.

```

## Troubleshooting

| Issue | Solution |
|---|---|
| [e.g., `ModuleNotFoundError`] | [e.g., Run `pip install -r requirements.txt` again] |
| [e.g., Database connection refused] | [e.g., Ensure PostgreSQL is running: `docker compose up db`] |
| [e.g., watsonx.ai 401 error] | [e.g., Check `WATSONX_API_KEY` in your `.env` file] |
