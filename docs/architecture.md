# Architecture

## System Architecture

```mermaid
graph TD
    A[Alert SourcesSIEM / CyberSensor /SatelliteFeed / IntelReport] -->|HTTP| B[Flask Backendpipeline.py]
    B -->|REST API| C[Correlation Engine]
    C -->|SDK| D[Scoring & MITRE ATT&CKMapping]
    D --> E[BLUF Report Generatorrule-based,watsonx.ai-ready]
    E -->|Publish| F[REST API/api/alerts /api/incidents/api/summary
]
    F -->|Fetch| G|Dashboard FrontendHTML/JS| 
```

## Components

| Component | Technology | Responsibility |
|---|---|---|
| Frontend | HTML/CSS/JavaScript (SPA) | Command Center dashboard, incident cards, alert search/filter, BLUF report modal |
| Backend API | Flask (Python) |Serves REST endpoints, orchestrates the correlation → scoring → BLUF pipeline |
| Correlation Engine | Custom Python logic (pipeline.py) |Groups related raw alerts into single incidents using shared source IP + time window |
| Scoring & MITRE Mapping | Custom Python logic | Computes risk score (severity × asset value × corroboration), maps incidents to ATT&CK techniques |
| AI / ML | watsonx.ai (Granite model) — architected, not connected in demo | Intended to generate natural-language BLUF summaries; offline rule-based generator used as the working fallback |
| Database | Static JSON file (alerts_data.json) | Holds the generated sample alert dataset; no database used in this prototype |

## Data Flow

1. Raw alerts (from SIEM, CyberSensor, SatelliteFeed, and IntelReport) are loaded from a generated JSON dataset simulating a live multi-source feed.
2. The correlation engine groups alerts sharing a source IP within a 30-minute window into a single incident.
3. Each incident is scored using a weighted formula (severity × asset value × number of corroborating alerts) and classified as CRITICAL, HIGH, MEDIUM, or LOW.
4. Each incident is matched against a MITRE ATT&CK technique lookup table via keyword analysis of its alert descriptions.
5. A BLUF (Bottom Line Up Front) report is generated per incident — currently via a rule-based generator, with the code path already built to call watsonx.ai instead.
6. The Flask backend exposes this processed data through REST endpoints (/api/alerts, /api/incidents, /api/summary).
7. The dashboard frontend fetches from these endpoints and renders the raw feed, ranked incidents, and BLUF detail view; the Refresh button re-triggers the fetch cycle.

## Security Considerations

--API keys and credentials (for the watsonx.ai integration) are stored in a .env file, excluded from version control via .gitignore — never hardcoded in source.
--The watsonx.ai integration includes a try/except fallback: if the API call fails or credentials are missing, the system automatically falls back to the offline generator rather than exposing an error or crashing.
--No real production security data is used — the dataset is entirely synthetic and generated for demonstration purposes.

## Scalability Notes

--The Flask backend is currently stateless per request and reads from a static JSON file, so it could be extended to read from a real database (e.g., PostgreSQL) or live message queue (e.g., Kafka) without changing the correlation/scoring logic itself. The correlation step is currently O(n²) over the alert set for simplicity — at production scale (real-time feeds with millions of alerts), this would need to move to an indexed, streaming-window approach (e.g., grouping by source IP in a time-bucketed store) rather than pairwise comparison. The BLUF generation step, once connected to watsonx.ai, would become the primary latency bottleneck and would benefit from batching multiple incidents per API call.
