# SYNAPSE - IOC Correlation Engine

AI-powered Indicator of Compromise (IOC) correlation engine that ingests threat indicators, enriches them, builds relationship graphs using NetworkX, detects threat campaigns via Louvain community detection, and presents results through an interactive dashboard.

## Features

- **IOC Ingestion** - Accepts IPs, domains, and file hashes via JSON or plain text
- **Enrichment** - Simulated threat intelligence enrichment (ASN, hosting, SSL, malware family, C2 domains)
- **Graph Correlation** - Builds a weighted relationship graph with probability-union edge accumulation
- **Community Detection** - Louvain algorithm groups related IOCs into threat campaigns
- **Risk Scoring** - Multi-factor confidence scoring with CRITICAL/HIGH/MEDIUM/LOW classification
- **Interactive Dashboard** - React 18 frontend with gradient donut charts, correlation intelligence panels, and campaign breakdowns
- **Export** - JSON and CSV report export

## Tech Stack

**Backend:** Python 3.11+, FastAPI, NetworkX, python-louvain, Pydantic v2

**Frontend:** React 18 (CDN + Babel), D3.js, single-file SPA served via FastAPI static files

## Project Structure

```
app/
  api/           # FastAPI routes and pipeline orchestration
  correlation/   # Graph builder and correlation engine
  models/        # Pydantic data models (IOC, enrichment, campaign, graph)
  reporting/     # Export and summary generation
  scoring/       # Confidence and risk scoring
  services/      # IOC ingestion and enrichment services
  static/        # Frontend (index.html)
config.py        # Application configuration and thresholds
run.py           # Uvicorn dev server entry point
sample_iocs.json # Example IOC payload for testing
```

## Getting Started

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run the server

```bash
python run.py
```

The app starts at **http://localhost:8500**

### API Docs

Interactive API documentation is available at:
- Swagger UI: http://localhost:8500/docs
- ReDoc: http://localhost:8500/redoc

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/analyze` | Submit IOCs for correlation analysis |
| `GET` | `/health` | Health check |

### Example request

```bash
curl -X POST http://localhost:8500/api/analyze \
  -H "Content-Type: application/json" \
  -d @sample_iocs.json
```

## Configuration

Key thresholds are set in `config.py`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `time_proximity_hours` | 48 | Temporal window for time-based edges |
| `min_edge_weight` | 0.1 | Minimum weight to keep an edge |
| `community_resolution` | 1.0 | Louvain resolution (higher = more clusters) |
| `critical_threshold` | 85 | Confidence score for CRITICAL risk |
| `high_threshold` | 65 | Confidence score for HIGH risk |
| `medium_threshold` | 40 | Confidence score for MEDIUM risk |

## Edge Weight Calculation

Shared attributes between IOCs produce weighted edges:

| Relationship | Weight | Signal Strength |
|-------------|--------|-----------------|
| Shared IP | 0.85 | Very strong |
| Shared malware family | 0.78 | Strong |
| Shared C2 domain | 0.72 | Strong |
| Shared SSL issuer | 0.55 | Moderate |
| Shared ASN | 0.35 | Weak-moderate |
| Shared hosting | 0.30 | Weak |
| Time proximity | 0.20 | Very weak (decays with distance) |

Multiple shared attributes accumulate via **probability union**: `w = 1 - (1-a)(1-b)` for diminishing returns.

## License

MIT
