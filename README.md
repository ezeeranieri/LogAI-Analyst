# LogAI-Analyst

[![Quality Gate](https://sonarcloud.io/api/project_badges/quality_gate?project=ezeeranieri_LogAI-Analyst)](https://sonarcloud.io/summary/new_code?id=ezeeranieri_LogAI-Analyst)
[![codecov](https://codecov.io/github/ezeeranieri/LogAI-Analyst/graph/badge.svg?token=SV1EA30KXW)](https://codecov.io/github/ezeeranieri/LogAI-Analyst)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Real-time security log analysis system that detects brute-force, web attacks, and anomalies through a professional Dashboard + Hybrid ML/Heuristic API.**

## Impact Statement

**Problem:** Security operations centers (SOC) often struggle with voluminous logs, leading to alert fatigue or missed sophisticated attacks like slow brute-force or encoded SQL injections.

**Solution:** A comprehensive security platform featuring a **Professional Streamlit Dashboard** for visualization and a **High-Performance API** that processes 10,000+ log entries in O(n) time. It detects 7+ attack patterns + unknown anomalies via Isolation Forest with a 100% on-premises architecture.

**Key Results:**
- 🖥️ **Professional Dashboard**: Real-time visualization of threats, metrics, and forensic log viewer.
- 🔒 **100% local processing** — zero data leaves your infrastructure.
- ⚡ **Single-Pass O(n) Parser**: Robust timestamp handling and optimized file reading.
- 🤖 **Hybrid detection**: Rule-based heuristics (SQLi, XSS, Brute Force) + Refined ML layer (`fail_ratio` awareness).
- 🧪 **63 automated tests** covering API, detection engine, and web security scenarios.

## Quick Start

### 1. Dashboard Mode (Recommended)
```bash
# Clone and setup
git clone https://github.com/ezeeranieri/LogAI-Analyst.git
cd LogAI-Analyst
pip install -r requirements.txt

# Run Dashboard
streamlit run dashboard.py
```

### 2. API Mode
```bash
# Run API
uvicorn main:app --reload

# Alternative: Docker with Redis (Rate Limiting)
cp .env.example .env
docker compose up --build

# Analyze a log
curl -X POST "http://localhost:8000/analyze" \
  -H "X-API-KEY: your_secret_key" \
  -F "file=@/var/log/auth.log"
```

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│  Dashboard   │ ↔  │   LogAI API   │ →  │   Engine     │ →  │  Analytics   │
│ (Streamlit)  │    │  (FastAPI)    │    │ Rules + ML   │    │  & Reports   │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
       │                   │                   │                   │
  File Upload         Single-Pass         Hybrid Detect:      JSON/CSV Export
  Metric Cards        urldecode Logic     SQLi, XSS, PathT    Log Highlighting
  Forensic View       Rate Limiting       ML (fail_ratio)    ML Anomaly Scores
```

## Tech Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| **UI** | Streamlit | Professional Security Dashboard |
| **API** | FastAPI | Async endpoints, auto-validation |
| **Logic** | Pandas + NumPy | O(n) high-speed analysis |
| **Web Security** | urldecode Patterns | Encoded attack detection |
| **ML** | Scikit-learn (Isolation Forest) | Unknown behavior detection |
| **Security** | slowapi + Redis | Distributed rate limiting |
| **Testing** | pytest | 63 automated tests |

## Production Features

| Feature | Implementation |
|---------|---------------|
| **Interactive Dashboard** | Carbon-styled UI with metric cards and log visualizer |
| **Web Attack Detection** | SQL Injection, XSS, and Path Traversal with **urldecode preprocessing** |
| **ML Refined Features** | `hour`, `ip_hash`, `status`, and **`fail_ratio_per_ip`** for slow attacks |
| **Optimized Parser** | Single-pass reading with `seek(0)` and multi-format `strptime` |
| **Rate Limiting** | 10 req/min (Global enforcement via Redis) |
| **Safe File Ingestion** | UUID ephemeral renaming (Path Traversal protection) + Streaming validation (8KB chunks) for DoS mitigation |
| **Privacy & GDPR** | Auto-cleanup, hashed features, 100% on-premises |

## API Reference

### POST /analyze
Upload and analyze logs. Returns detected threats with severity and reasons.

### POST /export
Export analysis results to **JSON** or **CSV** for SIEM integration or audit.

### POST /stats
High-level parsing statistics to verify log ingestion health.

## Engineering Decisions

### Why the Hybrid Approach?
Heuristic rules provide high precision for known attack patterns (SQLi, Brute Force), while the Isolation Forest ML model surfaces "weird" behavior that doesn't fit a specific rule.

### Unsupervised ML: Isolation Forest
We chose **Isolation Forest** specifically for its efficacy in detecting anomalies in unlabeled datasets (unsupervised learning). Unlike signature-based systems, this allows us to identify **zero-day attacks** and atypical behaviors without requiring prior knowledge of the threat pattern.

### Stateless Architecture & SIEM Integration
The engine is **Stateless** by design to maximize processing throughput and simplify horizontal scaling. While it doesn't store session history, it is built for **SIEM compatibility**, offering structured JSON/CSV exports that can be ingested by Splunk, ELK, or specialized Forensic tools.

### Optimized Single-Pass Parsing
Previously, the system read the file twice. The new implementation detects the format from a 10-line sample and uses `file.seek(0)` to process the rest in a single pass, doubling performance on large datasets.

### SQLi urldecode Logic
To bypass simple detection, attackers encode payloads. LogAI-Analyst performs `unquote_plus` decoding before applying context-aware regex patterns, significantly reducing false positives while catching encoded bypasses.

## Testing

```bash
# Run all 63 tests
python -m pytest tests/ -v
```

**Coverage:** API auth, file security, 7 detection rules, feature engineering, parser robustness, and export logic.

## License

MIT License — see [LICENSE](LICENSE) file.

---

**Built with:** Python · Streamlit · FastAPI · Scikit-learn · Pandas


