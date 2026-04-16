# LogAI-Analyst

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=ezeeranieri_LogAI-Analyst)](https://sonarcloud.io/summary/new_code?id=ezeeranieri_LogAI-Analyst)
[![codecov](https://codecov.io/github/ezeeranieri/LogAI-Analyst/graph/badge.svg?token=SV1EA30KXW)](https://codecov.io/github/ezeeranieri/LogAI-Analyst)

Professional AI-powered security analysis tool built with Python and FastAPI for proactive threat detection in system logs (Syslog / Auth.log).

## Quick Overview

- **FastAPI-based** log analysis API with async file processing
- **Detects 3 main attack types** + ML anomaly detection (Brute Force, User Probing, Time Anomalies + Isolation Forest)
- **Secure by design**: UUID file handling, rate limiting, API key auth
- **Optimized algorithms**: O(n) sliding window for high-volume logs

👉 *10-second summary: Upload auth.log → Receive structured anomaly detection with human-readable explanations.*

## Tech Stack

| Component | Technology |
|-----------|------------|
| **API Framework** | FastAPI + Pydantic |
| **Data Processing** | Pandas + NumPy |
| **ML Engine** | Scikit-learn (Isolation Forest) |
| **Rate Limiting** | slowapi + Redis (optional) |
| **Deployment** | Docker + Uvicorn |
| **Testing** | pytest + FastAPI TestClient |

## How It Works

```
┌─────────────┐    ┌──────────────┐    ┌─────────────┐    ┌──────────────┐
│ 1. Upload   │ →  │ 2. Parser    │ →  │ 3. Engine   │ →  │ 4. Return    │
│    Log File │    │    Extracts  │    │    Applies  │    │    Anomalies │
│             │    │    Structured│    │    Rules+ML │    │    + Reasons │
└─────────────┘    │    Data      │    └─────────────┘    └──────────────┘
                   └──────────────┘
```

1. **Upload**: Secure file upload (max 10MB) with UUID sanitization
2. **Parse**: Extract timestamp, IP, user, action from syslog/auth.log
3. **Detect**: Rule-based heuristics (brute force, probing) + lightweight ML for unknown patterns
4. **Return**: JSON with threats, confidence scores, and human-readable explanations

## Requirements

- Python 3.10+
- Docker (recommended)
- `pip install -r requirements.txt`

## Production Features

- **Authentication (NEW)**: Security enforced via `X-API-KEY` header in every request.
- **Rate Limiting (NEW)**: 10 requests per minute per IP on the `/analyze` endpoint using slowapi, to prevent abuse and DoS.
- **Docker Hardening**: Secure execution using a non-privileged user (`appuser`).
- **UUID Sanitization**: Unique temporary filenames for maximum security and path traversal prevention.
- **Heuristic & Lightweight ML**: Rule-based detection (3 attack types) + ML layer for unknown patterns.
- **Security Quotas**: 10MB file upload limit to prevent storage exhaustion or DoS.

## Security & Privacy

### Data Processing

- **100% Local Processing**: Log files are processed **on-premises** — no data is sent to external APIs, cloud services, or third-party AI providers
- **Ephemeral Storage**: Uploaded files are stored temporarily (UUID-named) and **automatically deleted** after analysis via `finally` blocks
- **No Data Persistence**: The API is **stateless** — log contents are never stored in databases or retained between requests
- **No Training on Real Data**: The ML model (`Isolation Forest`) is **pre-trained offline** on synthetic data — it never learns from or retains your actual log entries

### Sensitive Information Handling

- **IP addresses**: Hashed using deterministic `zlib.adler32` for feature extraction (reversible mapping not stored)
- **Usernames**: Processed only for detection rules (brute force, probing) — never logged or retained
- **Passwords/Keys**: Never parsed — the regex explicitly extracts only syslog envelope data (timestamp, IP, user, action)

### Compliance Notes

This architecture supports GDPR/privacy-conscious deployments:
- Data never leaves your infrastructure
- No persistent storage of PII (Personally Identifiable Information)
- Automatic cleanup prevents data leakage between requests

## Installation and Deployment

### Environment Configuration
Create a `.env` file in the root directory with the following variables:
```env
DATA_DIR=data
API_KEY=your_super_secure_secret
LOG_FILE=app_production.log
APP_HOST=127.0.0.1
APP_PORT=8000
```

### Initial Model Training (NEW)
Before running the API for the first time, you must train the AI anomaly detection model:

**Note:** `train_model.py` must be run from the project root directory:
```bash
python train_model.py
```
This will generate synthetic data and save a pre-trained `IsolationForest` model to `data/model.pkl`.

### Running with Docker (Recommended)
```bash
docker build -t logai-analyst .
docker run -p 8000:8000 --env-file .env logai-analyst
```

## API Usage (/analyze)

All interactions with the analysis endpoint require your API Key in the headers.

**Example with `curl` (Authenticated File Upload):**
```bash
curl -X POST "http://localhost:8000/analyze" \
     -H "X-API-KEY: your_super_secure_secret" \
     -H "Accept: application/json" \
     -F "file=@path/to/log/auth.log"
```

### Response Structure (JSON)
The API returns a detailed report of the detected threats:

```json
{
  "status": "success",
  "total_threats": 1,
  "data": [
    {
      "timestamp": "Oct 11 10:00:00",
      "ip_origin": "192.0.2.1",
      "user": "root",
      "action": "Failed password for root",
      "status": "FAIL",
      "datetime": "2026-10-11 10:00:00",
      "reason": "Brute Force (>5 fails per min)"
    }
  ]
}
```

## Quality and Testing (QA)

The project includes an integration test suite to validate the authentication flow and detection engine.

### Running tests:
```bash
python -m pytest
```

## Design Decisions

This project implements several architectural and security patterns to ensure reliability and scalability:

### Why FastAPI over Flask
FastAPI was chosen for its high performance (comparable to NodeJS and Go) and native support for asynchronous operations. Unlike Flask, FastAPI provides:
- **Automatic data validation** via Pydantic models, eliminating boilerplate validation code
- **Native OpenAPI/Swagger documentation** generation, essential for API governance
- **Dependency injection system** that simplifies testing and middleware implementation
- **Type hints as first-class citizens**, catching integration bugs at development time

### Why Isolation Forest for Anomaly Detection
Traditional rule-based systems can only detect known attack patterns. Isolation Forest was selected because:
- It isolates anomalies instead of profiling normal data, making it effective for **zero-day-like threats**
- **O(n log n) training complexity** vs O(n²) for distance-based methods like LOF
- **Unsupervised learning** requires no labeled attack datasets, which are expensive to produce
- Linear scalability with feature dimensions, ideal for high-dimensional log metadata (hour, IP hash, status)

### Why Sliding Window over Pandas Rolling
The `UserProbingRule` detects when a single IP attempts 4+ different usernames within 10 minutes. Two implementations were considered:

| Approach | Time Complexity | Memory | Scalability |
|----------|----------------|--------|-------------|
| `df.rolling('10min').apply(lambda x: len(set(x)))` | **O(n²)** | High (slices) | Poor |
| **Two-pointer sliding window** | **O(n)** | O(k) where k=unique users | Excellent |

The sliding window maintains a frequency dictionary and moves left/right pointers, processing each element at most twice. This provides **deterministic linear performance** even with high-volume logs (10K+ entries per IP).

### Why UUID-Based File Handling
To prevent **Path Traversal attacks** (`../../../etc/passwd`) and **race conditions**:
- Uploaded files are immediately renamed to UUID v4 before touching the filesystem
- Original filenames are never used for disk operations
- Temporary directory is isolated and cleaned up via `finally` blocks
- This follows the security principle: **never trust client-provided filenames**

### Why Async Streaming for File Uploads
Instead of loading entire files into memory (risking DoS via memory exhaustion):
- Files are streamed in **8KB chunks** using `aiofiles`
- Size validation happens **during streaming**, not after full upload
- This supports files up to 10MB with **constant memory footprint**, regardless of concurrent uploads

### Why Redis-Backed Rate Limiting
For multi-worker deployments (Kubernetes, Docker Compose):
- **In-memory rate limiting** fails when multiple API instances run behind a load balancer
- **Redis backend** ensures consistent rate limiting state across all workers
- The implementation uses `slowapi` with automatic fallback to in-memory for local development

### Why Separate Training from Inference
Originally `IADetectorRule` trained on-the-fly if no model existed. This was changed because:
- **Cold-start latency**: First request took 3-5 seconds
- **Data leakage**: Training on the same data being evaluated produces circular logic
- **Solution**: `train_model.py` generates synthetic data offline, decoupling training from the request cycle

## Limitations

This section documents known constraints that affect deployment decisions:

### Model Trained on Synthetic Data
The Isolation Forest model is trained on synthetically generated logs. While this ensures the model has "seen" diverse patterns, it may not generalize perfectly to:
- Highly specialized enterprise environments with unique logging patterns
- Legacy systems with non-standard syslog formats
- **Mitigation**: The detection engine falls back to heuristic rules when ML confidence is low.

### Stateless API Architecture
The API processes each log file independently with **no persistent state**:
- No correlation between events across multiple API calls
- Cannot detect slow-burning attacks spread across multiple uploads
- **Mitigation**: The `/stats` endpoint provides parsing metadata that can be aggregated by an external SIEM.

### Pandas-Based Processing
The current implementation uses Pandas for log manipulation:
- **Single-threaded processing** limits throughput on multi-core systems
- **Memory-bound** for very large logs (100MB+ files would require chunking)
- **Mitigation**: 10MB upload limit prevents memory exhaustion; for larger scale, the parser would need migration to Dask or Polars.

### Year Ambiguity in Syslog Format
Standard syslog format (`Oct 11 10:00:00`) lacks year information:
- The parser infers the current year, which fails for logs from December processed in January
- Python 3.15 will change `pd.to_datetime()` behavior for year-less dates
- **Mitigation**: Year inference happens at parsing time; explicit year in log format would be ideal.

### No Persistent Threat Storage
Detected anomalies are returned in the API response but **not stored**:
- No historical trending or attack pattern analysis over time
- Requires external database integration for long-term storage
- **Trade-off**: This was intentional to keep the API stateless and horizontally scalable.

## Frequently Asked Questions (FAQ)

### What types of attacks does it detect?
LogAI-Analyst identifies four main types of threats:
- **Brute Force**: Excessive failed login attempts (>5 per minute) from a single IP.
- **Time Anomalies**: Successful logins occurring outside of standard business hours (8 AM - 6 PM).
- **User Probing**: A single IP trying to access more than 3 different user accounts within 10 minutes.
- **AI Anomalies**: Unusual patterns detected by machine learning that don't fit normal system behavior.

### Do I need security knowledge to use it?
No. The tool is designed to be accessible to developers and system administrators. Every detection includes a clear "reason" field in the JSON response explaining why a specific event was flagged as a threat.

### What is Isolation Forest and what does it do here?
Isolation Forest is an unsupervised machine learning algorithm used for anomaly detection. In this project, it analyzes login metadata (time, IP hashes, and status) to isolate outliers that might represent sophisticated attacks which don't trigger traditional heuristic rules.

### How is the API protected?
The API is hardened with an mandatory `X-API-KEY` header authentication. Every request is validated against a secret key defined in your environment variables, ensuring that only authorized users can perform log analysis.

### What log format does it accept?
It natively supports standard UNIX authentication logs (`auth.log` and `syslog`). This includes logs generated by `sshd` and other system services that follow the classic syslog format.

## Challenges & Learnings

Building a production-grade log analysis API surfaced several non-trivial engineering problems. Below are the concrete challenges encountered and what each one taught.

### 1. Syslog Parsing is More Complex Than It Looks
Writing a regex that reliably handles real-world `auth.log` entries—where `sshd`, `sudo`, `PAM`, and `cron` all write in slightly different formats—required a two-pass approach: a primary regex to extract the syslog envelope (`timestamp`, `hostname`, `process`) and separate secondary regexes for the IP and username inside the free-form action field. A single monolithic regex proved too brittle.

**Learning**: Composing small, single-purpose regexes and combining their results is far more maintainable than trying to capture everything in one pattern.

### 2. Rolling Time Windows on a Pandas Index
The Brute Force rule needs to count failed logins per IP within a sliding 1-minute window. `DataFrame.rolling()` only works on a `DatetimeIndex`, which required setting the index before grouping, sorting within each group, and then resetting it afterwards. Forgetting any step produced silently wrong counts.

**Learning**: Pandas time-based rolling operations have strict prerequisites. Always validate intermediate DataFrame shapes and index types during development.

### 3. Decoupling ML Training from the Request Cycle (Critical Decision)
**The Problem**: The original `IADetectorRule` trained an `IsolationForest` on-the-fly if no model file existed. This created two severe issues:
- **Cold-start latency**: First request took 3-5 seconds, unacceptable for production APIs
- **Data leakage**: The model trained on the very data it was supposed to evaluate, making anomaly detection circular and unreliable

**The Decision**: I chose to **reject runtime training entirely** and move it to an offline `train_model.py` script with synthetic data generation.

**Trade-offs**:
- ✅ Eliminated cold-start latency
- ✅ Eliminated data leakage
- ✅ Model file can be versioned and audited
- ❌ Requires manual retraining for new environments
- ❌ Synthetic data may not match real-world distributions

**Learning**: *An ML model trained on the data it evaluates cannot reliably flag outliers. The engineering cost of offline training is always lower than the operational risk of circular logic.*

### 4. Feature Engineering Must Be Identical Between Training and Inference
The IP-to-number encoding uses `zlib.adler32` for deterministic hashing. Any difference between how `train_model.py` computes features and how `IADetectorRule.evaluate()` computes them would silently produce meaningless anomaly scores. Both code paths share the exact same hashing logic and `status` mapping, and this contract must be enforced manually.

**Learning**: Feature extraction logic should live in a shared utility function rather than be duplicated. A mismatch between training and inference pipelines is one of the hardest ML bugs to diagnose.

### 5. SonarCloud Security Hotspots Require Explicit Intent
Hardcoded IP strings—even inside clearly named test constants—were flagged as security hotspots. The fix required migrating all test IPs to the IANA RFC 5737 `192.0.2.x` documentation-reserved range, which is globally understood to be non-routable and non-production.

**Learning**: IP address literals are a recognized security smell regardless of context. Using the IANA-reserved `TEST-NET-1` range (`192.0.2.0/24`) communicates intent unambiguously to both static analysis tools and human reviewers.

### 6. Algorithmic Complexity: When O(n²) Becomes Unacceptable
The `UserProbingRule` initially used `df.rolling('10min').apply(lambda x: len(set(x['usuario'])))`. For a log with 10,000 entries from one IP, this resulted in:
- **10,000 window slices** created
- **10,000 set operations** on variable-size windows
- **Effective complexity**: O(n²) with high constant factors

**The Decision**: Implement a custom two-pointer sliding window with frequency dictionary:
```python
left = 0
user_counts = {}
for right in range(n):
    # Add right element
    user_counts[usuarios[right]] += 1
    # Shrink window if needed
    while window_too_large:
        user_counts[usuarios[left]] -= 1
        left += 1
```

**Impact**: 
- Same result, but **O(n) time** and **O(k) memory** (k = unique users)
- Processing time dropped from ~2s to ~50ms on 10K entry datasets
- Code is more complex but the performance gain justified the added complexity

**Learning**: *Pandas convenience methods can hide algorithmic complexity. When processing high-volume security data, manual optimization beats abstraction.*

### 7. Ambiguous Date Parsing Across Python Versions
`pd.to_datetime()` with format `%b %d %H:%M:%S` (the standard syslog format, which has no year) raises a `DeprecationWarning` in Python 3.14+ because the behavior on leap days is undefined. The parser works around this by correcting years defaulted to `1900` back to the current year, but the underlying Pandas behavior is changing in 3.15.

**Learning**: Timestamp formats without a year component are inherently ambiguous. Year inference should be added as early as possible in the parsing pipeline rather than patched downstream.


