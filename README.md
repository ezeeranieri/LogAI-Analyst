# LogAI-Analyst

[![Quality gate](https://sonarcloud.io/api/project_badges/quality_gate?project=ezeeranieri_LogAI-Analyst)](https://sonarcloud.io/summary/new_code?id=ezeeranieri_LogAI-Analyst)
[![codecov](https://codecov.io/github/ezeeranieri/LogAI-Analyst/graph/badge.svg?token=SV1EA30KXW)](https://codecov.io/github/ezeeranieri/LogAI-Analyst)

Professional AI-powered security analysis tool built with Python and FastAPI for proactive threat detection in system logs (Syslog / Auth.log).

## Requirements

- Python 3.10+
- Docker (recommended)
- `pip install -r requirements.txt`

## Production Features

- **Authentication (NEW)**: Security enforced via `X-API-KEY` header in every request.
- **Docker Hardening**: Secure execution using a non-privileged user (`appuser`).
- **UUID Sanitization**: Unique temporary filenames for maximum security and path traversal prevention.
- **Heuristic & AI Detection**: 4 layers of analysis (Brute Force, Time Anomalies, User Probing, and IA).
- **Security Quotas**: 10MB file upload limit to prevent storage exhaustion or DoS.

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

## Engineering Decisions

This project implements several architectural and security patterns to ensure reliability and scalability:

- **FastAPI over Flask**: FastAPI was chosen for its high performance and native support for asynchronous operations. It provides robust data validation via Pydantic and automatic OpenAPI (Swagger) documentation, which is essential for maintaining a production-grade security API.
- **Isolation Forest for Anomaly Detection**: Unlike traditional rule-based systems, Isolation Forest is highly effective at detecting unknown threats (Zero-Day-like patterns). It isolates anomalies rather than profiling normal data, making it ideal for high-dimensional log data where patterns evolve over time.
- **UUID for Temporary Files**: To prevent Path Traversal attacks and ensure file uniqueness, all uploaded logs are renamed to a version 4 UUID before processing. This sanitization step ensures that the application never trusts the client-provided filename.
- **Modular Rules (Abstract Base Classes)**: The detection engine uses an inheritance-based architecture. By implementing the `DetectionRule` abstract class, developers can add new heuristic or AI rules without modifying the core processing logic (following the Open/Closed Principle).

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

### 3. Decoupling ML Training from the Request Cycle
The original `IADetectorRule` trained an `IsolationForest` on-the-fly if no model file existed, meaning the first request after a cold start could take several seconds and produced a model trained on the very data it was supposed to evaluate—making anomaly detection circular and unreliable. Separating training into `train_model.py` with synthetic data solved both the latency and the logic problem.

**Learning**: An ML model trained on the data it is meant to evaluate cannot reliably flag outliers. Training data must be independent of inference data.

### 4. Feature Engineering Must Be Identical Between Training and Inference
The IP-to-number encoding uses `zlib.adler32` for deterministic hashing. Any difference between how `train_model.py` computes features and how `IADetectorRule.evaluate()` computes them would silently produce meaningless anomaly scores. Both code paths share the exact same hashing logic and `status` mapping, and this contract must be enforced manually.

**Learning**: Feature extraction logic should live in a shared utility function rather than be duplicated. A mismatch between training and inference pipelines is one of the hardest ML bugs to diagnose.

### 5. SonarCloud Security Hotspots Require Explicit Intent
Hardcoded IP strings—even inside clearly named test constants—were flagged as security hotspots. The fix required migrating all test IPs to the IANA RFC 5737 `192.0.2.x` documentation-reserved range, which is globally understood to be non-routable and non-production.

**Learning**: IP address literals are a recognized security smell regardless of context. Using the IANA-reserved `TEST-NET-1` range (`192.0.2.0/24`) communicates intent unambiguously to both static analysis tools and human reviewers.

### 6. Ambiguous Date Parsing Across Python Versions
`pd.to_datetime()` with format `%b %d %H:%M:%S` (the standard syslog format, which has no year) raises a `DeprecationWarning` in Python 3.14+ because the behavior on leap days is undefined. The parser works around this by correcting years defaulted to `1900` back to the current year, but the underlying Pandas behavior is changing in 3.15.

**Learning**: Timestamp formats without a year component are inherently ambiguous. Year inference should be added as early as possible in the parsing pipeline rather than patched downstream.


