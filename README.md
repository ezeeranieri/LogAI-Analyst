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
      "ip_origin": "192.168.1.1",
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

