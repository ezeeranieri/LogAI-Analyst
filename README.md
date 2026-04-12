# LogAI-Analyst

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
```

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

