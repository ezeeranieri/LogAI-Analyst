# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in LogAI-Analyst, please report it responsibly:

1. **Email:** Send details to [ezequiel.ranieri@example.com] (replace with your email)
2. **Subject:** Use prefix `[SECURITY]` in the subject line
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

## Security Features

This project implements the following security measures:

- **API Key Authentication**: All endpoints require `X-API-KEY` header
- **Rate Limiting**: 10 requests per minute per IP (Redis-backed for multi-worker)
- **File Upload Security**: 
  - UUID-based filenames (prevents path traversal)
  - 10MB size limit
  - Streaming upload with size validation
- **Data Privacy**: 100% local processing, no external APIs
- **Ephemeral Storage**: Files auto-deleted after analysis

## Known Limitations

- Regex-based syslog parser may not handle all non-standard formats
- ML model trained on synthetic data may not generalize to all environments
- Stateless API cannot correlate events across multiple uploads

## Best Practices for Deployment

1. Use strong, randomly generated API keys
2. Enable Redis for distributed rate limiting in multi-worker deployments
3. Run behind a reverse proxy (nginx/traefik) with TLS termination
4. Monitor logs for unusual patterns

## Acknowledgments

We appreciate responsible disclosure of security issues.
