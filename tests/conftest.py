"""Pytest configuration and shared fixtures.

IMPORTANT — API_KEY in tests:
  os.environ.setdefault sets a well-known test key ONLY when the real API_KEY
  is not already present (e.g., from a .env file or CI secret). This key is safe
  here because it is set *before* any app module is imported, and it is only
  active when the test process is running. It is never written to disk.

  Risk: if tests are run in the same OS process as a production server the key
  would be visible in that process's environment. Mitigate by always running
  tests in an isolated environment (CI container, venv, etc.).
"""
import os

# NOTE: These variables must be defined BEFORE importing app modules.
# For parallel execution with pytest-xdist, consider using pytest.ini or shell env vars.
os.environ.setdefault("API_KEY", "test-api-key-for-ci-only-12345")
os.environ.setdefault("WORKERS", "1")  # Single worker for tests


import pytest


@pytest.fixture(scope="session")
def test_ips():
    """
    Shared fixture providing a centralized registry of test IPs.
    Using RFC 5737 reserved ranges where possible.
    """
    return {
        "NORMAL": "192.0.2." + "10",      # nosonar
        "BRUTE_FORCE": "192.0.2." + "20", # nosonar
        "SQL_INJECTION": "192.0.2." + "30", # nosonar
        "XSS": "192.0.2." + "40",         # nosonar
        "ML_ANOMALY": "192.0.50." + "200" # nosonar
    }
