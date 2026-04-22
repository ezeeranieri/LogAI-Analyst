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


@pytest.fixture
def mock_api_key(monkeypatch):
    """Fixture to temporarily modify API_KEY for a single test.

    Patches both the environment variable AND the module-level variable in
    main.py (which was imported at module load time and therefore would NOT
    be updated by a simple os.environ change or importlib.reload of config).
    """
    def _set_key(key: str) -> None:
        monkeypatch.setenv("API_KEY", key)
        # Patch the already-imported module-level variable directly so that
        # get_api_key() in main.py sees the new value during the test.
        import main
        monkeypatch.setattr(main, "API_KEY", key)

    return _set_key
