"""Pytest configuration and shared fixtures."""
import os

# Set test API key before importing app modules
os.environ.setdefault("API_KEY", "test-api-key-for-ci-only-12345")
os.environ.setdefault("WORKERS", "1")  # Single worker for tests
