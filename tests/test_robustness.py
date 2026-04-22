import pytest
import io
from fastapi.testclient import TestClient
from main import app
from src.config import API_KEY

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
TEST_IP_1 = "192.0.2.1"
TEST_IP_2 = "192.0.2.2"

client = TestClient(app)
HEADERS = {"X-API-KEY": API_KEY}

def test_analyze_unparsable_timestamps():
    """
    Verifies that API does NOT return 500 when receiving logs with corrupted timestamps.
    Should ignore malformed records and process the rest or return empty success.
    """
    log_content = (
        f"INVALID_TIMESTAMP server sshd[123]: Failed password for root from {TEST_IP_1}\n"
        f"Oct 11 10:00:00 server sshd[123]: Failed password for root from {TEST_IP_2}"
    )
    
    file = io.BytesIO(log_content.encode("utf-8"))
    
    response = client.post(
        "/analyze",
        files={"file": ("auth.log", file, "text/plain")},
        headers=HEADERS
    )
    
    # Should not return 500
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    # First record is invalid and gets dropped. Second is valid but doesn't trigger rules alone.
    # So total_threats should be 0 or higher if there are rules that trigger with 1 row.
    # The important thing is that it's NOT a 500.
    assert "total_threats" in data

def test_analyze_completely_corrupt_file():
    """
    Verifies completely garbage file.
    """
    log_content = "This is not a log file at all.\nSecond line of garbage."
    file = io.BytesIO(log_content.encode("utf-8"))
    
    response = client.post(
        "/analyze",
        files={"file": ("auth.log", file, "text/plain")},
        headers=HEADERS
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert response.json()["total_threats"] == 0
