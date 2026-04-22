import pytest
import io
from fastapi.testclient import TestClient
from main import app
from src.config import API_KEY

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
TEST_IP = "192.0.2.1"

client = TestClient(app)
HEADERS = {"X-API-KEY": API_KEY}
BAD_HEADERS = {"X-API-KEY": "wrong-key-000"}


# ---------------------------------------------------------------------------
# /analyze endpoint tests
# ---------------------------------------------------------------------------

def test_analyze_upload_no_key():
    """
    Verifies that API rejects requests without API Key (403).
    """
    file = io.BytesIO(b"content")
    response = client.post("/analyze", files={"file": ("auth.log", file)})
    assert response.status_code == 403


def test_analyze_upload_success():
    """
    Tests the upload flow of a valid file with correct API Key.
    """
    # Generate 6 failures to trigger Brute Force rule
    log_content = "\n".join([
        f"Oct 11 10:00:00 server sshd[123]: Failed password for root from {TEST_IP}" 
        for _ in range(6)
    ])
    
    file = io.BytesIO(log_content.encode("utf-8"))
    
    response = client.post(
        "/analyze",
        files={"file": ("auth.log", file, "text/plain")},
        headers=HEADERS
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_threats"] > 0


def test_analyze_upload_invalid_extension():
    """
    Verifies that files with disallowed extensions are rejected (.exe).
    """
    file = io.BytesIO(b"malicious content")
    
    response = client.post(
        "/analyze",
        files={"file": ("virus.exe", file)},
        headers=HEADERS
    )
    
    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


def test_analyze_upload_no_extension():
    """
    Verifies that files without extension are accepted (with API Key).
    """
    log_content = "Oct 11 10:00:00 server sshd[123]: session opened for user root"
    file = io.BytesIO(log_content.encode("utf-8"))
    
    response = client.post(
        "/analyze",
        files={"file": ("auth", file)},
        headers=HEADERS
    )
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"


# ---------------------------------------------------------------------------
# /export endpoint tests
# ---------------------------------------------------------------------------

SAMPLE_THREAT_DATA = [
    {
        "datetime": "2026-10-11 03:00:00",
        "ip_origen": TEST_IP,
        "usuario": "root",
        "accion": "Failed password for root",
        "status": "FAIL",
        "reason": "Brute Force: 6+ failed logins in 1 min",
    }
]


def test_export_no_api_key():
    """
    /export must reject requests without a valid API Key (403).
    """
    response = client.post(
        "/export",
        json={"data": SAMPLE_THREAT_DATA, "format": "json"},
    )
    assert response.status_code == 403


def test_export_wrong_api_key():
    """
    /export must reject requests with an incorrect API Key (403).
    """
    response = client.post(
        "/export",
        json={"data": SAMPLE_THREAT_DATA, "format": "json"},
        headers=BAD_HEADERS,
    )
    assert response.status_code == 403


def test_export_invalid_format():
    """
    /export must return 400 for unsupported format values.
    """
    response = client.post(
        "/export",
        json={"data": SAMPLE_THREAT_DATA, "format": "xml"},
        headers=HEADERS,
    )
    assert response.status_code == 400
    assert "Invalid format" in response.json()["detail"]


def test_export_empty_data():
    """
    /export must return 400 when data list is empty.
    """
    response = client.post(
        "/export",
        json={"data": [], "format": "json"},
        headers=HEADERS,
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_export_json_happy_path():
    """
    /export must return 200 with file metadata for a valid JSON export.
    """
    response = client.post(
        "/export",
        json={"data": SAMPLE_THREAT_DATA, "format": "json"},
        headers=HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert "file_path" in body
    assert body["file_info"]["size_bytes"] > 0


def test_export_csv_happy_path():
    """
    /export must return 200 with file metadata for a valid CSV export.
    """
    response = client.post(
        "/export",
        json={"data": SAMPLE_THREAT_DATA, "format": "csv"},
        headers=HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["file_info"]["filename"].endswith(".csv")


def test_export_custom_filename():
    """
    /export must use the provided filename when specified.
    """
    response = client.post(
        "/export",
        json={
            "data": SAMPLE_THREAT_DATA,
            "format": "json",
            "filename": "my_report",
        },
        headers=HEADERS,
    )
    assert response.status_code == 200
    body = response.json()
    assert "my_report" in body["file_info"]["filename"]
