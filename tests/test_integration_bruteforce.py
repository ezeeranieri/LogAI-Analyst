"""
Integration test: Simulates a real brute force attack
and verifies the API detects it correctly.

This test demonstrates the complete flow:
1. Generate fake log with multiple failed attempts from same IP
2. Upload to /analyze endpoint
3. Verify HTTP 200 and BruteForce detection
"""
import pytest
import io
from fastapi.testclient import TestClient
from main import app
from src.config import API_KEY

client = TestClient(app)
HEADERS = {"X-API-KEY": API_KEY}

# Reserved test IP (RFC 5737)
ATTACKER_IP = "192.0.2.100"
TARGET_USER = "admin"

def generate_brute_force_log(attempts: int = 10, ip: str = ATTACKER_IP, user: str = TARGET_USER) -> str:
    """Generates an auth.log simulating brute force attack."""
    lines = []
    base_time = "Oct 15 14:30:{:02d}"
    
    for i in range(attempts):
        timestamp = base_time.format(i)
        line = f"{timestamp} server sshd[{1000 + i}]: Failed password for {user} from {ip} port {2200 + i} ssh2"
        lines.append(line)
    
    return "\n".join(lines)


def test_brute_force_detection():
    """
    E2E Test: Upload brute force log → Verify detection.
    
    Scenario: Attacker attempts 10 failed logins in 1 minute from same IP.
    Expected: API should detect as BruteForce and return 200.
    """
    # 1. Generate log with 10 failed attempts (typical threshold: 5+)
    log_content = generate_brute_force_log(attempts=10)
    file = io.BytesIO(log_content.encode("utf-8"))
    
    # 2. Upload to API
    response = client.post(
        "/analyze",
        files={"file": ("auth.log", file, "text/plain")},
        headers=HEADERS
    )
    
    # 3. Verifications
    assert response.status_code == 200, f"Expected 200, got {response.status_code}: {response.text}"
    
    data = response.json()
    assert data["status"] == "success"
    assert data["total_threats"] > 0, "Should detect at least 1 threat"
    
    # 4. Verify it specifically detected BruteForce for the correct reason
    threats = data["data"]
    
    # Check threat has brute force reason
    brute_force_by_reason = any(
        "brute force" in str(threat.get("reason", "")).lower()
        for threat in threats
    )
    
    assert brute_force_by_reason, (
        f"Brute force not detected by reason. "
        f"Threats found: {threats}"
    )
    
    # 5. Verify attacker IP is in results
    detected_ips = {t.get("ip_origen") for t in threats if t.get("ip_origen")}
    assert ATTACKER_IP in detected_ips, f"Attacker IP {ATTACKER_IP} not found in detections: {detected_ips}"


def test_brute_force_below_threshold():
    """
    Negative test: 2 failed attempts should NOT trigger alert.
    """
    log_content = generate_brute_force_log(attempts=2)
    file = io.BytesIO(log_content.encode("utf-8"))
    
    response = client.post(
        "/analyze",
        files={"file": ("auth.log", file, "text/plain")},
        headers=HEADERS
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # With only 2 attempts, there should be no brute force detection
    # (though there could be other detections like UserProbing if applicable)
    brute_force_threats = [
        t for t in data["data"]
        if "brute force" in str(t.get("reason", "")).lower()
    ]
    
    assert len(brute_force_threats) == 0, f"Should not detect brute force with only 2 attempts: {brute_force_threats}"
