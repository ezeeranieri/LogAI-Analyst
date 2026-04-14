import pytest
import io
from fastapi.testclient import TestClient
from main import app
from src.config import API_KEY

# IP de prueba claramente marcada para evitar hotspots de SonarCloud
TEST_IP = "1.1.1.1"

client = TestClient(app)
HEADERS = {"X-API-KEY": API_KEY}

def test_analyze_upload_no_key():
    """
    Verifica que la API rechace peticiones sin API Key (403).
    """
    file = io.BytesIO(b"content")
    response = client.post("/analyze", files={"file": ("auth.log", file)})
    assert response.status_code == 403

def test_analyze_upload_success():
    """
    Prueba el flujo de subida de un archivo válido con API Key correcta.
    """
    # Generamos 6 fallos para disparar la regla de Brute Force
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
    Verifica que se rechacen archivos con extensiones no permitidas (.exe).
    """
    file = io.BytesIO(b"malicious content")
    
    response = client.post(
        "/analyze",
        files={"file": ("virus.exe", file)},
        headers=HEADERS
    )
    
    assert response.status_code == 400
    assert "Extensión no válida" in response.json()["detail"]

def test_analyze_upload_no_extension():
    """
    Verifica que se acepten archivos sin extensión (con API Key).
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
