import pytest
import io
from fastapi.testclient import TestClient
from main import app
from src.config import API_KEY

# IPs de prueba claramente marcadas para evitar hotspots de SonarCloud
TEST_IP_1 = "1.1.1.1"
TEST_IP_2 = "1.1.1.2"

client = TestClient(app)
HEADERS = {"X-API-KEY": API_KEY}

def test_analyze_unparsable_timestamps():
    """
    Verifica que la API NO devuelva un 500 al recibir logs con timestamps corruptos.
    Debería ignorar los registros malformados y procesar el resto o devolver éxito vacío.
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
    
    # No debe dar 500
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    # El primer registro es inválido y se dropea. El segundo es válido pero no dispara reglas solo.
    # Así que total_threats debería ser 0 o mayor si hay reglas que disparen con 1 fila.
    # Lo importante es que NO sea un 500.
    assert "total_threats" in data

def test_analyze_completely_corrupt_file():
    """
    Verifica archivo completamente basura.
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
