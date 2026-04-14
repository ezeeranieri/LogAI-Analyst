import pytest
import pandas as pd
from src.parser import AuthLogParser

# IPs de prueba — RFC 5737 (192.0.2.x) rango reservado por IANA para documentación y tests
TEST_IP_FAIL = "192.0.2.1"
TEST_IP_SUCCESS = "192.0.2.2"

def test_parse_single_line_failed(tmp_path):
    """
    Valida que una línea de fallo de autenticación se parsee
    correctamente con el status FAIL y extracción de usuario/IP.
    Utiliza el fixture tmp_path para gestión segura de archivos temporales.
    """
    d = tmp_path / "subdir"
    d.mkdir()
    log_file = d / "test_auth.log"
    line = f"Oct 11 10:00:00 server sshd[123]: Failed password for root from {TEST_IP_FAIL}"
    log_file.write_text(line)
        
    parser = AuthLogParser(str(log_file))
    df = parser.parse()
    
    assert not df.empty
    assert df.iloc[0]['status'] == "FAIL"
    assert df.iloc[0]['usuario'] == "root"
    assert df.iloc[0]['ip_origen'] == TEST_IP_FAIL
    assert 'datetime' in df.columns

def test_parse_success_line(tmp_path):
    """
    Valida la normalización a SUCCESS de un acceso aceptado usando tmp_path.
    """
    log_file = tmp_path / "test_success.log"
    line = f"Oct 11 12:00:00 server sshd[456]: Accepted password for admin from {TEST_IP_SUCCESS}"
    log_file.write_text(line)
        
    parser = AuthLogParser(str(log_file))
    df = parser.parse()
    
    assert df.iloc[0]['status'] == "SUCCESS"
    assert df.iloc[0]['usuario'] == "admin"
