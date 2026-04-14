import pytest
import pandas as pd
from datetime import datetime, timedelta
from src.detector import LogDetector, BruteForceRule, UserProbingRule

# IPs de prueba — RFC 5737 (192.0.2.x) rango reservado por IANA para documentación y tests
TEST_IP_BRUTE_FORCE = "192.0.2.1"
TEST_IP_USER_PROBING = "192.0.2.2"

def test_brute_force_detection():
    """
    Simula 6 intentos fallidos en menos de un minuto para validar
    que la regla de BruteForceRule los detecta correctamente.
    """
    # 1. Crear datos sintéticos
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    data = []
    
    # Generamos 6 fallos en intervalos de 5 segundos (total 25 segundos < 1 min)
    for i in range(6):
        data.append({
            'timestamp': (base_time + timedelta(seconds=i*5)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(seconds=i*5),
            'ip_origen': TEST_IP_BRUTE_FORCE,
            'usuario': 'root',
            'accion': 'Failed password for root',
            'status': 'FAIL'
        })
        
    df = pd.DataFrame(data)
    
    # 2. Configurar detector
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    
    # 3. Ejecutar detección
    anomalies = detector.run(df)
    
    # 4. Validaciones
    # La regla detecta a partir del 6to intento fallido en la ventana
    assert not anomalies.empty
    assert len(anomalies) >= 1
    assert "Fuerza Bruta" in anomalies.iloc[0]['razon']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_BRUTE_FORCE


def test_user_probing_detection():
    """
    Simula 4 usuarios distintos desde la misma IP en 9 minutos para validar
    que UserProbingRule detecta el sondeo de cuentas.
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    data = []
    
    # 4 usuarios distintos en intervalos de 2 minutos (total 6 minutos < 10 min)
    users = ["admin", "root", "dev", "guest"]
    for i, user in enumerate(users):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i*2)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i*2),
            'ip_origen': TEST_IP_USER_PROBING,
            'usuario': user,
            'accion': f'Failed login for {user}',
            'status': 'FAIL'
        })
        
    df = pd.DataFrame(data)
    detector = LogDetector()
    detector.add_rule(UserProbingRule())
    
    anomalies = detector.run(df)
    
    assert not anomalies.empty
    assert "Sondeo de Usuarios" in anomalies.iloc[0]['razon']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_USER_PROBING
    # La regla detecta a partir del 4to usuario distinto
    assert len(anomalies) >= 1
