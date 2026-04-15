import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from src.detector import LogDetector, BruteForceRule, TimeAnomalyRule, UserProbingRule, IADetectorRule

# IPs de prueba — RFC 5737 (192.0.2.x) rango reservado por IANA para documentación y tests
TEST_IP_BRUTE_FORCE = "192.0.2.1"
TEST_IP_USER_PROBING = "192.0.2.2"
TEST_IP_TIME_ANOMALY = "192.0.2.3"

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


def test_time_anomaly_detection():
    """
    Simula accesos exitosos fuera del horario laboral (3 AM) para validar
    que TimeAnomalyRule detecta correctamente.
    """
    base_time = datetime(2026, 10, 11, 3, 0, 0)  # 3 AM - fuera de horario
    data = []

    # 3 accesos exitosos a las 3 AM (fuera de 8-18)
    for i in range(3):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i*10)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i*10),
            'ip_origen': TEST_IP_TIME_ANOMALY,
            'usuario': 'admin',
            'accion': 'session opened for user admin',
            'status': 'SUCCESS'
        })

    df = pd.DataFrame(data)
    rule = TimeAnomalyRule(start_hour=8, end_hour=18)

    anomalies = rule.evaluate(df)

    assert not anomalies.empty
    assert "Anomalía de Horario" in anomalies.iloc[0]['razon']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_TIME_ANOMALY


def test_time_anomaly_no_detection_during_work_hours():
    """
    Verifica que NO se detectan anomalías durante horario laboral.
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)  # 10 AM - dentro de horario
    data = []

    # Accesos exitosos durante horario laboral
    for i in range(3):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i*10)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i*10),
            'ip_origen': TEST_IP_TIME_ANOMALY,
            'usuario': 'admin',
            'accion': 'session opened for user admin',
            'status': 'SUCCESS'
        })

    df = pd.DataFrame(data)
    rule = TimeAnomalyRule(start_hour=8, end_hour=18)

    anomalies = rule.evaluate(df)

    # No debería detectar anomalías durante horario laboral
    assert anomalies.empty


def test_ia_detector_with_synthetic_anomalies():
    """
    Prueba IADetectorRule con datos que deberían ser anómalos
    (horarios raros + IPs inusuales + muchos fallos).
    """
    # Generar datos anómalos
    base_time = datetime(2026, 10, 11, 2, 0, 0)  # 2 AM
    data = []

    # 15 registros anómalos: hora rara, IP rara, status FAIL
    for i in range(15):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i),
            'ip_origen': "192.0.2.200",  # IP rara
            'usuario': 'root',
            'accion': 'Failed password',
            'status': 'FAIL'
        })

    df = pd.DataFrame(data)
    rule = IADetectorRule()

    # El modelo debería detectar algunas anomalías
    # (sin modelo entrenado, puede no detectar nada)
    anomalies = rule.evaluate(df)

    # Solo validamos que no crashea; la detección depende del modelo
    assert isinstance(anomalies, pd.DataFrame)


def test_ia_detector_empty_data():
    """
    Verifica que IADetectorRule maneja correctamente DataFrames vacíos.
    """
    df = pd.DataFrame()
    rule = IADetectorRule()

    anomalies = rule.evaluate(df)

    assert anomalies.empty


def test_ia_detector_insufficient_data():
    """
    Verifica que IADetectorRule requiere suficientes datos (>5 registros).
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    data = []

    # Solo 3 registros (menos del umbral de 5)
    for i in range(3):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i),
            'ip_origen': "192.0.2.1",
            'usuario': 'root',
            'accion': 'Failed password',
            'status': 'FAIL'
        })

    df = pd.DataFrame(data)
    rule = IADetectorRule()

    anomalies = rule.evaluate(df)

    # Debería devolver vacío por insuficientes datos
    assert anomalies.empty
