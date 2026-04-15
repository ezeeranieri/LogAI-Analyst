import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from src.detector import LogDetector, BruteForceRule, TimeAnomalyRule, UserProbingRule, IADetectorRule

# IPs de prueba — RFC 5737 (192.0.2.x) rango reservado por IANA para documentación y tests
TEST_IP_BRUTE_FORCE = "192.0.2.1"
TEST_IP_USER_PROBING = "192.0.2.2"
TEST_IP_TIME_ANOMALY = "192.0.2.3"


def _create_log_entries(base_time: datetime, count: int, ip: str, user: str,
                        action: str, status: str, interval_seconds: int = 5) -> pd.DataFrame:
    """Helper function to create log entries for testing."""
    data = []
    for i in range(count):
        data.append({
            'timestamp': (base_time + timedelta(seconds=i*interval_seconds)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(seconds=i*interval_seconds),
            'ip_origen': ip,
            'usuario': user,
            'accion': action,
            'status': status
        })
    return pd.DataFrame(data)


def _create_log_entries_with_interval(base_time: datetime, count: int, ip: str, users: list,
                                       action_template: str, status: str, interval_minutes: int = 2) -> pd.DataFrame:
    """Helper function to create log entries with varying users and minute intervals."""
    data = []
    for i, user in enumerate(users):
        data.append({
            'timestamp': (base_time + timedelta(minutes=i*interval_minutes)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i*interval_minutes),
            'ip_origen': ip,
            'usuario': user,
            'accion': action_template.format(user=user),
            'status': status
        })
    return pd.DataFrame(data)

def test_brute_force_detection():
    """
    Simula 6 intentos fallidos en menos de un minuto para validar
    que la regla de BruteForceRule los detecta correctamente.
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    df = _create_log_entries(
        base_time=base_time,
        count=6,
        ip=TEST_IP_BRUTE_FORCE,
        user='root',
        action='Failed password for root',
        status='FAIL',
        interval_seconds=5
    )
    
    # 2. Configurar detector
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    
    # 3. Ejecutar detección
    anomalies = detector.run(df)

    # 4. Validaciones
    # La regla detecta a partir del 6to intento fallido en la ventana
    assert anomalies is not None
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
    users = ["admin", "root", "dev", "guest"]
    df = _create_log_entries_with_interval(
        base_time=base_time,
        count=4,
        ip=TEST_IP_USER_PROBING,
        users=users,
        action_template='Failed login for {user}',
        status='FAIL',
        interval_minutes=2
    )
    detector = LogDetector()
    detector.add_rule(UserProbingRule())
    
    anomalies = detector.run(df)

    assert anomalies is not None
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
    base_time = datetime(2026, 10, 11, 3, 0, 0)
    df = _create_log_entries(
        base_time=base_time,
        count=3,
        ip=TEST_IP_TIME_ANOMALY,
        user='admin',
        action='session opened for user admin',
        status='SUCCESS',
        interval_seconds=600  # 10 minutes
    )
    rule = TimeAnomalyRule(start_hour=8, end_hour=18)

    anomalies = rule.evaluate(df)

    assert anomalies is not None
    assert not anomalies.empty
    assert "Anomalía de Horario" in anomalies.iloc[0]['razon']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_TIME_ANOMALY


def test_time_anomaly_no_detection_during_work_hours():
    """
    Verifica que NO se detectan anomalías durante horario laboral.
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    df = _create_log_entries(
        base_time=base_time,
        count=3,
        ip=TEST_IP_TIME_ANOMALY,
        user='admin',
        action='session opened for user admin',
        status='SUCCESS',
        interval_seconds=600  # 10 minutes
    )
    rule = TimeAnomalyRule(start_hour=8, end_hour=18)

    anomalies = rule.evaluate(df)

    # No debería detectar anomalías durante horario laboral
    assert anomalies is not None
    assert anomalies.empty


def test_ia_detector_with_synthetic_anomalies():
    """
    Prueba IADetectorRule con datos que deberían ser anómalos
    (horarios raros + IPs inusuales + muchos fallos).
    """
    base_time = datetime(2026, 10, 11, 2, 0, 0)
    df = _create_log_entries(
        base_time=base_time,
        count=15,
        ip="192.0.2.200",
        user='root',
        action='Failed password',
        status='FAIL',
        interval_seconds=60  # 1 minute
    )
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

    assert anomalies is not None
    assert anomalies.empty


def test_ia_detector_insufficient_data():
    """
    Verifica que IADetectorRule requiere suficientes datos (>5 registros).
    """
    base_time = datetime(2026, 10, 11, 10, 0, 0)
    df = _create_log_entries(
        base_time=base_time,
        count=3,
        ip="192.0.2.1",
        user='root',
        action='Failed password',
        status='FAIL',
        interval_seconds=60  # 1 minute
    )
    rule = IADetectorRule()

    anomalies = rule.evaluate(df)

    # Debería devolver vacío por insuficientes datos
    assert anomalies is not None
    assert anomalies.empty
