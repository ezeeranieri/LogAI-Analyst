"""Tests for shared feature engineering module."""
import pytest
import pandas as pd
from datetime import datetime
from src.features import extract_features

# IPs de prueba — RFC 5737 (192.0.2.x) rango reservado por IANA para documentación y tests
TEST_IP_1 = "192.0.2.1"
TEST_IP_2 = "192.0.2.2"


def test_extract_features_produces_expected_columns():
    """
    Verifica que extract_features produce las 3 columnas esperadas:
    hour, ip_encoded, status_val
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 14, 30, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['SUCCESS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    assert list(features.columns) == ['hour', 'ip_encoded', 'status_val']
    assert len(features) == 1


def test_extract_features_hour_extraction():
    """
    Verifica que la hora se extrae correctamente del datetime.
    """
    data = {
        'datetime': [
            datetime(2026, 10, 11, 0, 0, 0),   # midnight
            datetime(2026, 10, 11, 12, 30, 0),  # noon
            datetime(2026, 10, 11, 23, 59, 0),  # almost midnight
        ],
        'ip_origen': [TEST_IP_1, TEST_IP_1, TEST_IP_1],
        'status': ['SUCCESS', 'FAIL', 'INFO']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    assert features['hour'].iloc[0] == 0
    assert features['hour'].iloc[1] == 12
    assert features['hour'].iloc[2] == 23


def test_extract_features_ip_hash_deterministic():
    """
    Verifica que el hash de IP es determinístico entre llamadas.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['SUCCESS']
    }
    df = pd.DataFrame(data)

    # Llamar dos veces con los mismos datos
    features1 = extract_features(df)
    features2 = extract_features(df)

    # El hash debe ser idéntico
    assert features1['ip_encoded'].iloc[0] == features2['ip_encoded'].iloc[0]


def test_extract_features_different_ips_produce_different_hashes():
    """
    Verifica que diferentes IPs producen diferentes hashes.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0), datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1, TEST_IP_2],
        'status': ['SUCCESS', 'SUCCESS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    # Diferentes IPs deben tener diferentes hashes
    assert features['ip_encoded'].iloc[0] != features['ip_encoded'].iloc[1]


def test_extract_features_status_mapping():
    """
    Verifica que el mapeo de status es correcto:
    SUCCESS=1, FAIL=0, INFO=0.5
    """
    data = {
        'datetime': [
            datetime(2026, 10, 11, 10, 0, 0),
            datetime(2026, 10, 11, 10, 1, 0),
            datetime(2026, 10, 11, 10, 2, 0),
        ],
        'ip_origen': [TEST_IP_1, TEST_IP_1, TEST_IP_1],
        'status': ['SUCCESS', 'FAIL', 'INFO']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    assert features['status_val'].iloc[0] == 1.0
    assert features['status_val'].iloc[1] == 0.0
    assert features['status_val'].iloc[2] == 0.5


def test_extract_features_unknown_status_defaults():
    """
    Verifica que status desconocidos usan el default de 0.5.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['UNKNOWN_STATUS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    assert features['status_val'].iloc[0] == 0.5


def test_extract_features_preserves_index():
    """
    Verifica que el índice del DataFrame original se preserva.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['SUCCESS']
    }
    df = pd.DataFrame(data, index=[42])

    features = extract_features(df)

    assert features.index[0] == 42
