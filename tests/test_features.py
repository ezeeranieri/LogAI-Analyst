"""Tests for shared feature engineering module."""
import pytest
import pandas as pd
from datetime import datetime
from src.features import extract_features

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
TEST_IP_1 = "192.0.2.1"
TEST_IP_2 = "192.0.2.2"


def test_extract_features_produces_expected_columns():
    """
    Verifies that extract_features produces the 4 expected columns:
    hour, ip_encoded, status_val, fail_ratio_per_ip
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 14, 30, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['SUCCESS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    expected_cols = [
        'hour', 'ip_encoded', 'status_val', 'fail_ratio_per_ip',
        'requests_per_minute', 'unique_users_per_ip', 'url_entropy',
        'unique_urls_per_ip'
    ]
    assert sorted(list(features.columns)) == sorted(expected_cols)
    assert len(features) == 1


def test_extract_features_hour_extraction():
    """
    Verifies that hour is correctly extracted from datetime.
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

    # Call twice with same data
    features1 = extract_features(df)
    features2 = extract_features(df)

    # Hash should be identical
    assert features1['ip_encoded'].iloc[0] == features2['ip_encoded'].iloc[0]


def test_extract_features_different_ips_produce_different_hashes():
    """
    Verifies that different IPs produce different hashes.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0), datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1, TEST_IP_2],
        'status': ['SUCCESS', 'SUCCESS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    # Different IPs should have different hashes
    assert features['ip_encoded'].iloc[0] != features['ip_encoded'].iloc[1]


def test_extract_features_status_mapping():
    """
    Verifies that status mapping is correct:
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

    assert features['status_val'].iloc[0] == pytest.approx(1.0)
    assert features['status_val'].iloc[1] == pytest.approx(0.0)
    assert features['status_val'].iloc[2] == pytest.approx(0.5)


def test_extract_features_unknown_status_defaults():
    """
    Verifies that unknown statuses use the default of 0.5.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['UNKNOWN_STATUS']
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    assert features['status_val'].iloc[0] == pytest.approx(0.5)


def test_extract_features_preserves_index():
    """
    Verifies that the original DataFrame index is preserved.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)],
        'ip_origen': [TEST_IP_1],
        'status': ['SUCCESS']
    }
    df = pd.DataFrame(data, index=[42])

    features = extract_features(df)

    assert features.index[0] == 42


def test_extract_features_fail_ratio_per_ip():
    """
    Verifies that fail_ratio_per_ip is correctly calculated as the ratio
    of FAIL statuses for each IP in the batch.
    """
    data = {
        'datetime': [datetime(2026, 10, 11, 10, 0, 0)] * 10,
        'ip_origen': [TEST_IP_1] * 5 + [TEST_IP_2] * 5,
        'status': [
            'SUCCESS', 'FAIL', 'SUCCESS', 'FAIL', 'SUCCESS',    # IP_1: 2 fails / 5 events = 0.4
            'FAIL', 'FAIL', 'FAIL', 'FAIL', 'SUCCESS'          # IP_2: 4 fails / 5 events = 0.8
        ]
    }
    df = pd.DataFrame(data)

    features = extract_features(df)

    # IP_1 ratio: 2 fail / 5 events = 0.4
    assert features['fail_ratio_per_ip'].iloc[0] == pytest.approx(0.4)
    # IP_2 ratio: 4 fail / 5 events = 0.8
    assert features['fail_ratio_per_ip'].iloc[5] == pytest.approx(0.8)
