import pytest
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from src.detector import LogDetector, BruteForceRule, TimeAnomalyRule, UserProbingRule, IsolationForestRule

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
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
    Simulates 6 failed attempts in less than a minute to validate
    that BruteForceRule detects them correctly.
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
    
    # 2. Configure detector
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    
    # 3. Run detection
    anomalies = detector.run(df)

    # 4. Validations
    # Rule detects from 6th failed attempt in window
    assert anomalies is not None
    assert not anomalies.empty
    assert len(anomalies) >= 1
    assert "Brute Force" in anomalies.iloc[0]['reason']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_BRUTE_FORCE


def test_user_probing_detection():
    """
    Simulates 4 different users from same IP in 9 minutes to validate
    that UserProbingRule detects account probing.
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
    assert "User Probing" in anomalies.iloc[0]['reason']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_USER_PROBING
    # Rule detects from 4th different user
    assert len(anomalies) >= 1


def test_time_anomaly_detection():
    """
    Simulates successful logins outside business hours (3 AM) to validate
    that TimeAnomalyRule detects correctly.
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
    assert "Time Anomaly" in anomalies.iloc[0]['reason']
    assert anomalies.iloc[0]['ip_origen'] == TEST_IP_TIME_ANOMALY


def test_time_anomaly_no_detection_during_work_hours():
    """
    Verifies that NO anomalies are detected during business hours.
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

    # Should not detect anomalies during business hours
    assert anomalies is not None
    assert anomalies.empty


def test_ia_detector_with_synthetic_anomalies():
    """
    Tests IsolationForestRule with a model trained inline on clearly normal data.
    then presented with clearly anomalous data.

    Uses a high contamination value (0.3) so the Isolation Forest is tuned to
    flag the top 30% most anomalous points — guaranteeing detections in a
    small, controlled dataset where the anomalous cluster is distinct.
    """
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        pytest.skip("scikit-learn not installed")

    # --- Build a clearly normal training dataset (business hours, SUCCESS) ---
    rng = np.random.default_rng(42)
    n_normal = 200
    normal_data = pd.DataFrame({
        'datetime': [
            datetime(2026, 10, 11, int(h), 0, 0)
            for h in rng.integers(8, 18, n_normal)
        ],
        'ip_origen': [f"192.0.2.{i % 50 + 1}" for i in range(n_normal)],
        'status': ['SUCCESS'] * n_normal,
    })

    from src.features import extract_features
    X_train = extract_features(normal_data)

    # Train with contamination=0.3 so that the 15 anomalous rows below
    # (all 3AM FAILs from a single IP) are reliably flagged
    model = IsolationForest(contamination=0.3, random_state=42)
    model.fit(X_train)

    # --- Build a clearly anomalous test dataset (3 AM, all FAILs, same IP) ---
    base_time = datetime(2026, 10, 11, 3, 0, 0)  # 3 AM — outside normal hours
    df_anomalous = _create_log_entries(
        base_time=base_time,
        count=15,
        ip="192.0.50.200",   # IP not seen in training
        user='root',
        action='Failed password',
        status='FAIL',
        interval_seconds=60,
    )

    rule = IsolationForestRule(model=model)
    anomalies = rule.evaluate(df_anomalous)

    # With contamination=0.3 and a clearly distinct anomalous cluster,
    # the model MUST flag at least one row
    assert isinstance(anomalies, pd.DataFrame)
    assert not anomalies.empty, (
        "IsolationForestRule should detect anomalies in clearly anomalous data "
        "(3AM FAILs from unseen IP against a normal-hours SUCCESS model)"
    )


def test_ia_detector_empty_data():
    """
    Verifies that IsolationForestRule correctly handles empty DataFrames.
    """
    df = pd.DataFrame()
    rule = IsolationForestRule()

    anomalies = rule.evaluate(df)

    assert anomalies is not None
    assert anomalies.empty


def test_ia_detector_insufficient_data():
    """
    Verifies that IsolationForestRule requires sufficient data (>5 records).
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
    rule = IsolationForestRule()

    anomalies = rule.evaluate(df)

    # Should return empty due to insufficient data
    assert anomalies is not None
    assert anomalies.empty


def test_logdetector_groupby_with_none_usuario_accion():
    """
    Regression test: LogDetector.run() must correctly group and deduplicate
    anomalies from web logs where 'usuario' and 'accion' are None.

    Web logs (Nginx/Apache) for unauthenticated requests have usuario=None and
    accion=None. The groupby in run() uses dropna=False so that None values are
    treated as a valid group key rather than being silently dropped.

    Without dropna=False, anomalous web-log rows with None in these columns
    would be discarded by the groupby, causing missed detections.
    """
    base_time = datetime(2026, 10, 11, 3, 0, 0)  # 3 AM — triggers TimeAnomalyRule too

    # Simulate web log rows: usuario=None, accion=None (typical for Nginx access logs)
    rows = []
    for i in range(3):
        rows.append({
            'timestamp': (base_time + timedelta(minutes=i)).strftime('%b %d %H:%M:%S'),
            'datetime': base_time + timedelta(minutes=i),
            'ip_origen': '192.0.2.100',
            'usuario': None,       # No authenticated user (web log)
            'accion': None,        # No action string (web log)
            'status': 'SUCCESS',   # HTTP 200 at 3 AM
            'url': '/admin',
        })
    df_web = pd.DataFrame(rows)

    detector = LogDetector()
    detector.add_rule(TimeAnomalyRule(start_hour=8, end_hour=18))
    result = detector.run(df_web)

    # The 3 anomalous rows should survive the groupby deduplication
    assert not result.empty, (
        "Web log anomalies with usuario=None/accion=None must NOT be dropped by groupby"
    )
    # All detected rows had the same IP
    assert (result['ip_origen'] == '192.0.2.100').all()
    # Reason must be set (not None/NaN)
    assert result['reason'].notna().all()
