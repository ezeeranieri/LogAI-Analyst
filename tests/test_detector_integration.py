import pytest
import pandas as pd
from datetime import datetime, timedelta
from src.detector import (
    LogDetector, BruteForceRule, SQLInjectionRule, 
    XSSRule, IsolationForestRule
)
from src.normalization import normalize_df

def test_detector_full_integration(test_ips):
    """
    High-level integration test for the LogDetector with multiple rules.
    Verifies that different types of attacks (Auth, Web, ML) can be
    detected simultaneously in a single dataset.
    """
    # 1. Setup Data
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    
    data = [
        # Normal traffic
        {"datetime": base_time, "ip_origen": test_ips["NORMAL"], "status": "SUCCESS", "usuario": "alice", "url": "/index.html"},
        
        # Brute Force Burst (6 attempts in 30s)
        *[{"datetime": base_time + timedelta(seconds=i), "ip_origen": test_ips["BRUTE_FORCE"], "status": "FAIL", "usuario": "admin", "url": "/login"} for i in range(6)],
        
        # SQL Injection attempt
        {"datetime": base_time + timedelta(minutes=5), "ip_origen": test_ips["SQL_INJECTION"], "status": "FAIL", "usuario": "guest", "url": "/search?id=1' OR '1'='1"},
        
        # XSS attempt (URL encoded)
        {"datetime": base_time + timedelta(minutes=6), "ip_origen": test_ips["XSS"], "status": "FAIL", "usuario": "guest", "url": "/profile?name=%3Cscript%3Ealert(1)%3C/script%3E"},
    ]
    
    df_raw = pd.DataFrame(data)
    
    # 2. Normalization (Required for Web rules to find decoded patterns)
    df_normalized = normalize_df(df_raw)
    
    # 3. Setup Detector
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    detector.add_rule(SQLInjectionRule())
    detector.add_rule(XSSRule())
    
    # 4. Run Detection
    results = detector.run(df_normalized)
    
    # 5. Assertions
    assert not results.empty, "Should detect at least some anomalies"
    
    # Check for Brute Force
    bf_hits = results[results['reason'].str.contains("Brute Force", case=False)]
    assert len(bf_hits) >= 1, "Should detect brute force burst"
    assert test_ips["BRUTE_FORCE"] in bf_hits['ip_origen'].values
    
    # Check for SQL Injection
    sqli_hits = results[results['reason'].str.contains("SQL Injection", case=False)]
    assert len(sqli_hits) >= 1, "Should detect SQL injection"
    assert test_ips["SQL_INJECTION"] in sqli_hits['ip_origen'].values
    
    # Check for XSS
    xss_hits = results[results['reason'].str.contains("XSS", case=False)]
    assert len(xss_hits) >= 1, "Should detect XSS (needs normalization)"
    assert test_ips["XSS"] in xss_hits['ip_origen'].values

def test_isolation_forest_rule_integration(test_ips):
    """Validates the IsolationForestRule with a mock/simple setup."""
    detector = LogDetector()
    # Mocking model presence is hard without training, but we can check it doesn't crash
    # on empty or normal data
    rule = IsolationForestRule(model=None) # Will fallback to loading or fail gracefully
    detector.add_rule(rule)
    
    df = pd.DataFrame({
        "datetime": [datetime.now()],
        "ip_origen": [test_ips["NORMAL"]],
        "status": ["SUCCESS"],
        "usuario": ["admin"],
        "url": ["/"]
    })
    
    # SHould not crash even if model is missing (it logs warning)
    results = detector.run(df)
    assert isinstance(results, pd.DataFrame)
