"""
Shared feature engineering for ML model training and inference.

This module ensures that training (train_model.py) and inference (detector.py)
use identical feature extraction logic, preventing mismatches that would
silently degrade model performance.

Feature engineering notes:
- ip_encoded uses zlib.adler32 (32-bit space ~4B values). Collision probability
  is negligible for typical log datasets (<100K unique IPs), but this is NOT a
  cryptographic guarantee. Do not rely on uniqueness for security purposes.
- fail_ratio_per_ip is computed over the *analyzed batch*, not historical data.
  It captures IPs with a high failure rate within the current log file, which
  helps detect slow brute-force attacks that stay under per-minute thresholds.
  NOTE: This feature lacks statistical significance in very low volume logs 
  (e.g., an IP with 1 total event will have a 1.0 fail_ratio if that event failed).
  Interpret this feature with caution when counts are low.
"""
import zlib
import math
import pandas as pd
from collections import Counter


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    probabilities = [n_x / len(text) for n_x in Counter(text).values()]
    return -sum(p * math.log2(p) for p in probabilities)


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features from log DataFrame for ML model training/inference.

    Features extracted:
    - hour: Hour of day (0-23)
    - ip_encoded: Hash of IP address
    - status_val: Numeric status (SUCCESS=1, FAIL=0, INFO=0.5)
    - fail_ratio_per_ip: Ratio of FAIL events in batch
    - requests_per_minute: Request frequency in 1-min windows
    - unique_users_per_ip: Diversity of users attempted by IP
    - url_entropy: Shannon entropy of the URL/Action
    """
    features = pd.DataFrame(index=df.index)
    features['hour'] = df['datetime'].dt.hour

    # IP encoding
    features['ip_encoded'] = df['ip_origen'].apply(
        lambda x: zlib.adler32(str(x).encode()) & 0xffffffff
    )

    # Status mapping
    status_map = {'SUCCESS': 1, 'FAIL': 0, 'INFO': 0.5}
    features['status_val'] = df['status'].map(status_map).fillna(0.5)

    # Fail ratio per IP (with weighting: ignore IPs with < 5 requests to reduce noise)
    grouped_fail = df.assign(is_fail=(df['status'] == 'FAIL').astype(float)).groupby('ip_origen', sort=False)['is_fail']
    fail_ratio = grouped_fail.transform('mean')
    request_counts = grouped_fail.transform('count')
    features['fail_ratio_per_ip'] = fail_ratio.where(request_counts >= 5, 0.0)

    # NEW: Unique users per IP
    if 'usuario' in df.columns:
        features['unique_users_per_ip'] = (
            df.groupby('ip_origen')['usuario']
            .transform('nunique')
        ).fillna(0)
    else:
        features['unique_users_per_ip'] = 0

    # NEW: Requests per minute (frequency)
    # Computed per IP using a 1-minute window.
    # We use a temp column to map back to original order safely.
    df_temp = df[['ip_origen', 'datetime']].copy()
    df_temp['_sort_idx'] = range(len(df))
    df_temp = df_temp.sort_values(['ip_origen', 'datetime'])
    
    rpm_series = (
        df_temp.groupby('ip_origen', sort=False)
        .rolling('1min', on='datetime')['_sort_idx']
        .count()
        .reset_index(level=0, drop=True)
    )
    
    # Merge or align back to original order
    df_temp['rpm'] = rpm_series.values
    features['requests_per_minute'] = df_temp.sort_values('_sort_idx')['rpm'].values

    # NEW: URL Entropy
    # Combines action/URL to find unusual patterns
    if 'accion' in df.columns:
        features['url_entropy'] = df['accion'].astype(str).apply(calculate_entropy)
    else:
        features['url_entropy'] = 0.0

    # NEW: Unique URLs per IP (Signals scanning/crawling)
    if 'url' in df.columns:
        features['unique_urls_per_ip'] = (
            df.groupby('ip_origen')['url']
            .transform('nunique')
        ).fillna(0)
    else:
        features['unique_urls_per_ip'] = 0

    return features
