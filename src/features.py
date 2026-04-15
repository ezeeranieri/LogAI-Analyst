"""
Shared feature engineering for ML model training and inference.

This module ensures that training (train_model.py) and inference (detector.py)
use identical feature extraction logic, preventing mismatches that would
silently degrade model performance.
"""
import zlib
import pandas as pd


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract features from log DataFrame for ML model training/inference.

    Features extracted:
    - hour: Hour of day (0-23) from datetime
    - ip_encoded: Deterministic hash of IP address using zlib.adler32
    - status_val: Numeric encoding of status (SUCCESS=1, FAIL=0, INFO=0.5)

    Args:
        df: DataFrame with columns 'datetime', 'ip_origen', 'status'

    Returns:
        DataFrame with extracted features
    """
    features = pd.DataFrame(index=df.index)
    features['hour'] = df['datetime'].dt.hour

    # Hashing determinístico para IPs (evita dependencia del orden de entrada de LabelEncoder)
    features['ip_encoded'] = df['ip_origen'].apply(
        lambda x: zlib.adler32(str(x).encode()) & 0xffffffff
    )

    # Mapeo numérico del status para el modelo
    status_map = {'SUCCESS': 1, 'FAIL': 0, 'INFO': 0.5}
    features['status_val'] = df['status'].map(status_map).fillna(0.5)

    return features
