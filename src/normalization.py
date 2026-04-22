import pandas as pd
from urllib.parse import unquote_plus
import logging

logger = logging.getLogger(__name__)

def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Centralized normalization step for the log analysis pipeline.
    
    WARNING: Operates IN-PLACE on the provided DataFrame for memory optimization.
    
    Operations:
    - Decodes URLs in the 'url' column (unquote_plus) to catch obfuscated attacks.
    - Standardizes column types and fills missing values.
    
    This ensures all detection rules work on consistent, pre-processed data.
    """
    if df.empty:
        return df

    # 1. URL Decoding (Centralized)
    if 'url' in df.columns:
        # Fill NaN with empty string to avoid float issues in unquote_plus
        df['url_decoded'] = df['url'].fillna("").astype(str).apply(unquote_plus)
    else:
        # For non-web logs, ensure the column exists as empty to avoid Rule crashes
        df['url_decoded'] = ""
        
    # 2. Basic cleanup
    if 'usuario' in df.columns:
        df['usuario'] = df['usuario'].fillna("-")
        
    if 'ip_origen' in df.columns:
        df['ip_origen'] = df['ip_origen'].fillna("0.0.0.0")

    logger.debug(f"In-place normalization complete for {len(df)} rows.")
    return df
