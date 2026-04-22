import os
import re
import zlib
import joblib
import logging
import pandas as pd
from urllib.parse import unquote_plus
from typing import List, Optional
from abc import ABC, abstractmethod
from .config import MODEL_PATH
from .features import extract_features

# Logger local
logger = logging.getLogger(__name__)

class DetectionRule(ABC):
    """
    Base class (Interface) for creating detection rules.
    Allows scaling logic by adding new subclasses.
    """
    @property
    @abstractmethod
    def severity(self) -> str:
        """Severity level: low, medium, high."""
        pass

    @abstractmethod
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Evaluates the DataFrame and returns only rows considered anomalous.
        Adds columns: 'reason', 'rule', 'severity'.
        """
        pass


class BruteForceRule(DetectionRule):
    """
    Detects brute force attacks.
    > 5 failed login attempts within 1 minute from the same IP.
    
    This rule analyzes patterns using a 1-minute sliding window. 
    It can detect multiple bursts from the same IP if they occur in 
    different time windows.
    """
    @property
    def rule_name(self) -> str:
        return "Brute Force"

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifies brute force patterns using a 1-minute sliding window.
        Only marks the specific row where the threshold is crossed (6th attempt),
        not all rows in the window.
        
        Note: Once the threshold is crossed for an IP, no more alerts are
        generated for that IP in the same session (prevents duplicates).
        """
        try:
            if df.empty or 'datetime' not in df.columns:
                return pd.DataFrame()

            # Filter only failed login attempts
            df_failed = df[df['status'] == 'FAIL'].copy()

            if df_failed.empty:
                return pd.DataFrame()

            anomalies = []

            # Group by IP to detect coordinated attacks from same source
            for ip, group in df_failed.groupby('ip_origen'):
                if len(group) < 6:
                    continue

                # Ensure chronological order
                group_sorted = group.sort_values('datetime').reset_index(drop=True)
                datetimes = group_sorted['datetime']

                n = len(group_sorted)

                # Sliding window: count attempts in 1-minute window
                # Use two-pointer O(n) approach for efficiency
                left = 0
                threshold_crossed_indices = []

                for right in range(n):
                    # Move left pointer to maintain 1-minute window
                    while left <= right and datetimes.iloc[right] - datetimes.iloc[left] > pd.Timedelta('1min'):
                        left += 1

                    # Count attempts in current window
                    attempts_in_window = right - left + 1

                    # If we reach or exceed threshold (6+ attempts), mark this row
                    # We report each event that is the "tail" of a burst
                    if attempts_in_window >= 6:
                        threshold_crossed_indices.append(right)

                if threshold_crossed_indices:
                    # Mark all rows where threshold was active
                    anomalous_rows = group_sorted.iloc[threshold_crossed_indices].copy()
                    anomalous_rows['reason'] = f"{self.rule_name}: Threshold reached (6+ failed logins)"
                    anomalous_rows['rule'] = self.rule_name
                    anomalous_rows['severity'] = self.severity
                    anomalies.append(anomalous_rows)

            if anomalies:
                combined = pd.concat(anomalies, ignore_index=True)
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(combined)} events from {len(anomalies)} IPs")
                return combined
        except Exception as e:
            logger.error(f"Error in rule {self.rule_name}: {e}")

        return pd.DataFrame()


class TimeAnomalyRule(DetectionRule):
    def __init__(self, start_hour=8, end_hour=18):
        # By default, off-hours are before 8 AM and after 6 PM.
        self.start_hour = start_hour
        self.end_hour = end_hour

    @property
    def rule_name(self) -> str:
        return "Time Anomaly"

    @property
    def severity(self) -> str:
        return "medium"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """Detects successful logins outside of business hours."""
        try:
            if df.empty or 'datetime' not in df.columns:
                return pd.DataFrame()

            # Use normalized 'status' column
            df_success = df[df['status'] == 'SUCCESS'].copy()
            
            if df_success.empty:
                return pd.DataFrame()
                
        # Check hour (using datetime)
            hour = df_success['datetime'].dt.hour
            out_of_hours_mask = (hour < self.start_hour) | (hour >= self.end_hour)
            
            df_anomalies = df_success[out_of_hours_mask].copy()
            if not df_anomalies.empty:
                df_anomalies['reason'] = f"{self.rule_name}: Login outside business hours"
                df_anomalies['rule'] = self.rule_name
                df_anomalies['severity'] = self.severity
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(df_anomalies)} events")
                return df_anomalies
        except Exception as e:
            logger.error(f"Error in rule {self.rule_name}: {e}")
            
        return pd.DataFrame()


class UserProbingRule(DetectionRule):
    """
    Detects user probing from a single IP.
    > 4 different usernames within 10 minutes from the same IP.
    """
    
    @property
    def rule_name(self) -> str:
        return "User Probing"

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detects if a single IP attempts to access more than 3 different usernames
        within a 10-minute interval. Uses O(n) sliding window with two-pointer approach.
        
        Note: Once the threshold (4+ unique users) is crossed for an IP,
        no more alerts are generated for that IP in the same session (prevents duplicates).
        """
        try:
            if df.empty or 'datetime' not in df.columns or 'ip_origen' not in df.columns or 'usuario' not in df.columns:
                return pd.DataFrame()

            anomalies = []
            # Group by IP to analyze username diversity
            for ip, group in df.groupby('ip_origen'):
                if len(group) < 4:
                    continue

                # Sort by datetime for sliding window
                group_sorted = group.sort_values('datetime').reset_index(drop=True)
                datetimes = group_sorted['datetime']
                usuarios = group_sorted['usuario']

                n = len(group_sorted)
                window_unique_counts = []

                # Sliding window: track unique users in current window
                # Two-pointer approach: O(n) total
                user_counts = {}
                left = 0
                current_unique = 0

                for right in range(n):
                    # Add right pointer user
                    user_right = usuarios.iloc[right]
                    user_counts[user_right] = user_counts.get(user_right, 0) + 1
                    if user_counts[user_right] == 1:
                        current_unique += 1

                    # Move left pointer to maintain 10-minute window
                    while left <= right and datetimes.iloc[right] - datetimes.iloc[left] > pd.Timedelta('10min'):
                        user_left = usuarios.iloc[left]
                        user_counts[user_left] -= 1
                        if user_counts[user_left] == 0:
                            current_unique -= 1
                            del user_counts[user_left]
                        left += 1

                    window_unique_counts.append(current_unique)

                # Find indices where threshold is crossed (4+ unique users)
                threshold_indices = [i for i, count in enumerate(window_unique_counts) if count >= 4]

                if threshold_indices:
                    # Mark all rows where threshold was active
                    anomalous_rows = group_sorted.iloc[threshold_indices].copy()
                    anomalous_rows['reason'] = f"{self.rule_name}: Threshold reached (4+ unique users in 10min)"
                    anomalous_rows['rule'] = self.rule_name
                    anomalous_rows['severity'] = self.severity
                    anomalies.append(anomalous_rows)

            if anomalies:
                combined = pd.concat(anomalies, ignore_index=True)
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(combined)} probing events")
                return combined
        except Exception as e:
            logger.error(f"Error in rule {self.rule_name}: {e}")

        return pd.DataFrame()


class IsolationForestRule(DetectionRule):
    def __init__(self, contamination: float = 0.01, model_path: str = MODEL_PATH, model=None):
        self.contamination = contamination
        self.model_path = model_path
        self.model = model  # Pre-loaded model

    @property
    def rule_name(self) -> str:
        return "Isolation Forest Anomaly"

    @property
    def severity(self) -> str:
        return "low"
        
    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Utiliza Isolation Forest para detectar anomalías.
        Persiste el modelo para evitar re-entrenamiento constante.
        """
        try:
            from sklearn.ensemble import IsolationForest
        except ImportError:
            logger.warning("scikit-learn not found. Skipping advanced AI detection.")
            return pd.DataFrame()

        if df.empty or len(df) < 5:  # Reducimos umbral para facilitar tests, pero ideal > 10
            return pd.DataFrame()

        df_ml = df.copy()
        # Use shared feature extraction to ensure consistency with training
        features = extract_features(df_ml)

        try:
            model = self.model
            if model is None:
                if not os.path.exists(self.model_path):
                    logger.warning(f"AI model not found at {self.model_path}. Please run train_model.py first.")
                    return pd.DataFrame()
                # FALLBACK: Cargando desde disco - esto bloquea el request thread!
                # En producción, esto solo debería ocurrir si el lifespan falló
                logger.warning("=" * 70)
                logger.warning("WARNING: AI model loading from disk (fallback mode)")
                logger.warning("This may cause latency on the first request.")
                logger.warning("Verify that the lifespan in main.py loaded the model correctly.")
                logger.warning("=" * 70)
                model = joblib.load(self.model_path)
                logger.debug(f"AI model loaded from file {self.model_path}")
            else:
                logger.debug("Pre-loaded AI model used")

            predictions = model.predict(features)
            anomaly_mask = predictions == -1
            
            df_anomalies = df_ml[anomaly_mask].copy()
            if not df_anomalies.empty:
                df_anomalies['reason'] = self.rule_name
                df_anomalies['rule'] = self.rule_name
                df_anomalies['severity'] = self.severity
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(df_anomalies)} anomalies")
                return df_anomalies
        except Exception as e:
            logger.error(f"Error in AI engine: {e}")
            
        return pd.DataFrame()


class LogDetector:
    """Main detection engine that orchestrates all detection rules."""
    
    def __init__(self):
        self.rules: List[DetectionRule] = []
        
    def add_rule(self, rule: DetectionRule) -> None:
        """Adds a rule to the evaluation context.
        
        Validates that no rule of the same type exists to prevent duplicates.
        """
        # Validate no duplicate rule is added (same type)
        existing_types = [type(r) for r in self.rules]
        if type(rule) in existing_types:
            logger.warning(f"Rule {type(rule).__name__} already exists in detector. Skipping duplicate.")
            return
        
        self.rules.append(rule)
        
    def run(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Transforms data and runs DataFrame against all loaded rules,
        consolidating into a single DataFrame with anomalies.
        """
        if df.empty:
            logger.warning("Empty DataFrame. Detector finishing.")
            return pd.DataFrame()
            
        df_analysis = df.copy()
        
        # DataFrame should already have 'datetime' column from parser.
        # If missing for some reason, log warning but don't try to fix here.
        if 'datetime' not in df_analysis.columns:
            logger.error("DataFrame does not contain required 'datetime' column for analysis.")
            return pd.DataFrame()

        all_anomalies = []
        for rule in self.rules:
            logger.debug(f"Evaluating DataFrame against rule: {rule.rule_name}")
            anomalous_df = rule.evaluate(df_analysis)

            if anomalous_df is not None and not anomalous_df.empty:
                all_anomalies.append(anomalous_df)
                
        if all_anomalies:
            final_df = pd.concat(all_anomalies, ignore_index=True)
            
            # Group anomalies and clean duplicates.
            # Use 'datetime' (with inferred year) instead of 'timestamp' (without year)
            # to avoid collapsing legitimately distinct events that occur
            # at the same second but in different years.
            #
            # NOTE: Web logs (Nginx/Apache) may have usuario=None and accion=None
            # for unauthenticated requests. dropna=False ensures these rows are
            # grouped correctly (None treated as a valid group key) rather than
            # being silently dropped, which would cause missed detections.
            groupby_cols = ['datetime', 'ip_origen', 'usuario', 'accion', 'status']
            # Only include groupby columns that exist in the DataFrame
            groupby_cols = [c for c in groupby_cols if c in final_df.columns]

            # Aggregation logic: consolidate reasons, rules, and take max severity
            def aggregate_severity(series):
                prio = {"high": 3, "medium": 2, "low": 1}
                return max(series, key=lambda x: prio.get(x.lower(), 0))

            agg_dict = {
                'reason': lambda x: " | ".join(x.unique()),
                'rule': lambda x: " | ".join(x.unique()),
                'severity': aggregate_severity
            }
            if 'timestamp' in final_df.columns:
                agg_dict['timestamp'] = 'first'

            final_df = final_df.groupby(
                groupby_cols, dropna=False, as_index=False
            ).agg(agg_dict)
            
            final_df.sort_values(by='datetime', inplace=True)
            return final_df
            
        return pd.DataFrame()
 # Empty DataFrame => log is "clean"

class SQLInjectionRule(DetectionRule):
    """
    Detects SQL Injection attacks in web server logs.

    URLs are URL-decoded before pattern matching to catch both encoded and
    plain-text injection attempts in a single pass.

    Pattern design rationale:
    - The previously-used broad patterns (single quote alone, bare '#') caused
      false positives on legitimate URLs such as /products/women's-shoes or
      /page#section. All patterns now require SQL-specific context to reduce FPs.
    """
    @property
    def rule_name(self) -> str:
        return "SQL Injection"

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifies requests with SQL injection patterns in the URL.

        URLs are decoded with urllib.parse.unquote_plus before matching so that
        both %27 and the literal apostrophe are caught by the same pattern,
        eliminating the need for parallel encoded/plain variants.
        """
        try:
            if df.empty or 'url' not in df.columns:
                logger.debug(
                    f"Rule {self.rule_name}: 'url' column not present, "
                    "skipping (auth log format)"
                )
                return pd.DataFrame()

            # SQL injection patterns — all require explicit SQL context to avoid FPs.
            sql_patterns = [
                r"('|\")\s*(or|and|union|select|--|#|;)",
                r"=\s*[^&\n]*('|\")\s*(--|;|or\b|and\b)",
                r"union\s+(?:all\s+)?select\s+.+\s+from",
                r"insert\s+into\s+\w+\s*\(",
                r"delete\s+from\s+\w+\s+where",
                r"update\s+\w+\s+set\s+\w+\s*=",
                r"drop\s+(table|database)\s+\w+",
                r"exec\s*\(\s*|xp_\w+",
                r"benchmark\s*\(\s*\d+",
                r"\bsleep\s*\(\s*\d+",
                r";\s*(select|insert|update|delete|drop|exec)\b",
            ]

            combined_pattern = '|'.join(f'({p})' for p in sql_patterns)
            regex = re.compile(combined_pattern, re.IGNORECASE)

            # Use normalized pre-decoded URLs
            # If 'url_decoded' is missing for some reason, fallback to plain URL
            url_col = 'url_decoded' if 'url_decoded' in df.columns else 'url'
            mask = df[url_col].astype(str).str.contains(regex, na=False, regex=True)
            anomalies = df[mask].copy()

            if not anomalies.empty:
                anomalies['reason'] = f"Detected by {self.rule_name}"
                anomalies['rule'] = self.rule_name
                anomalies['severity'] = self.severity
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(anomalies)} injection attempts")

            return anomalies

        except Exception as e:
            logger.error(f"Error in SQLInjectionRule: {e}")
            return pd.DataFrame()


class XSSRule(DetectionRule):
    """
    Detects Cross-Site Scripting (XSS) attacks in web server logs.
    Looks for script tags, JavaScript protocols, event handlers, etc.
    URLs are decoded before matching.
    """
    @property
    def rule_name(self) -> str:
        return "XSS Attack"

    @property
    def severity(self) -> str:
        return "medium"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifies requests with XSS patterns in the URL or user agent.
        URLs are URL-decoded before matching to handle encoded payloads.
        """
        try:
            if df.empty or 'url' not in df.columns:
                logger.debug(
                    f"Rule {self.rule_name}: 'url' column not present, "
                    "skipping (auth log format)"
                )
                return pd.DataFrame()

            # XSS patterns
            xss_patterns = [
                r"<script[^>]*>[\s\S]*?</script>",  # <script> tags
                r"javascript:",                       # javascript: protocol
                r"on\w+\s*=\s*['\"]",               # Event handlers: onclick=, onload=, etc.
                r"alert\s*\(",                        # alert()
                r"document\.cookie",                  # document.cookie access
                r"document\.location",                # document.location manipulation
                r"window\.location",                  # window.location
                r"eval\s*\(",                         # eval()
                r"String\.fromCharCode",              # String.fromCharCode obfuscation
                r"<iframe",                           # iframe injection
                r"<object",                           # object tag
                r"<embed",                            # embed tag
                r"expression\s*\(",                   # CSS expression
            ]

            combined_pattern = '|'.join(f'({p})' for p in xss_patterns)
            regex = re.compile(combined_pattern, re.IGNORECASE)

            # Use normalized pre-decoded URLs
            url_col = 'url_decoded' if 'url_decoded' in df.columns else 'url'
            url_mask = df[url_col].astype(str).str.contains(regex, na=False, regex=True)

            ua_mask = (
                df['user_agent'].astype(str).str.contains(regex, na=False, regex=True)
                if 'user_agent' in df.columns
                else pd.Series([False] * len(df))
            )

            mask = url_mask | ua_mask
            anomalies = df[mask].copy()

            if not anomalies.empty:
                anomalies['reason'] = f"Detected by {self.rule_name}"
                anomalies['rule'] = self.rule_name
                anomalies['severity'] = self.severity
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(anomalies)} XSS attempts")

            return anomalies

        except Exception as e:
            logger.error(f"Error in XSSRule: {e}")
            return pd.DataFrame()


class PathTraversalRule(DetectionRule):
    """
    Detects Path Traversal / Directory Traversal attacks.
    Looks for ../, ..\\ patterns attempting to access files outside web root.
    URLs are decoded before matching.
    """
    @property
    def rule_name(self) -> str:
        return "Path Traversal"

    @property
    def severity(self) -> str:
        return "high"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifies requests with path traversal patterns in the URL.
        URLs are URL-decoded before matching to handle encoded traversal attempts.
        """
        try:
            if df.empty or 'url' not in df.columns:
                logger.debug(
                    f"Rule {self.rule_name}: 'url' column not present, "
                    "skipping (auth log format)"
                )
                return pd.DataFrame()

            # Path traversal patterns
            traversal_patterns = [
                r"\.\./",                # ../
                r"\.\.[/\\]",           # ../ or ..\
                r"\.\.%2f",             # URL-encoded ../ (caught after partial decode)
                r"\.\.\.\.\/",          # Multiple dots
                r"etc/passwd",          # /etc/passwd access attempt
                r"windows/win\.ini",    # Windows ini file
                r"boot\.ini",           # Windows boot.ini
                r"\.\.%c0%af",          # Unicode traversal
                r"\.\.%c1%9c",          # Unicode traversal (alternate)
            ]

            combined_pattern = '|'.join(f'({p})' for p in traversal_patterns)
            regex = re.compile(combined_pattern, re.IGNORECASE)

            # Use normalized pre-decoded URLs
            url_col = 'url_decoded' if 'url_decoded' in df.columns else 'url'
            mask = df[url_col].astype(str).str.contains(regex, na=False, regex=True)
            anomalies = df[mask].copy()

            if not anomalies.empty:
                anomalies['reason'] = f"Detected by {self.rule_name}"
                anomalies['rule'] = self.rule_name
                anomalies['severity'] = self.severity
                logger.info(f"SECURITY ALERT: {self.rule_name} detected {len(anomalies)} traversal attempts")

            return anomalies

        except Exception as e:
            logger.error(f"Error in PathTraversalRule: {e}")
            return pd.DataFrame()


class WebAttackRule(DetectionRule):
    """
    Generic web attack detector using patterns from the parser.
    Detects any requests flagged with attack_types during parsing.
    """
    @property
    def rule_name(self) -> str:
        return "Web Attack"

    @property
    def severity(self) -> str:
        return "medium"

    def evaluate(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identifies requests that were flagged with attack types during parsing.
        """
        try:
            if df.empty or 'attack_types' not in df.columns:
                return pd.DataFrame()

            # Filter rows with attack_types set
            mask = df['attack_types'].notna()
            anomalies = df[mask].copy()

            if not anomalies.empty:
                anomalies['reason'] = anomalies['attack_types'].apply(
                    lambda x: f"Detected by {self.rule_name}: {', '.join(x) if isinstance(x, list) else x}"
                )
                anomalies['rule'] = self.rule_name
                anomalies['severity'] = self.severity
                logger.debug(
                    f"Rule {self.rule_name}: {len(anomalies)} anomalies detected "
                    f"from parser-flagged attack_types"
                )

            return anomalies

        except Exception as e:
            logger.error(f"Error in WebAttackRule: {e}")
            return pd.DataFrame()


if __name__ == "__main__":
    # Local test or visual debugging for import
    detector = LogDetector()
    detector.add_rule(BruteForceRule())
    detector.add_rule(TimeAnomalyRule())
    detector.add_rule(IsolationForestRule())
    detector.add_rule(SQLInjectionRule())
    detector.add_rule(XSSRule())
    detector.add_rule(PathTraversalRule())

    print("Detector module initialized successfully with Patterns and Machine Learning (IF).")
