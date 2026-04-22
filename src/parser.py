import pandas as pd
import logging
from datetime import datetime
from typing import List, Dict, Optional, Callable, Any
from .parsers.syslog import SyslogParser
from .parsers.web import WebParser

logger = logging.getLogger(__name__)

class AuthLogParser:
    """
    Facade class that orchestrates different log parsers.
    Supports auto-detection and progress reporting.
    """

    LOG_FORMAT_SYSLOG = "syslog"
    LOG_FORMAT_NGINX = "nginx"
    LOG_FORMAT_APACHE = "apache"

    def __init__(self, file_path: str) -> None:
        self.file_path = file_path
        self.syslog_parser = SyslogParser(file_path)
        self.web_parser = WebParser(file_path)
        self.active_parser = None
        self.lines_read = 0

    def _detect_format(self, sample_lines: List[str]) -> Any:
        """Detects format and returns the appropriate parser instance."""
        syslog_matches = 0
        web_matches = 0

        for line in sample_lines:
            line = line.strip()
            if not line: continue
            
            # Use the underlying parsers' internal patterns for detection (simplified check)
            if self.syslog_parser.syslog_pattern.match(line):
                syslog_matches += 1
            elif self.web_parser.weblog_pattern.match(line) or self.web_parser.web_error_pattern.match(line):
                web_matches += 1

        if web_matches > syslog_matches:
            return self.web_parser
        return self.syslog_parser

    def parse(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> pd.DataFrame:
        """
        Parses the log file using auto-detection in a single pass.
        Supports a progress_callback(current_line, total_lines).
        """
        parsed_data = []
        
        try:
            # Senior optimization: Avoid double-read of the file.
            # We skip the line count (O(N) penalty) and report progress with total=-1 
            # unless a very efficient estimate is needed.
            total_lines = -1 
            
            with open(self.file_path, 'r', encoding='utf-8', errors='replace') as f:
                # Detect format from first 20 lines
                sample = [f.readline() for _ in range(20)]
                detected = self._detect_format(sample)
                
                if detected is None:
                    raise ValueError(f"CRITICAL: Failed to detect log format for {self.file_path}. No suitable parser found.")
                
                self.active_parser = detected
                logger.info(f"Using parser: {self.active_parser.__class__.__name__}")
                
                f.seek(0)
                for i, line in enumerate(f):
                    line = line.strip()
                    if not line: continue
                    
                    if self.active_parser is None:
                        # This should theoretically be unreachable due to the raise above, 
                        # but we check to satisfy static analysis tools (SonarQube)
                        break
                        
                    p_line = self.active_parser.parse_line(line)
                    if p_line:
                        parsed_data.append(p_line)
                    
                    if progress_callback and i % 500 == 0:
                        progress_callback(i + 1, total_lines)
                
                if progress_callback:
                    progress_callback(len(parsed_data), total_lines)

            # Sync stats from active parser
            if self.active_parser:
                self.lines_read = self.active_parser.lines_read
            
        except Exception as e:
            logger.error(f"Parsing error: {e}")
            return pd.DataFrame()

        df = pd.DataFrame(parsed_data)
        if df.empty: return self._get_empty_df()

        return self._post_process(df)

    def _post_process(self, df: pd.DataFrame) -> pd.DataFrame:
        """Standardizes columns and processes timestamps."""
        all_columns = [
            'timestamp', 'datetime', 'hostname', 'process', 'pid',
            'ip_origen', 'usuario', 'accion', 'status',
            'method', 'url', 'http_status', 'user_agent', 'referer',
            'attack_types', 'bytes_sent', 'log_level'
        ]
        
        for col in all_columns:
            if col not in df.columns: df[col] = None

        # Datetime conversion
        df['datetime'] = pd.to_datetime(df['timestamp'], format='%b %d %H:%M:%S', errors='coerce')
        df = df.dropna(subset=['datetime']).copy()
        
        # Year inference
        cur = datetime.now()
        df['datetime'] = df['datetime'].apply(
            lambda x: x.replace(year=cur.year if x.replace(year=cur.year) <= cur else cur.year - 1)
            if x.year == 1900 else x
        )
        
        return df[all_columns]

    def _get_empty_df(self) -> pd.DataFrame:
        return pd.DataFrame(columns=[
            'timestamp', 'datetime', 'hostname', 'process', 'pid', 'ip_origen', 
            'usuario', 'accion', 'status'
        ])

    def get_stats(self) -> Dict[str, Any]:
        return self.active_parser.get_stats() if self.active_parser else {}

    @property
    def detected_format(self) -> Optional[str]:
        """Backward compatible access to detected format."""
        if not self.active_parser:
            return None
        from .parsers.web import WebParser
        return self.LOG_FORMAT_NGINX if isinstance(self.active_parser, WebParser) else self.LOG_FORMAT_SYSLOG
