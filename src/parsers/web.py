import re
import logging
from datetime import datetime
from typing import Dict, Optional, Any, List
from .base import BaseParser

logger = logging.getLogger(__name__)

class WebParser(BaseParser):
    """Parser for Nginx and Apache log formats (Access and Error)."""
    
    _TIMESTAMP_FORMATS = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%d/%b/%Y:%H:%M:%S",
        "%a %b %d %H:%M:%S.%f %Y",
        "%a %b %d %H:%M:%S %Y",
        "%b %d %H:%M:%S %Y",
    ]

    def __init__(self, file_path: str):
        super().__init__(file_path)
        
        # Combined log format (Nginx/Apache)
        self.weblog_pattern = re.compile(
            r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
            r"(?P<ident>\S+)\s+"
            r"(?P<user>\S+)\s+"
            r"\[(?P<timestamp>[^\]]+)\]\s+"
            r'"(?P<method>\S+)\s+(?P<url>\S+)\s+[^"]*"\s+'
            r"(?P<status>\d+)\s+"
            r"(?P<bytes>\S+)\s+"
            r'"(?P<referer>[^"]*)"\s+'
            r'"(?P<user_agent>[^"]*)"'
        )

        # Error log format
        self.web_error_pattern = re.compile(
            r"^\[(?P<timestamp>[^\]]+)\]\s+"
            r"\[(?P<level>\w+)\]\s+"
            r"(?:\[pid\s+(?P<pid>\d+)\]\s+)?"
            r"(?:\[client\s+(?P<ip>[^\]]+)\]\s+)?"
            r"(?P<message>.*)$"
        )
        
        self.web_attack_patterns = {
            'command_injection': re.compile(r"(;|\||\`|\$\(|\$\{|&&|\|\||\n|%0a|%0d)", re.IGNORECASE),
        }

    def _parse_timestamp(self, ts_str: str) -> str:
        if not ts_str: return ''
        clean = ts_str.strip('[]').strip()
        for fmt in self._TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(clean, fmt)
                return dt.strftime('%b %d %H:%M:%S')
            except ValueError: continue
        return ts_str[:20]

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        self.lines_read += 1
        if not line: return None
        
        # Try Access Log
        match = self.weblog_pattern.match(line)
        if match:
            data = match.groupdict()
            url = data.get('url', '')
            attack_types = [name for name, p in self.web_attack_patterns.items() if p.search(url)]
            
            try:
                status_num = int(data.get('status', '200'))
                status = "FAIL" if status_num >= 400 else "SUCCESS" if status_num >= 200 else "INFO"
            except (ValueError, TypeError): 
                status = "INFO"

            self.lines_parsed += 1
            return {
                'timestamp': self._parse_timestamp(data.get('timestamp', '')),
                'hostname': '-',
                'process': 'web_server',
                'pid': None,
                'ip_origen': data.get('ip'),
                'usuario': data.get('user') if data.get('user') != '-' else None,
                'accion': f"{data.get('method', 'GET')} {url}",
                'status': status,
                'method': data.get('method'),
                'url': url,
                'http_status': data.get('status'),
                'user_agent': data.get('user_agent'),
                'referer': data.get('referer'),
                'attack_types': attack_types if attack_types else None,
                'bytes_sent': data.get('bytes')
            }

        # Try Error Log
        match = self.web_error_pattern.match(line)
        if match:
            data = match.groupdict()
            ip_raw = data.get('ip')
            client_ip = ip_raw.split(':')[0] if ip_raw else None
            
            self.lines_parsed += 1
            return {
                'timestamp': self._parse_timestamp(data.get('timestamp', '')),
                'hostname': '-',
                'process': 'web_server',
                'pid': data.get('pid'),
                'ip_origen': client_ip,
                'usuario': None,
                'accion': data.get('message', ''),
                'status': 'FAIL',
                'log_level': data.get('level'),
                'method': None,
                'url': None,
                'attack_types': None
            }

        self.lines_discarded += 1
        return None
