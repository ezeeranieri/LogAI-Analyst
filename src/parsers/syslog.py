import re
import logging
from typing import Dict, Optional, Any
from .base import BaseParser

logger = logging.getLogger(__name__)

class SyslogParser(BaseParser):
    """Parser for standard UNIX syslog formats."""
    
    def __init__(self, file_path: str):
        super().__init__(file_path)
        
        # Main regex for typical syslog format
        # Example: "Oct 11 10:00:00 servername sshd[123]: Failed password for user from <IP>"
        self.syslog_pattern = re.compile(
            r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
            r"(?P<hostname>\S+)\s+"
            r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
            r"(?P<action>.*)$"
        )
        
        # IPv4 pattern
        self.ip_pattern = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
        
        # User patterns
        self.user_pattern = re.compile(
            r"(?:user\s+(?:'='?'?)?|for\s+(?:invalid\s+)?user\s+|user\s*[=:]\s*)(?P<user>[a-zA-Z0-9_.-]+)",
            re.IGNORECASE
        )
        
        self.auth_patterns = {
            'invalid_user': re.compile(r"invalid\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'failed_password': re.compile(r"failed\s+password\s+(?:for\s+)?(?:invalid\s+user\s+)?(?P<user>\S*)", re.IGNORECASE),
            'accepted_password': re.compile(r"accepted\s+password\s+for\s+(?P<user>\S+)", re.IGNORECASE),
            'session_opened': re.compile(r"session\s+opened\s+for\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'session_closed': re.compile(r"session\s+closed\s+for\s+user\s+(?P<user>\S+)", re.IGNORECASE),
            'authentication_failure': re.compile(r"authentication\s+failure", re.IGNORECASE),
            'pam_auth': re.compile(r"pam_\w+\(.*?\):\s+authentication\s+(?P<result>\w+)", re.IGNORECASE),
        }

    def _extract_user(self, action_msg: str) -> Optional[str]:
        """Extracts username from message using multiple patterns."""
        for name, pattern in self.auth_patterns.items():
            match = pattern.search(action_msg)
            if match:
                user = match.groupdict().get('user')
                if user: return user
        
        user_match = self.user_pattern.search(action_msg)
        return user_match.group('user') if user_match else None

    def _determine_status(self, action_msg: str, process: str) -> str:
        """Determines status based on message content."""
        action_lower = action_msg.lower()
        process_lower = process.lower()
        
        success_terms = ['accept', 'success', 'granted', 'opened', 'authorized', 'authenticated']
        fail_terms = ['fail', 'invalid', 'error', 'denied', 'refused', 'incorrect', 'bad', 'not allowed']
        
        if 'pam' in process_lower or 'sshd' in process_lower:
            if re.search(r'\b(accepted|opened|session opened)\b', action_lower):
                return "SUCCESS"
            if re.search(r'\b(failed|invalid|authentication failure|closed|rejected)\b', action_lower):
                return "FAIL"
                
        if any(term in action_lower for term in fail_terms): return "FAIL"
        if any(term in action_lower for term in success_terms): return "SUCCESS"
        return "INFO"

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        self.lines_read += 1
        match = self.syslog_pattern.match(line)
        if not match:
            self.lines_discarded += 1
            return None

        data = match.groupdict()
        action_msg = data['action']
        
        ip_match = self.ip_pattern.search(action_msg)
        user = self._extract_user(action_msg)
        status = self._determine_status(action_msg, data.get('process', ''))

        self.lines_parsed += 1
        return {
            'timestamp': data['timestamp'],
            'hostname': data['hostname'],
            'process': data['process'],
            'pid': data.get('pid'),
            'ip_origen': ip_match.group('ip') if ip_match else None,
            'usuario': user,
            'accion': action_msg,
            'status': status,
            'method': None,
            'url': None,
            'attack_types': None
        }
