import pytest
import pandas as pd
from src.parser import AuthLogParser

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
TEST_IP_FAIL = "192.0.2.1"
TEST_IP_SUCCESS = "192.0.2.2"

def test_parse_single_line_failed(tmp_path):
    """
    Validates that an authentication failure line is parsed
    correctly with FAIL status and user/IP extraction.
    Uses tmp_path fixture for safe temporary file management.
    """
    d = tmp_path / "subdir"
    d.mkdir()
    log_file = d / "test_auth.log"
    line = f"Oct 11 10:00:00 server sshd[123]: Failed password for root from {TEST_IP_FAIL}"
    log_file.write_text(line)
        
    parser = AuthLogParser(str(log_file))
    df = parser.parse()
    
    assert not df.empty
    assert df.iloc[0]['status'] == "FAIL"
    assert df.iloc[0]['usuario'] == "root"
    assert df.iloc[0]['ip_origen'] == TEST_IP_FAIL
    assert 'datetime' in df.columns

def test_parse_success_line(tmp_path):
    """
    Validates SUCCESS normalization of an accepted access using tmp_path.
    """
    log_file = tmp_path / "test_success.log"
    line = f"Oct 11 12:00:00 server sshd[456]: Accepted password for admin from {TEST_IP_SUCCESS}"
    log_file.write_text(line)
        
    parser = AuthLogParser(str(log_file))
    df = parser.parse()
    
    assert df.iloc[0]['status'] == "SUCCESS"
    assert df.iloc[0]['usuario'] == "admin"
