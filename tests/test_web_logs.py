"""Tests for web server log parsing (Nginx, Apache) and web attack detection."""
import pytest
import pandas as pd
from datetime import datetime
from src.parser import AuthLogParser
from src.detector import SQLInjectionRule, XSSRule, PathTraversalRule, WebAttackRule
from src.normalization import normalize_df

# Test IPs — RFC 5737 (192.0.2.x) reserved range by IANA for documentation and tests
TEST_IP = "192.0.2.1"
ATTACKER_IP = "192.0.2.100"


class TestWebLogParsing:
    """Test parsing of Nginx/Apache combined log format."""

    def test_parse_nginx_access_log(self, tmp_path):
        """
        Validates parsing of Nginx combined log format.
        """
        log_file = tmp_path / "nginx_access.log"
        log_line = f'{TEST_IP} - - [11/Oct/2026:10:00:00 +0000] "GET /api/test HTTP/1.1" 200 1234 "-" "Mozilla/5.0"'
        log_file.write_text(log_line)

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert df is not None, "AuthLogParser.parse() returned None for Nginx access log"
        assert not df.empty
        assert df.iloc[0]['ip_origen'] == TEST_IP
        assert df.iloc[0]['method'] == "GET"
        assert df.iloc[0]['url'] == "/api/test"
        assert df.iloc[0]['http_status'] == "200"
        assert df.iloc[0]['status'] == "SUCCESS"
        assert df.iloc[0]['user_agent'] == "Mozilla/5.0"

    def test_parse_apache_error_log(self, tmp_path):
        """
        Validates parsing of Apache error log format.
        """
        log_file = tmp_path / "apache_error.log"
        log_line = '[Thu Oct 11 10:00:00.123456 2026] [error] [pid 12345] [client 192.0.2.1:54321] File not found'
        log_file.write_text(log_line)

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert df is not None, "AuthLogParser.parse() returned None for Apache error log"
        assert not df.empty
        assert df.iloc[0]['ip_origen'] == "192.0.2.1"
        assert df.iloc[0]['status'] == "FAIL"
        assert df.iloc[0]['log_level'] == "error"

    def test_parse_multiple_web_entries(self, tmp_path):
        """
        Validates parsing multiple web log entries.
        NOTE: The parser does not guarantee original line order (may sort by datetime).
        Uses sorted() comparison to verify content regardless of row ordering.
        """
        log_file = tmp_path / "web.log"
        lines = [
            '192.0.2.1 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"',
            '192.0.2.2 - - [11/Oct/2026:10:01:00 +0000] "POST /login HTTP/1.1" 302 456 "-" "Mozilla/5.0"',
            '192.0.2.1 - - [11/Oct/2026:10:02:00 +0000] "GET /admin HTTP/1.1" 404 789 "-" "Mozilla/5.0"'
        ]
        log_file.write_text("\n".join(lines))

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert df is not None, "AuthLogParser.parse() returned None for multiple web log entries"
        assert len(df) == 3
        # Use sorted comparison to avoid order dependency
        assert sorted(df['method'].tolist()) == sorted(["GET", "POST", "GET"])
        assert sorted(df['http_status'].tolist()) == sorted(["200", "302", "404"])

    def test_web_log_status_classification(self, tmp_path):
        """
        Validates HTTP status code classification (2xx=SUCCESS, 4xx/5xx=FAIL).
        """
        log_file = tmp_path / "status_test.log"
        lines = [
            '192.0.2.1 - - [11/Oct/2026:10:00:00 +0000] "GET /ok HTTP/1.1" 200 123 "-" "-"',
            '192.0.2.1 - - [11/Oct/2026:10:01:00 +0000] "GET /redirect HTTP/1.1" 301 0 "-" "-"',
            '192.0.2.1 - - [11/Oct/2026:10:02:00 +0000] "GET /notfound HTTP/1.1" 404 123 "-" "-"',
            '192.0.2.1 - - [11/Oct/2026:10:03:00 +0000] "POST /error HTTP/1.1" 500 123 "-" "-"'
        ]
        log_file.write_text("\n".join(lines))

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert df is not None, "AuthLogParser.parse() returned None during status classification test"
        statuses = df['status'].tolist()
        assert statuses == ["SUCCESS", "SUCCESS", "FAIL", "FAIL"]


class TestSQLInjectionDetection:
    """Test SQL Injection attack detection."""

    def test_detects_sql_injection_union_select(self):
        """
        Validates detection of UNION SELECT SQL injection.
        """
        rule = SQLInjectionRule()
        data = {
            'url': ["/search?q=1' UNION SELECT * FROM users--", "/normal/page", "/api?id=1' OR '1'='1"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2", ATTACKER_IP],
            'status': ["FAIL", "SUCCESS", "FAIL"]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None"
        assert len(anomalies) == 2
        assert all("SQL Injection" in reason for reason in anomalies['reason'])

    def test_detects_sql_injection_quotes_and_comments(self):
        """
        Validates detection of quote+operator and stacked-query SQL injection.

        Note: bare /page?id=1# (hash fragment with no SQL context) is intentionally
        NOT detected by the updated rule to avoid false positives on fragment URLs.
        The patterns now require explicit SQL context next to quotes/comments.
        """
        rule = SQLInjectionRule()
        data = {
            'url': [
                "/page?id=1'--",           # quote followed by SQL comment → match
                "/login?user=admin'or 1",  # quote + 'or' keyword → match
            ],
            'ip_origen': [ATTACKER_IP] * 2,
            'status': ["FAIL"] * 2
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None for quote/comment patterns"
        assert len(anomalies) == 2

    def test_detects_encoded_sql_injection(self):
        """
        Validates that URL-encoded payloads are detected after decoding.
        %27 = apostrophe, %20 = space.
        """
        rule = SQLInjectionRule()
        data = {
            'url': [
                "/search?q=1%27%20UNION%20SELECT%20*%20FROM%20users--",
                "/api?id=1%27%20OR%20%271%27%3D%271",
            ],
            'ip_origen': [ATTACKER_IP] * 2,
            'status': ["FAIL"] * 2,
        }
        df = pd.DataFrame(data)
        df = normalize_df(df)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None for encoded payloads"
        assert len(anomalies) == 2, (
            "URL-encoded SQL injection payloads must be detected after unquote_plus decoding"
        )

    def test_no_false_positives_on_normal_urls(self):
        """
        Validates no false positives on normal URLs containing words like 'select'.
        """
        rule = SQLInjectionRule()
        data = {
            'url': ["/products/select-size", "/help/selection-guide", "/api/v1/users"],
            'ip_origen': ["192.0.2.1"] * 3,
            'status': ["SUCCESS"] * 3
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None for normal URLs"
        assert anomalies.empty

    def test_no_false_positives_apostrophe_in_url(self):
        """
        Regression: URLs with apostrophes in product names or user names must NOT
        trigger the SQL injection rule. The previous broad pattern matched any bare '.

        Examples of legitimate URLs that the old rule incorrectly flagged:
          /products/women's-shoes
          /users/O'Brien-profile
          /items/it's-here?color=red
        """
        rule = SQLInjectionRule()
        data = {
            'url': [
                "/products/women's-shoes",
                "/users/O'Brien-profile",
                "/items/it's-here?color=red",
            ],
            'ip_origen': ["192.0.2.1"] * 3,
            'status': ["SUCCESS"] * 3,
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None for apostrophe regression test"
        assert anomalies.empty, (
            f"Legitimate URLs with apostrophes should NOT be flagged as SQL injection. "
            f"Got detections for: {list(df['url'][anomalies.index]) if not anomalies.empty else []}"
        )

    def test_no_false_positives_hash_fragment_in_url(self):
        """
        Regression: URLs with '#' hash fragments (anchor links) must NOT trigger
        the SQL injection rule. The previous broad pattern matched any bare #.

        Examples of legitimate URLs that the old rule incorrectly flagged:
          /page#section
          /docs/api#introduction
          /home#contact-us
        """
        rule = SQLInjectionRule()
        data = {
            'url': [
                "/page#section",
                "/docs/api#introduction",
                "/home#contact-us",
            ],
            'ip_origen': ["192.0.2.1"] * 3,
            'status': ["SUCCESS"] * 3,
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "SQLInjectionRule.evaluate() returned None for hash fragment regression test"
        assert anomalies.empty, (
            f"URLs with '#' hash fragments should NOT be flagged as SQL injection. "
            f"Got detections for: {list(df['url'][anomalies.index]) if not anomalies.empty else []}"
        )


class TestXSSDetection:
    """Test XSS attack detection."""

    def test_detects_script_tag_xss(self):
        """
        Validates detection of <script> tag XSS.
        """
        rule = XSSRule()
        data = {
            'url': ["/search?q=<script>alert(1)</script>", "/page?name=normal"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"],
            'user_agent': ["Mozilla/5.0", "Mozilla/5.0"]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "XSSRule.evaluate() returned None"
        assert len(anomalies) == 1
        assert "XSS Attack" in anomalies.iloc[0]['reason']

    def test_detects_javascript_protocol(self):
        """
        Validates detection of javascript: protocol.
        """
        rule = XSSRule()
        data = {
            'url': ["/redirect?url=javascript:alert(1)", "/redirect?url=https://example.com"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"]
        }
        df = pd.DataFrame(data)
        df['user_agent'] = None

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "XSSRule.evaluate() returned None for javascript protocol"
        assert len(anomalies) == 1

    def test_detects_xss_in_user_agent(self):
        """
        Validates detection of XSS in User-Agent header.
        """
        rule = XSSRule()
        data = {
            'url': ["/normal/page", "/api/endpoint"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"],
            'user_agent': ["<script>alert(1)</script>", "Mozilla/5.0"]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "XSSRule.evaluate() returned None for user agent XSS"
        assert len(anomalies) == 1


class TestPathTraversalDetection:
    """Test Path Traversal attack detection."""

    def test_detects_directory_traversal(self):
        """
        Validates detection of ../ path traversal.
        """
        rule = PathTraversalRule()
        data = {
            'url': ["/static/../../../etc/passwd", "/images/logo.png"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "PathTraversalRule.evaluate() returned None"
        assert len(anomalies) == 1
        assert "Path Traversal" in anomalies.iloc[0]['reason']

    def test_detects_url_encoded_traversal(self):
        """
        Validates detection of URL-encoded path traversal.
        """
        rule = PathTraversalRule()
        data = {
            'url': ["/download?file=%2e%2e%2fconfig.ini", "/download?file=report.pdf"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"]
        }
        df = pd.DataFrame(data)
        df = normalize_df(df)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "PathTraversalRule.evaluate() returned None for encoded patterns"
        assert len(anomalies) == 1

    def test_detects_windows_path_traversal(self):
        """
        Validates detection of Windows-style path traversal.
        """
        rule = PathTraversalRule()
        data = {
            'url': ["/download?file=..\\..\\windows\\win.ini", "/file.txt"],
            'ip_origen': [ATTACKER_IP, "192.0.2.2"],
            'status': ["FAIL", "SUCCESS"]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "PathTraversalRule.evaluate() returned None for Windows patterns"
        assert len(anomalies) == 1


class TestWebAttackRule:
    """Test generic web attack detection from parser flags."""

    def test_detects_parser_flagged_attacks(self):
        """
        Validates detection using attack_types from parser.
        """
        rule = WebAttackRule()
        data = {
            'url': ["/test", "/api", "/admin"],
            'ip_origen': ["192.0.2.1"] * 3,
            'status': ["FAIL"] * 3,
            'attack_types': [None, ['sql_injection', 'xss'], None]
        }
        df = pd.DataFrame(data)

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "WebAttackRule.evaluate() returned None"
        assert len(anomalies) == 1
        assert "sql_injection" in anomalies.iloc[0]['reason']
        assert "xss" in anomalies.iloc[0]['reason']

    def test_empty_dataframe(self):
        """
        Validates graceful handling of empty DataFrame.
        """
        rule = WebAttackRule()
        df = pd.DataFrame()

        anomalies = rule.evaluate(df)

        assert anomalies is not None, "WebAttackRule.evaluate() returned None for empty DataFrame"
        assert anomalies.empty


class TestFormatAutoDetection:
    """Test automatic log format detection."""

    def test_detects_syslog_format(self, tmp_path):
        """
        Validates auto-detection of syslog format.
        """
        log_file = tmp_path / "auth.log"
        log_file.write_text("Oct 11 10:00:00 server sshd[123]: Failed password for root from 192.0.2.1")

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert parser.active_parser is not None, "Auto-detection failed: active_parser is None for syslog"
        assert parser.detected_format == AuthLogParser.LOG_FORMAT_SYSLOG

    def test_detects_web_log_format(self, tmp_path):
        """
        Validates auto-detection of web log format.
        """
        log_file = tmp_path / "access.log"
        log_file.write_text('192.0.2.1 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 123 "-" "Mozilla/5.0"')

        parser = AuthLogParser(str(log_file))
        df = parser.parse()

        assert parser.active_parser is not None, "Auto-detection failed: active_parser is None for nginx web log"
        assert parser.detected_format == AuthLogParser.LOG_FORMAT_NGINX
