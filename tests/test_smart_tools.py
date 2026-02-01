"""
Tests for smart_tools.py - Verify smart filtering works correctly
"""

import json
import pytest
from unittest.mock import Mock, patch
import sys
from pathlib import Path

# Add parent to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orchestrator.agents.smart_tools import (
    _is_interesting,
    http_get_smart,
    http_batch_get_smart,
    test_sqli_smart,
    test_xss_smart,
    scan_for_vulns_comprehensive,
)


class TestIsInteresting:
    """Test the core filtering logic"""

    def test_normal_response_not_interesting(self):
        """Normal 200 OK should not be interesting"""
        is_int, reasons = _is_interesting(200, "Welcome to our website!")
        assert not is_int
        assert len(reasons) == 0

    def test_error_is_interesting(self):
        """HTTP errors should be interesting"""
        is_int, reasons = _is_interesting(404, "Not found")
        assert is_int
        assert "HTTP 404" in reasons

    def test_sql_keywords_interesting(self):
        """SQL keywords should be flagged"""
        is_int, reasons = _is_interesting(200, "SQL error: SELECT * FROM users")
        assert is_int
        assert "SQL keywords" in reasons

    def test_xss_vector_interesting(self):
        """XSS payloads should be flagged"""
        is_int, reasons = _is_interesting(200, "<script>alert(1)</script>")
        assert is_int
        assert "XSS vector" in reasons

    def test_admin_content_interesting(self):
        """Admin content should be flagged"""
        is_int, reasons = _is_interesting(200, "Admin Dashboard")
        assert is_int
        assert "admin content" in reasons

    def test_error_trace_interesting(self):
        """Error traces should be flagged"""
        is_int, reasons = _is_interesting(500, "Traceback: File app.py line 42")
        assert is_int
        assert "error trace" in reasons

    def test_sensitive_data_interesting(self):
        """Sensitive data keywords should be flagged"""
        is_int, reasons = _is_interesting(200, "password: admin123")
        assert is_int
        assert "sensitive data" in reasons


class TestHttpGetSmart:
    """Test smart HTTP GET filtering"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_skips_boring_response(self, mock_get):
        """Should skip normal 200 OK responses"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Welcome to our normal website"
        mock_get.return_value = mock_response

        result = http_get_smart(url="http://test.com", params_json=None)

        assert result["skipped"] is True
        assert result["status"] == 200
        assert "normal" in result["reason"].lower()

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_interesting_response(self, mock_get):
        """Should return responses with SQL keywords"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "SQL error: SELECT * FROM users failed"
        mock_get.return_value = mock_response

        result = http_get_smart(url="http://test.com/api/products", params_json=None)

        assert "skipped" not in result or not result["skipped"]
        assert result["status"] == 200
        assert "SQL keywords" in result["indicators"]
        assert "preview" in result

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_errors(self, mock_get):
        """Should return error responses"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_get.return_value = mock_response

        result = http_get_smart(url="http://test.com", params_json=None)

        assert result["status"] == 500
        assert "HTTP 500" in result["indicators"]


class TestHttpBatchGetSmart:
    """Test batch GET with filtering"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_filters_boring_responses(self, mock_get):
        """Should only return interesting responses from batch"""
        # Mock 3 responses: 2 boring, 1 with SQL
        responses = [
            Mock(status_code=200, text="Normal page 1"),
            Mock(status_code=200, text="SQL error in query"),
            Mock(status_code=200, text="Normal page 2"),
        ]
        mock_get.side_effect = responses

        urls = ["/page1", "/api/products", "/page2"]
        result = http_batch_get_smart(urls_json=json.dumps(urls))

        assert result["tested"] == 3
        assert result["interesting"] == 1
        assert result["skipped_boring"] == 2
        assert len(result["findings"]) == 1
        assert "SQL keywords" in result["findings"][0]["indicators"]

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_summary_when_nothing_interesting(self, mock_get):
        """Should return summary when all responses are boring"""
        mock_response = Mock(status_code=200, text="Normal content")
        mock_get.return_value = mock_response

        urls = ["/page1", "/page2", "/page3"]
        result = http_batch_get_smart(urls_json=json.dumps(urls))

        assert result["tested"] == 3
        assert result["interesting"] == 0
        assert "No vulnerabilities found" in result["summary"]


class TestSqliSmart:
    """Test SQLi testing with smart filtering"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_only_vulnerable_endpoints(self, mock_get):
        """Should only return endpoints with SQLi"""
        # Mock responses: first endpoint vulnerable, second not
        def side_effect(*args, **kwargs):
            url = args[0]
            if "/api/products" in url:
                return Mock(status_code=200, text="MySQL error: syntax error")
            return Mock(status_code=200, text="Normal response")

        mock_get.side_effect = side_effect

        endpoints = ["/api/products", "/api/users"]
        result = test_sqli_smart(endpoints_json=json.dumps(endpoints))

        assert result["vulnerable_count"] == 1
        assert len(result["vulnerable_endpoints"]) == 1
        assert result["vulnerable_endpoints"][0]["endpoint"] == "/api/products"

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_summary_when_no_sqli(self, mock_get):
        """Should return clean summary when no SQLi found"""
        mock_response = Mock(status_code=200, text="Normal response")
        mock_get.return_value = mock_response

        endpoints = ["/api/products", "/api/users"]
        result = test_sqli_smart(endpoints_json=json.dumps(endpoints))

        assert result["vulnerable"] == 0
        assert "No SQL injection found" in result["summary"]


class TestXssSmart:
    """Test XSS testing with smart filtering"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    @patch('orchestrator.agents.smart_tools.httpx.post')
    def test_detects_reflected_xss(self, mock_post, mock_get):
        """Should detect when XSS payload is reflected"""
        payload = "<script>alert(1)</script>"
        mock_response = Mock(status_code=200, text=f"Comment: {payload}")
        mock_get.return_value = mock_response

        endpoints = ["/api/comments"]
        result = test_xss_smart(endpoints_json=json.dumps(endpoints))

        assert result["vulnerable_count"] >= 1
        assert any(payload in v["payload"] for v in result["vulnerable_endpoints"])

    @patch('orchestrator.agents.smart_tools.httpx.get')
    @patch('orchestrator.agents.smart_tools.httpx.post')
    def test_returns_summary_when_no_xss(self, mock_post, mock_get):
        """Should return clean summary when no XSS found"""
        mock_response = Mock(status_code=200, text="Safe content")
        mock_get.return_value = mock_response
        mock_post.return_value = mock_response

        endpoints = ["/api/comments"]
        result = test_xss_smart(endpoints_json=json.dumps(endpoints))

        assert result["vulnerable"] == 0
        assert "No XSS found" in result["summary"]


class TestComprehensiveScan:
    """Test comprehensive vulnerability scanning"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_detects_multiple_vuln_types(self, mock_get):
        """Should detect SQLi, XSS, etc. when present"""
        def side_effect(*args, **kwargs):
            params = kwargs.get('params', {})

            # Check for SQLi payload
            if any("'" in str(v) for v in params.values()):
                return Mock(status_code=200, text="SQL syntax error")

            # Check for XSS payload
            if any("<script>" in str(v) for v in params.values()):
                return Mock(status_code=200, text="<script>alert(1)</script>")

            return Mock(status_code=200, text="Normal")

        mock_get.side_effect = side_effect

        endpoints = ["/api/products"]
        result = scan_for_vulns_comprehensive(endpoints_json=json.dumps(endpoints))

        assert result["findings_count"] >= 1
        assert "findings" in result
        # Should have at least SQLi or XSS detected
        assert len(result["findings"].get("sqli", [])) > 0 or len(result["findings"].get("xss", [])) > 0

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_returns_summary_when_no_vulns(self, mock_get):
        """Should return clean summary when no vulnerabilities"""
        mock_response = Mock(status_code=200, text="Normal safe content")
        mock_get.return_value = mock_response

        endpoints = ["/api/products"]
        result = scan_for_vulns_comprehensive(endpoints_json=json.dumps(endpoints))

        assert result["findings"] == 0
        assert "No vulnerabilities found" in result["summary"]


class TestTokenSavings:
    """Test that smart tools actually save tokens"""

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_boring_response_much_smaller(self, mock_get):
        """Boring response should be tiny compared to full response"""
        # Simulate large HTML response
        large_html = "<!DOCTYPE html>" + "A" * 5000 + "</html>"
        mock_response = Mock(status_code=200, text=large_html)
        mock_get.return_value = mock_response

        result = http_get_smart(url="http://test.com", params_json=None)

        # Result should be tiny (just status + skip message)
        result_str = json.dumps(result)
        assert len(result_str) < 150  # Much less than 5000!

    @patch('orchestrator.agents.smart_tools.httpx.get')
    def test_interesting_response_still_truncated(self, mock_get):
        """Even interesting responses should be truncated"""
        large_response = "SQL error: " + "A" * 5000
        mock_response = Mock(status_code=200, text=large_response)
        mock_get.return_value = mock_response

        result = http_get_smart(url="http://test.com", params_json=None)

        # Should have preview but truncated
        assert "preview" in result
        assert len(result["preview"]) < 150  # Truncated!


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
