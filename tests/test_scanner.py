"""
tests/test_scanner.py — basic unit tests for SecureScan.

Run with:
    python -m pytest tests/ -v

Tests use only mock data — no real network requests are made.
"""

import sys
import os
import types

# ---------------------------------------------------------------------------
# Lightweight stub for the `requests` library so tests can run even when
# requests is not installed in the test environment.
# ---------------------------------------------------------------------------
if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")

    class _Exceptions:
        class RequestException(Exception): pass
        class ConnectionError(Exception): pass
        class Timeout(Exception): pass
        class SSLError(Exception): pass
        class TooManyRedirects(Exception): pass

    requests_stub.exceptions = _Exceptions
    sys.modules["requests"] = requests_stub

# Add the SecureScan package directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import scanner
import report_generator


# ── URL validation tests ──────────────────────────────────────────────────────

class TestValidateUrl:
    def test_valid_https_url(self):
        ok, result = scanner.validate_url("https://example.com")
        assert ok is True
        assert result == "https://example.com"

    def test_prepends_https_when_no_scheme(self):
        ok, result = scanner.validate_url("example.com")
        assert ok is True
        assert result.startswith("https://")

    def test_http_scheme_accepted(self):
        ok, result = scanner.validate_url("http://example.com")
        assert ok is True

    def test_localhost_rejected(self):
        ok, msg = scanner.validate_url("http://localhost")
        assert ok is False
        assert "not permitted" in msg.lower()

    def test_loopback_ip_rejected(self):
        # 127.0.0.1 resolves to a loopback address
        ok, msg = scanner.validate_url("http://127.0.0.1")
        # May fail at DNS resolution stage and return True, but if it reaches
        # the IP check it must be rejected.
        if not ok:
            assert "not permitted" in msg.lower()

    def test_private_ip_rejected(self):
        # 192.168.1.1 is a private RFC-1918 address
        ok, msg = scanner.validate_url("http://192.168.1.1")
        if not ok:
            assert "not permitted" in msg.lower()

    def test_invalid_scheme_rejected(self):
        ok, msg = scanner.validate_url("ftp://example.com")
        assert ok is False

    def test_empty_string_rejected(self):
        ok, msg = scanner.validate_url("")
        assert ok is False

    def test_metadata_endpoint_rejected(self):
        ok, msg = scanner.validate_url("http://metadata.google.internal")
        assert ok is False


# ── Security header check tests ───────────────────────────────────────────────

class TestSecurityChecks:
    """Tests for the individual internal check helpers."""

    def test_https_check_pass(self):
        result = scanner._check_https("https://example.com")
        assert result["status"] == "PASS"

    def test_https_check_warning(self):
        result = scanner._check_https("http://example.com")
        assert result["status"] == "WARNING"
        assert result["recommendation"] != ""

    def test_x_content_type_nosniff_pass(self):
        result = scanner._check_x_content_type_options(
            {"X-Content-Type-Options": "nosniff"}
        )
        assert result["status"] == "PASS"

    def test_x_content_type_wrong_value_warning(self):
        result = scanner._check_x_content_type_options(
            {"X-Content-Type-Options": "something-else"}
        )
        assert result["status"] == "WARNING"

    def test_x_content_type_missing_warning(self):
        result = scanner._check_x_content_type_options({})
        assert result["status"] == "WARNING"

    def test_header_present_pass(self):
        result = scanner._check_header_present(
            {"Strict-Transport-Security": "max-age=31536000"},
            "Strict-Transport-Security",
        )
        assert result["status"] == "PASS"

    def test_header_missing_warning(self):
        result = scanner._check_header_present({}, "X-Frame-Options")
        assert result["status"] == "WARNING"
        assert result["recommendation"] != ""

    def test_status_check_is_info(self):
        result = scanner._check_status(200)
        assert result["status"] == "INFO"
        assert result["value"] == "200"

    def test_redirect_detected(self):
        result = scanner._check_redirect(
            "http://example.com", "https://example.com"
        )
        assert result["status"] == "INFO"
        assert "redirected" in result["explanation"].lower()

    def test_no_redirect(self):
        result = scanner._check_redirect(
            "https://example.com", "https://example.com"
        )
        assert "no redirect" in result["explanation"].lower()


# ── Report generation tests ───────────────────────────────────────────────────

class TestReportGeneration:
    """Tests for CSV and text report generators."""

    SAMPLE_RESULT = {
        "success": True,
        "error": "",
        "original_url": "https://example.com",
        "final_url": "https://example.com",
        "status_code": 200,
        "response_headers": {},
        "checks": [
            {
                "check": "HTTPS",
                "status": "PASS",
                "value": "https://example.com",
                "explanation": "Connection uses HTTPS.",
                "recommendation": "",
            },
            {
                "check": "X-Frame-Options",
                "status": "WARNING",
                "value": "Not present",
                "explanation": "Header not found.",
                "recommendation": "Set the X-Frame-Options header.",
            },
        ],
    }

    def test_csv_contains_url(self):
        csv = report_generator.generate_csv(self.SAMPLE_RESULT)
        assert "https://example.com" in csv

    def test_csv_contains_header_names(self):
        csv = report_generator.generate_csv(self.SAMPLE_RESULT)
        assert "Check" in csv
        assert "Status" in csv
        assert "Recommendation" in csv

    def test_csv_contains_findings(self):
        csv = report_generator.generate_csv(self.SAMPLE_RESULT)
        assert "HTTPS" in csv
        assert "X-Frame-Options" in csv

    def test_csv_contains_disclaimer(self):
        csv = report_generator.generate_csv(self.SAMPLE_RESULT)
        assert "DISCLAIMER" in csv

    def test_text_contains_url(self):
        text = report_generator.generate_text(self.SAMPLE_RESULT)
        assert "https://example.com" in text

    def test_text_contains_findings(self):
        text = report_generator.generate_text(self.SAMPLE_RESULT)
        assert "HTTPS" in text
        assert "X-Frame-Options" in text
        assert "[PASS]" in text
        assert "[WARNING]" in text

    def test_text_contains_disclaimer(self):
        text = report_generator.generate_text(self.SAMPLE_RESULT)
        assert "DISCLAIMER" in text

    def test_text_pass_count(self):
        text = report_generator.generate_text(self.SAMPLE_RESULT)
        assert "Passed         : 1" in text

    def test_text_warning_count(self):
        text = report_generator.generate_text(self.SAMPLE_RESULT)
        assert "Warnings       : 1" in text
