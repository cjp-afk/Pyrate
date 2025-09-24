"""Tests for the scanner module."""

from unittest.mock import Mock, patch

from pyrate.scanner import ScanResult, WebScanner


def test_scan_result_creation():
    """Test ScanResult model creation."""
    result = ScanResult(
        url="http://example.com",
        status_code=200,
        vulnerabilities=["XSS"],
        warnings=["Missing CSP header"],
    )
    assert str(result.url) == "http://example.com/"
    assert result.status_code == 200
    assert "XSS" in result.vulnerabilities
    assert "Missing CSP header" in result.warnings


def test_web_scanner_initialization():
    """Test WebScanner initialization."""
    scanner = WebScanner(timeout=60)
    assert scanner.timeout == 60
    scanner.close()


@patch("httpx.Client.get")
def test_scan_url_success(mock_get):
    """Test successful URL scanning."""
    # Mock response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "text/html"}
    mock_response.text = "<html><title>Test</title><form></form></html>"
    mock_get.return_value = mock_response

    scanner = WebScanner()
    result = scanner.scan_url("http://example.com")

    assert result.status_code == 200
    assert str(result.url) == "http://example.com/"
    assert len(result.warnings) > 0  # Should have security header warnings

    scanner.close()


@patch("httpx.Client.get")
def test_scan_url_request_error(mock_get):
    """Test URL scanning with request error."""
    mock_get.side_effect = Exception("Connection failed")

    scanner = WebScanner()
    result = scanner.scan_url("http://example.com")

    assert result.status_code == 0
    assert len(result.vulnerabilities) > 0
    assert "Request failed" in result.vulnerabilities[0]

    scanner.close()


def test_context_manager():
    """Test WebScanner as context manager."""
    with WebScanner() as scanner:
        assert scanner.timeout == 30
