"""
Pytest configuration and fixtures for Pyrate tests.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from pyrate.core.config import Config
from pyrate.models.scan_result import ScanResult, Vulnerability


@pytest.fixture
def sample_config():
    """Create a sample configuration for testing."""
    return Config()


@pytest.fixture
def sample_vulnerability():
    """Create a sample vulnerability for testing."""
    return Vulnerability(
        title="Test Vulnerability",
        url="https://example.com/vulnerable",
        severity="HIGH",
        description="This is a test vulnerability",
        recommendation="Fix the test vulnerability",
        plugin_name="test_plugin",
        plugin_category="Test",
        payload="test_payload",
    )


@pytest.fixture
def sample_scan_result(sample_vulnerability):
    """Create a sample scan result for testing."""
    scan_result = ScanResult(
        target="https://example.com",
        vulnerabilities=[sample_vulnerability],
        scan_info={
            "scanner_version": "0.1.0",
            "target_url": "https://example.com",
            "plugins_used": ["test_plugin"],
        }
    )
    return scan_result


@pytest.fixture
def mock_http_client():
    """Create a mock HTTP client for testing."""
    client = AsyncMock()
    
    # Mock response
    mock_response = AsyncMock()
    mock_response.status = 200
    mock_response.text.return_value = "Mock response content"
    mock_response.read.return_value = b"Mock response content"
    
    # Setup context manager behavior
    client.get.return_value.__aenter__.return_value = mock_response
    client.post.return_value.__aenter__.return_value = mock_response
    
    return client


@pytest.fixture
def temp_config_file(tmp_path):
    """Create a temporary configuration file for testing."""
    config_file = tmp_path / "test_config.yaml"
    config_content = """
scanner:
  max_concurrent_requests: 5
  request_timeout: 10
  user_agent: "Test Agent"

plugins:
  enabled_plugins: ["test_plugin"]
  disabled_plugins: []

reports:
  default_format: "json"
  output_directory: "./test_reports"

logging:
  level: "DEBUG"
"""
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def temp_output_dir(tmp_path):
    """Create a temporary output directory for testing."""
    output_dir = tmp_path / "test_output"
    output_dir.mkdir()
    return output_dir