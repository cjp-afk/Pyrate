"""Tests for the config module."""

from pathlib import Path

from pyrate.config import Config, ScanConfig, load_config


def test_scan_config_defaults():
    """Test ScanConfig with default values."""
    config = ScanConfig()
    assert config.timeout == 30
    assert config.max_redirects == 5
    assert config.threads == 1
    assert config.delay == 0.0
    assert "Pyrate" in config.user_agent


def test_config_defaults():
    """Test Config with default values."""
    config = Config()
    assert config.scan.timeout == 30
    assert config.output_dir == Path("./reports")
    assert config.log_level == "INFO"


def test_load_config_from_environment(monkeypatch):
    """Test loading configuration from environment variables."""
    monkeypatch.setenv("PYRATE_TIMEOUT", "60")
    monkeypatch.setenv("PYRATE_THREADS", "4")
    monkeypatch.setenv("PYRATE_DELAY", "1.5")
    monkeypatch.setenv("PYRATE_LOG_LEVEL", "debug")

    config = load_config()

    assert config.scan.timeout == 60
    assert config.scan.threads == 4
    assert config.scan.delay == 1.5
    assert config.log_level == "DEBUG"


def test_load_config_defaults():
    """Test loading configuration with defaults."""
    config = load_config()

    assert config.scan.timeout == 30
    assert config.scan.threads == 1
    assert config.log_level == "INFO"
