"""
Tests for configuration management.
"""

import os
import pytest
from pathlib import Path

from pyrate.core.config import Config, ScannerSettings, PluginSettings


class TestConfig:
    """Test configuration loading and validation."""
    
    def test_default_config(self):
        """Test default configuration values."""
        config = Config()
        
        assert config.scanner.max_concurrent_requests == 10
        assert config.scanner.request_timeout == 30
        assert config.scanner.user_agent == "Pyrate/0.1.0 Security Scanner"
        assert config.plugins.enabled_plugins == []
        assert config.reports.default_format == "json"
        assert config.logging.level == "INFO"
    
    def test_load_from_file(self, temp_config_file):
        """Test loading configuration from file."""
        config = Config.load(temp_config_file)
        
        assert config.scanner.max_concurrent_requests == 5
        assert config.scanner.request_timeout == 10
        assert config.scanner.user_agent == "Test Agent"
        assert config.plugins.enabled_plugins == ["test_plugin"]
        assert config.reports.default_format == "json"
        assert config.logging.level == "DEBUG"
    
    def test_load_from_env(self, monkeypatch):
        """Test loading configuration from environment variables."""
        monkeypatch.setenv("PYRATE_DEBUG", "true")
        monkeypatch.setenv("PYRATE_SCANNER__MAX_CONCURRENT_REQUESTS", "20")
        monkeypatch.setenv("PYRATE_SCANNER__USER_AGENT", "Custom Agent")
        monkeypatch.setenv("PYRATE_API_KEY_TEST", "test_api_key")
        
        config = Config.load()
        
        assert config.debug is True
        assert config.scanner.max_concurrent_requests == 20
        assert config.scanner.user_agent == "Custom Agent"
        assert config.api_keys["test"] == "test_api_key"
    
    def test_create_sample_config(self, temp_output_dir):
        """Test creating sample configuration file."""
        config_path = temp_output_dir / "sample_config.yaml"
        
        Config.create_sample(config_path)
        
        assert config_path.exists()
        
        # Load the created config and verify it's valid
        config = Config.load(config_path)
        assert isinstance(config, Config)
    
    def test_save_config(self, temp_output_dir):
        """Test saving configuration to file."""
        config = Config()
        config.debug = True
        config.scanner.max_concurrent_requests = 15
        
        config_path = temp_output_dir / "saved_config.yaml"
        config.save(config_path)
        
        assert config_path.exists()
        
        # Load the saved config and verify values
        loaded_config = Config.load(config_path)
        assert loaded_config.debug is True
        assert loaded_config.scanner.max_concurrent_requests == 15


class TestScannerSettings:
    """Test scanner settings validation."""
    
    def test_valid_settings(self):
        """Test valid scanner settings."""
        settings = ScannerSettings(
            max_concurrent_requests=5,
            request_timeout=60,
            retry_attempts=2,
            delay_between_requests=0.5,
        )
        
        assert settings.max_concurrent_requests == 5
        assert settings.request_timeout == 60
        assert settings.retry_attempts == 2
        assert settings.delay_between_requests == 0.5
    
    def test_invalid_concurrent_requests(self):
        """Test invalid concurrent requests value."""
        with pytest.raises(ValueError):
            ScannerSettings(max_concurrent_requests=0)
        
        with pytest.raises(ValueError):
            ScannerSettings(max_concurrent_requests=101)
    
    def test_invalid_timeout(self):
        """Test invalid timeout value."""
        with pytest.raises(ValueError):
            ScannerSettings(request_timeout=0)
        
        with pytest.raises(ValueError):
            ScannerSettings(request_timeout=301)


class TestPluginSettings:
    """Test plugin settings validation."""
    
    def test_valid_plugin_settings(self):
        """Test valid plugin settings."""
        settings = PluginSettings(
            enabled_plugins=["plugin1", "plugin2"],
            disabled_plugins=["plugin3"],
            plugin_directories=[Path("./plugins")],
        )
        
        assert "plugin1" in settings.enabled_plugins
        assert "plugin3" in settings.disabled_plugins
        assert Path("./plugins") in settings.plugin_directories
    
    def test_path_conversion(self):
        """Test automatic path conversion."""
        settings = PluginSettings(
            plugin_directories=["./plugins", "/opt/plugins"]
        )
        
        assert all(isinstance(p, Path) for p in settings.plugin_directories)