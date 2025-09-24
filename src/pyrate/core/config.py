"""
Configuration management for Pyrate scanner.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from pydantic import BaseModel, Field, validator
from dotenv import load_dotenv


class ScannerSettings(BaseModel):
    """Scanner-specific settings."""
    
    max_concurrent_requests: int = Field(default=10, ge=1, le=100)
    request_timeout: int = Field(default=30, ge=1, le=300)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    delay_between_requests: float = Field(default=0.1, ge=0.0, le=5.0)
    user_agent: str = Field(default="Pyrate/0.1.0 Security Scanner")
    follow_redirects: bool = Field(default=True)
    verify_ssl: bool = Field(default=True)


class PluginSettings(BaseModel):
    """Plugin configuration settings."""
    
    enabled_plugins: List[str] = Field(default_factory=list)
    disabled_plugins: List[str] = Field(default_factory=list)
    plugin_directories: List[Path] = Field(default_factory=list)
    
    @validator('plugin_directories', pre=True)
    def convert_to_paths(cls, v):
        if isinstance(v, list):
            return [Path(p) for p in v]
        return v


class ReportSettings(BaseModel):
    """Report generation settings."""
    
    default_format: str = Field(default="json", pattern=r"^(json|html|txt|xml)$")
    include_request_response: bool = Field(default=False)
    include_payloads: bool = Field(default=True)
    max_response_size: int = Field(default=1024 * 1024)  # 1MB
    output_directory: Path = Field(default=Path("./reports"))
    
    @validator('output_directory', pre=True)
    def convert_to_path(cls, v):
        return Path(v)


class LoggingSettings(BaseModel):
    """Logging configuration settings."""
    
    level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    format: str = Field(default="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_path: Optional[Path] = Field(default=None)
    max_file_size: int = Field(default=10 * 1024 * 1024)  # 10MB
    backup_count: int = Field(default=5)
    
    @validator('file_path', pre=True)
    def convert_to_path(cls, v):
        return Path(v) if v else None


class Config(BaseModel):
    """Main configuration class for Pyrate."""
    
    scanner: ScannerSettings = Field(default_factory=ScannerSettings)
    plugins: PluginSettings = Field(default_factory=PluginSettings)
    reports: ReportSettings = Field(default_factory=ReportSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    
    # Environment-specific settings
    debug: bool = Field(default=False)
    api_keys: Dict[str, str] = Field(default_factory=dict)
    
    class Config:
        """Pydantic configuration."""
        env_prefix = "PYRATE_"
        env_nested_delimiter = "__"
        case_sensitive = False
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Config":
        """
        Load configuration from file and environment variables.
        
        Args:
            config_path: Path to configuration file (YAML)
            
        Returns:
            Config instance
        """
        # Load environment variables from .env file if it exists
        load_dotenv()
        
        config_data = {}
        
        # Load from configuration file if provided
        if config_path and config_path.exists():
            with open(config_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
        
        # Override with environment variables
        env_config = cls._load_from_env()
        config_data.update(env_config)
        
        return cls(**config_data)
    
    @classmethod
    def _load_from_env(cls) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        env_config = {}
        
        # Basic settings
        if os.getenv("PYRATE_DEBUG"):
            env_config["debug"] = os.getenv("PYRATE_DEBUG").lower() == "true"
        
        # Scanner settings
        scanner_config = {}
        if os.getenv("PYRATE_SCANNER__MAX_CONCURRENT_REQUESTS"):
            scanner_config["max_concurrent_requests"] = int(
                os.getenv("PYRATE_SCANNER__MAX_CONCURRENT_REQUESTS")
            )
        if os.getenv("PYRATE_SCANNER__REQUEST_TIMEOUT"):
            scanner_config["request_timeout"] = int(
                os.getenv("PYRATE_SCANNER__REQUEST_TIMEOUT")
            )
        if os.getenv("PYRATE_SCANNER__USER_AGENT"):
            scanner_config["user_agent"] = os.getenv("PYRATE_SCANNER__USER_AGENT")
        
        if scanner_config:
            env_config["scanner"] = scanner_config
        
        # API Keys
        api_keys = {}
        for key, value in os.environ.items():
            if key.startswith("PYRATE_API_KEY_"):
                api_name = key.replace("PYRATE_API_KEY_", "").lower()
                api_keys[api_name] = value
        
        if api_keys:
            env_config["api_keys"] = api_keys
        
        return env_config
    
    @classmethod
    def create_sample(cls, output_path: Path) -> None:
        """
        Create a sample configuration file.
        
        Args:
            output_path: Path where to save the sample configuration
        """
        sample_config = {
            "scanner": {
                "max_concurrent_requests": 10,
                "request_timeout": 30,
                "retry_attempts": 3,
                "delay_between_requests": 0.1,
                "user_agent": "Pyrate/0.1.0 Security Scanner",
                "follow_redirects": True,
                "verify_ssl": True,
            },
            "plugins": {
                "enabled_plugins": ["sql_injection", "xss", "directory_traversal"],
                "disabled_plugins": [],
                "plugin_directories": ["./plugins"],
            },
            "reports": {
                "default_format": "json",
                "include_request_response": False,
                "include_payloads": True,
                "max_response_size": 1048576,
                "output_directory": "./reports",
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file_path": "./logs/pyrate.log",
                "max_file_size": 10485760,
                "backup_count": 5,
            },
            "debug": False,
            "api_keys": {
                "shodan": "your_shodan_api_key_here",
                "virustotal": "your_virustotal_api_key_here",
            },
        }
        
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            yaml.dump(sample_config, f, default_flow_style=False, indent=2)
    
    def save(self, output_path: Path) -> None:
        """
        Save current configuration to file.
        
        Args:
            output_path: Path where to save the configuration
        """
        # Ensure parent directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            yaml.dump(self.dict(), f, default_flow_style=False, indent=2)