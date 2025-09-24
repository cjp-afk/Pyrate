"""Configuration management for Pyrate."""

import os
from pathlib import Path

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Configuration for vulnerability scans."""

    timeout: int = Field(default=30, description="Request timeout in seconds")
    max_redirects: int = Field(default=5, description="Maximum redirects to follow")
    user_agent: str = Field(
        default="Pyrate/0.1.0 (Security Scanner)", description="User agent string"
    )
    threads: int = Field(default=1, description="Number of concurrent threads")
    delay: float = Field(default=0.0, description="Delay between requests in seconds")


class Config(BaseModel):
    """Main configuration class."""

    scan: ScanConfig = Field(default_factory=ScanConfig)
    output_dir: Path = Field(default=Path("./reports"))
    log_level: str = Field(default="INFO")


def load_config(config_file: Path | None = None) -> Config:
    """Load configuration from file or environment variables."""
    if config_file and config_file.exists():
        # TODO: Implement config file loading (TOML/YAML)
        pass

    # Load from environment variables
    config = Config()

    if timeout := os.getenv("PYRATE_TIMEOUT"):
        config.scan.timeout = int(timeout)

    if threads := os.getenv("PYRATE_THREADS"):
        config.scan.threads = int(threads)

    if delay := os.getenv("PYRATE_DELAY"):
        config.scan.delay = float(delay)

    if log_level := os.getenv("PYRATE_LOG_LEVEL"):
        config.log_level = log_level.upper()

    return config
