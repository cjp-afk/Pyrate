"""
Logging configuration for Pyrate vulnerability scanner.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional

from rich.logging import RichHandler


def setup_logging(
    level: str = "INFO",
    log_file: Optional[Path] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    format_string: Optional[str] = None,
) -> None:
    """
    Setup logging configuration for Pyrate.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (None for console only)
        max_file_size: Maximum log file size in bytes
        backup_count: Number of backup log files to keep
        format_string: Custom format string for log messages
    """
    # Convert string level to logging constant
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Default format
    if format_string is None:
        format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Setup rich console handler for colored output
    console_handler = RichHandler(
        rich_tracebacks=True,
        tracebacks_show_locals=True,
        show_time=False,  # Rich handler shows time by default
        show_path=False,
    )
    console_handler.setLevel(numeric_level)
    
    # Use a simpler format for console output
    console_format = logging.Formatter("%(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(console_format)
    root_logger.addHandler(console_handler)
    
    # Setup file handler if log file is specified
    if log_file:
        # Ensure log directory exists
        log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Use rotating file handler to manage log file size
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file,
            maxBytes=max_file_size,
            backupCount=backup_count,
            encoding='utf-8',
        )
        file_handler.setLevel(numeric_level)
        
        # Use detailed format for file output
        file_format = logging.Formatter(format_string)
        file_handler.setFormatter(file_format)
        root_logger.addHandler(file_handler)
    
    # Set specific logger levels for third-party libraries
    logging.getLogger("aiohttp").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    # Log setup completion
    logger = logging.getLogger(__name__)
    logger.info(f"Logging setup complete - Level: {level}, File: {log_file}")


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_http_request(
    logger: logging.Logger,
    method: str,
    url: str,
    status_code: Optional[int] = None,
    response_time: Optional[float] = None,
) -> None:
    """
    Log HTTP request details.
    
    Args:
        logger: Logger instance to use
        method: HTTP method
        url: Request URL
        status_code: Response status code
        response_time: Response time in seconds
    """
    if status_code and response_time:
        logger.debug(f"{method} {url} -> {status_code} ({response_time:.2f}s)")
    else:
        logger.debug(f"{method} {url}")


def log_vulnerability_found(
    logger: logging.Logger,
    vulnerability_title: str,
    url: str,
    severity: str,
    plugin_name: str,
) -> None:
    """
    Log when a vulnerability is found.
    
    Args:
        logger: Logger instance to use
        vulnerability_title: Title of the vulnerability
        url: URL where vulnerability was found
        severity: Severity level
        plugin_name: Name of the plugin that found the vulnerability
    """
    logger.info(f"[{severity}] {vulnerability_title} found at {url} by {plugin_name}")


def log_scan_progress(
    logger: logging.Logger,
    message: str,
    current: int,
    total: int,
) -> None:
    """
    Log scan progress.
    
    Args:
        logger: Logger instance to use
        message: Progress message
        current: Current progress
        total: Total items
    """
    percentage = (current / total) * 100 if total > 0 else 0
    logger.info(f"{message} ({current}/{total}, {percentage:.1f}%)")