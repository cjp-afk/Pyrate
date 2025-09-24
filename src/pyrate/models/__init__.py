"""Data models for Pyrate vulnerability scanner."""

from .plugin import BasePlugin
from .scan_result import ScanResult, Vulnerability

__all__ = ["BasePlugin", "ScanResult", "Vulnerability"]