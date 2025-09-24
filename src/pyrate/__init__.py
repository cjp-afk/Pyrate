"""
Pyrate - A web app vulnerability scanner.

A production-ready vulnerability scanner for web applications
with comprehensive reporting and plugin architecture.
"""

__version__ = "0.1.0"
__author__ = "Pyrate Team"
__email__ = "pyrate@example.com"

from .core.scanner import Scanner
from .core.config import Config

__all__ = ["Scanner", "Config", "__version__"]
