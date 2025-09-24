"""
Base plugin model for Pyrate vulnerability scanner.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from .scan_result import Vulnerability


class PluginMetadata(BaseModel):
    """Metadata for a plugin."""
    
    name: str
    description: str
    category: str
    risk_level: str  # LOW, MEDIUM, HIGH
    version: str = "1.0.0"
    author: str = "Unknown"
    references: List[str] = []
    tags: List[str] = []


class BasePlugin(ABC):
    """
    Abstract base class for all vulnerability scanning plugins.
    """
    
    def __init__(self):
        """Initialize the plugin."""
        self._metadata = self._get_metadata()
    
    @property
    def name(self) -> str:
        """Get plugin name."""
        return self._metadata.name
    
    @property
    def description(self) -> str:
        """Get plugin description."""
        return self._metadata.description
    
    @property
    def category(self) -> str:
        """Get plugin category."""
        return self._metadata.category
    
    @property
    def risk_level(self) -> str:
        """Get plugin risk level."""
        return self._metadata.risk_level
    
    @property
    def version(self) -> str:
        """Get plugin version."""
        return self._metadata.version
    
    @property
    def author(self) -> str:
        """Get plugin author."""
        return self._metadata.author
    
    @property
    def references(self) -> List[str]:
        """Get plugin references."""
        return self._metadata.references
    
    @property
    def tags(self) -> List[str]:
        """Get plugin tags."""
        return self._metadata.tags
    
    @abstractmethod
    def _get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.
        
        Returns:
            PluginMetadata instance
        """
        pass
    
    @abstractmethod
    async def run_async(self, target: str, http_client: Any) -> List[Vulnerability]:
        """
        Run the plugin asynchronously against a target.
        
        Args:
            target: Target URL to scan
            http_client: HTTP client for making requests
            
        Returns:
            List of vulnerabilities found
        """
        pass
    
    def run(self, target: str, http_client: Any) -> List[Vulnerability]:
        """
        Run the plugin synchronously against a target.
        
        Args:
            target: Target URL to scan
            http_client: HTTP client for making requests
            
        Returns:
            List of vulnerabilities found
        """
        import asyncio
        return asyncio.run(self.run_async(target, http_client))
    
    def validate_target(self, target: str) -> bool:
        """
        Validate if the target is suitable for this plugin.
        
        Args:
            target: Target URL to validate
            
        Returns:
            True if target is valid for this plugin
        """
        from urllib.parse import urlparse
        
        parsed = urlparse(target)
        return bool(parsed.scheme and parsed.netloc)
    
    def get_payloads(self) -> List[str]:
        """
        Get list of payloads used by this plugin.
        
        Returns:
            List of payload strings
        """
        return []
    
    def create_vulnerability(
        self,
        title: str,
        url: str,
        severity: str,
        description: str = "",
        recommendation: str = "",
        payload: str = "",
        request: Optional[str] = None,
        response: Optional[str] = None,
        evidence: Dict[str, Any] = None,
    ) -> Vulnerability:
        """
        Create a vulnerability instance with plugin information.
        
        Args:
            title: Vulnerability title
            url: URL where vulnerability was found
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            description: Detailed description
            recommendation: Recommendation for fixing
            payload: Payload used to find vulnerability
            request: HTTP request that found the vulnerability
            response: HTTP response that confirmed the vulnerability
            evidence: Additional evidence data
            
        Returns:
            Vulnerability instance
        """
        return Vulnerability(
            title=title,
            url=url,
            severity=severity,
            description=description,
            recommendation=recommendation,
            plugin_name=self.name,
            plugin_category=self.category,
            payload=payload,
            request=request,
            response=response,
            evidence=evidence or {},
        )