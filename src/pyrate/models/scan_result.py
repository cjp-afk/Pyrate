"""
Scan result models for Pyrate vulnerability scanner.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Vulnerability(BaseModel):
    """Represents a discovered vulnerability."""
    
    title: str = Field(..., description="Vulnerability title")
    url: str = Field(..., description="URL where vulnerability was found")
    severity: str = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)")
    description: str = Field(default="", description="Detailed description")
    recommendation: str = Field(default="", description="Recommendation for fixing")
    plugin_name: str = Field(..., description="Name of plugin that found this vulnerability")
    plugin_category: str = Field(..., description="Category of the plugin")
    
    # Technical details
    payload: str = Field(default="", description="Payload used to find vulnerability")
    request: Optional[str] = Field(default=None, description="HTTP request")
    response: Optional[str] = Field(default=None, description="HTTP response")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Additional evidence")
    
    # Metadata
    timestamp: datetime = Field(default_factory=datetime.now, description="When vulnerability was found")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence level (0.0-1.0)")
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class ScanResult(BaseModel):
    """Represents the complete result of a vulnerability scan."""
    
    target: str = Field(..., description="Target URL that was scanned")
    timestamp: datetime = Field(default_factory=datetime.now, description="When scan was performed")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="List of vulnerabilities found")
    scan_info: Dict[str, Any] = Field(default_factory=dict, description="Scan metadata and configuration")
    
    # Statistics
    @property
    def total_vulnerabilities(self) -> int:
        """Get total number of vulnerabilities."""
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        """Get number of critical vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == "CRITICAL"])
    
    @property
    def high_count(self) -> int:
        """Get number of high severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == "HIGH"])
    
    @property
    def medium_count(self) -> int:
        """Get number of medium severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == "MEDIUM"])
    
    @property
    def low_count(self) -> int:
        """Get number of low severity vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == "LOW"])
    
    @property
    def info_count(self) -> int:
        """Get number of informational vulnerabilities."""
        return len([v for v in self.vulnerabilities if v.severity == "INFO"])
    
    @property
    def severity_breakdown(self) -> Dict[str, int]:
        """Get breakdown of vulnerabilities by severity."""
        return {
            "CRITICAL": self.critical_count,
            "HIGH": self.high_count,
            "MEDIUM": self.medium_count,
            "LOW": self.low_count,
            "INFO": self.info_count,
        }
    
    def get_vulnerabilities_by_severity(self, severity: str) -> List[Vulnerability]:
        """
        Get vulnerabilities filtered by severity.
        
        Args:
            severity: Severity level to filter by
            
        Returns:
            List of vulnerabilities with the specified severity
        """
        return [v for v in self.vulnerabilities if v.severity == severity.upper()]
    
    def get_vulnerabilities_by_plugin(self, plugin_name: str) -> List[Vulnerability]:
        """
        Get vulnerabilities found by a specific plugin.
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            List of vulnerabilities found by the plugin
        """
        return [v for v in self.vulnerabilities if v.plugin_name == plugin_name]
    
    def get_vulnerabilities_by_category(self, category: str) -> List[Vulnerability]:
        """
        Get vulnerabilities filtered by plugin category.
        
        Args:
            category: Plugin category to filter by
            
        Returns:
            List of vulnerabilities from plugins in the specified category
        """
        return [v for v in self.vulnerabilities if v.plugin_category == category]
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """
        Add a vulnerability to the scan result.
        
        Args:
            vulnerability: Vulnerability to add
        """
        self.vulnerabilities.append(vulnerability)
    
    def sort_vulnerabilities_by_severity(self) -> None:
        """Sort vulnerabilities by severity (critical first)."""
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.vulnerabilities.sort(
            key=lambda v: (severity_order.get(v.severity, 5), v.title)
        )
    
    class Config:
        """Pydantic configuration."""
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }