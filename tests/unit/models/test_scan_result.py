"""
Tests for scan result models.
"""

import pytest
from datetime import datetime

from pyrate.models.scan_result import ScanResult, Vulnerability


class TestVulnerability:
    """Test vulnerability model."""
    
    def test_create_vulnerability(self):
        """Test creating a vulnerability."""
        vuln = Vulnerability(
            title="Test Vulnerability",
            url="https://example.com/test",
            severity="HIGH",
            description="Test description",
            recommendation="Test recommendation",
            plugin_name="test_plugin",
            plugin_category="Test",
            payload="test_payload",
        )
        
        assert vuln.title == "Test Vulnerability"
        assert vuln.url == "https://example.com/test"
        assert vuln.severity == "HIGH"
        assert vuln.plugin_name == "test_plugin"
        assert vuln.confidence == 1.0
        assert isinstance(vuln.timestamp, datetime)
    
    def test_vulnerability_defaults(self):
        """Test vulnerability default values."""
        vuln = Vulnerability(
            title="Test",
            url="https://example.com",
            severity="LOW",
            plugin_name="test",
            plugin_category="Test",
        )
        
        assert vuln.description == ""
        assert vuln.recommendation == ""
        assert vuln.payload == ""
        assert vuln.request is None
        assert vuln.response is None
        assert vuln.evidence == {}
        assert vuln.confidence == 1.0
    
    def test_vulnerability_serialization(self, sample_vulnerability):
        """Test vulnerability serialization."""
        data = sample_vulnerability.dict()
        
        assert data["title"] == "Test Vulnerability"
        assert data["severity"] == "HIGH"
        assert "timestamp" in data
        assert isinstance(data["timestamp"], datetime)


class TestScanResult:
    """Test scan result model."""
    
    def test_create_scan_result(self):
        """Test creating a scan result."""
        result = ScanResult(
            target="https://example.com",
            scan_info={"test": "info"},
        )
        
        assert result.target == "https://example.com"
        assert result.scan_info == {"test": "info"}
        assert result.vulnerabilities == []
        assert isinstance(result.timestamp, datetime)
    
    def test_vulnerability_counts(self, sample_scan_result):
        """Test vulnerability count properties."""
        # Add vulnerabilities of different severities
        vulnerabilities = [
            Vulnerability(
                title="Critical Vuln",
                url="https://example.com/1",
                severity="CRITICAL",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="High Vuln",
                url="https://example.com/2",
                severity="HIGH",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Medium Vuln",
                url="https://example.com/3",
                severity="MEDIUM",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Low Vuln",
                url="https://example.com/4",
                severity="LOW",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Info Vuln",
                url="https://example.com/5",
                severity="INFO",
                plugin_name="test",
                plugin_category="Test",
            ),
        ]
        
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=vulnerabilities,
        )
        
        assert result.total_vulnerabilities == 5
        assert result.critical_count == 1
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
        assert result.info_count == 1
    
    def test_severity_breakdown(self):
        """Test severity breakdown property."""
        vulnerabilities = [
            Vulnerability(
                title="Critical Vuln 1",
                url="https://example.com/1",
                severity="CRITICAL",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Critical Vuln 2",
                url="https://example.com/2",
                severity="CRITICAL",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="High Vuln",
                url="https://example.com/3",
                severity="HIGH",
                plugin_name="test",
                plugin_category="Test",
            ),
        ]
        
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=vulnerabilities,
        )
        
        breakdown = result.severity_breakdown
        assert breakdown["CRITICAL"] == 2
        assert breakdown["HIGH"] == 1
        assert breakdown["MEDIUM"] == 0
        assert breakdown["LOW"] == 0
        assert breakdown["INFO"] == 0
    
    def test_get_vulnerabilities_by_severity(self):
        """Test filtering vulnerabilities by severity."""
        vulnerabilities = [
            Vulnerability(
                title="Critical Vuln",
                url="https://example.com/1",
                severity="CRITICAL",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="High Vuln",
                url="https://example.com/2",
                severity="HIGH",
                plugin_name="test",
                plugin_category="Test",
            ),
        ]
        
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=vulnerabilities,
        )
        
        critical_vulns = result.get_vulnerabilities_by_severity("CRITICAL")
        assert len(critical_vulns) == 1
        assert critical_vulns[0].title == "Critical Vuln"
        
        high_vulns = result.get_vulnerabilities_by_severity("high")  # Test case insensitive
        assert len(high_vulns) == 1
        assert high_vulns[0].title == "High Vuln"
    
    def test_get_vulnerabilities_by_plugin(self):
        """Test filtering vulnerabilities by plugin."""
        vulnerabilities = [
            Vulnerability(
                title="Vuln 1",
                url="https://example.com/1",
                severity="HIGH",
                plugin_name="plugin1",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Vuln 2",
                url="https://example.com/2",
                severity="MEDIUM",
                plugin_name="plugin2",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Vuln 3",
                url="https://example.com/3",
                severity="LOW",
                plugin_name="plugin1",
                plugin_category="Test",
            ),
        ]
        
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=vulnerabilities,
        )
        
        plugin1_vulns = result.get_vulnerabilities_by_plugin("plugin1")
        assert len(plugin1_vulns) == 2
        assert all(v.plugin_name == "plugin1" for v in plugin1_vulns)
    
    def test_add_vulnerability(self):
        """Test adding vulnerability to scan result."""
        result = ScanResult(target="https://example.com")
        assert result.total_vulnerabilities == 0
        
        vuln = Vulnerability(
            title="Test Vuln",
            url="https://example.com/test",
            severity="HIGH",
            plugin_name="test",
            plugin_category="Test",
        )
        
        result.add_vulnerability(vuln)
        assert result.total_vulnerabilities == 1
        assert result.vulnerabilities[0] == vuln
    
    def test_sort_vulnerabilities_by_severity(self):
        """Test sorting vulnerabilities by severity."""
        vulnerabilities = [
            Vulnerability(
                title="Low Vuln",
                url="https://example.com/1",
                severity="LOW",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Critical Vuln",
                url="https://example.com/2",
                severity="CRITICAL",
                plugin_name="test",
                plugin_category="Test",
            ),
            Vulnerability(
                title="Medium Vuln",
                url="https://example.com/3",
                severity="MEDIUM",
                plugin_name="test",
                plugin_category="Test",
            ),
        ]
        
        result = ScanResult(
            target="https://example.com",
            vulnerabilities=vulnerabilities,
        )
        
        result.sort_vulnerabilities_by_severity()
        
        # Should be sorted: CRITICAL, MEDIUM, LOW
        severities = [v.severity for v in result.vulnerabilities]
        assert severities == ["CRITICAL", "MEDIUM", "LOW"]