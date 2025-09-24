"""Tests for the CLI module."""

from click.testing import CliRunner

from pyrate.cli import cli


def test_cli_version():
    """Test that the CLI shows version information."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


def test_info_command():
    """Test the info command."""
    runner = CliRunner()
    result = runner.invoke(cli, ["info"])
    assert result.exit_code == 0
    assert "Pyrate" in result.output
    assert "0.1.0" in result.output


def test_scan_command():
    """Test the scan command with a mock URL."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "http://example.com"])
    assert result.exit_code == 0
    assert "Scanning http://example.com" in result.output


def test_scan_command_with_verbose():
    """Test the scan command with verbose flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--verbose", "scan", "http://example.com"])
    assert result.exit_code == 0
    assert "Starting vulnerability scan" in result.output
