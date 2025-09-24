# Pyrate

[![CI](https://github.com/cjp-afk/Pyrate/workflows/CI/badge.svg)](https://github.com/cjp-afk/Pyrate/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

A production-ready web application vulnerability scanner built with Python and UV package manager.

## Features

- 🔍 **Comprehensive Scanning**: Multiple vulnerability detection plugins
- 🚀 **High Performance**: Asynchronous scanning with configurable concurrency
- 📊 **Multiple Report Formats**: JSON, HTML, XML, and plain text reports
- 🔧 **Extensible Plugin System**: Easy to add custom vulnerability checks
- 🐳 **Docker Support**: Containerized deployment ready
- 📈 **Production Ready**: Comprehensive logging, error handling, and monitoring
- 🛡️ **Security Focused**: Built with security best practices

## Quick Start

### Installation

#### Using UV (Recommended)

```bash
# Install UV if not already installed
pip install uv

# Clone the repository
git clone https://github.com/cjp-afk/Pyrate.git
cd Pyrate

# Install Pyrate
uv pip install -e .

# Or install with development dependencies
uv pip install -e ".[dev,test]"
```

#### Using Docker

```bash
# Build the Docker image
docker build -t pyrate .

# Run with Docker
docker run -v $(pwd)/reports:/app/reports pyrate scan https://example.com
```

### Basic Usage

```bash
# Show help
pyrate --help

# Generate sample configuration
pyrate init-config -o config.yaml

# Scan a target
pyrate scan https://example.com

# Scan with specific output format
pyrate scan https://example.com -f html -o report.html

# List available plugins
pyrate plugins

# Scan with specific plugins
pyrate scan https://example.com -p info_disclosure -p directory_traversal
```

## Configuration

Pyrate can be configured through:

1. **Configuration file** (YAML format)
2. **Environment variables**
3. **Command-line arguments**

### Sample Configuration

```yaml
scanner:
  max_concurrent_requests: 10
  request_timeout: 30
  user_agent: "Pyrate/0.1.0 Security Scanner"
  verify_ssl: true

plugins:
  enabled_plugins: ["info_disclosure", "directory_traversal"]
  plugin_directories: ["./plugins"]

reports:
  default_format: "json"
  output_directory: "./reports"

logging:
  level: "INFO"
  file_path: "./logs/pyrate.log"
```

### Environment Variables

```bash
export PYRATE_DEBUG=true
export PYRATE_SCANNER__MAX_CONCURRENT_REQUESTS=20
export PYRATE_SCANNER__USER_AGENT="Custom Scanner"
export PYRATE_API_KEY_SHODAN="your_api_key"
```

## Plugin Development

Create custom plugins by extending the `BasePlugin` class:

```python
from pyrate.models.plugin import BasePlugin, PluginMetadata
from pyrate.models.scan_result import Vulnerability

class CustomPlugin(BasePlugin):
    def _get_metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="custom_plugin",
            description="Custom vulnerability check",
            category="Custom",
            risk_level="MEDIUM",
        )
    
    async def run_async(self, target: str, http_client) -> List[Vulnerability]:
        # Implement your scanning logic here
        vulnerabilities = []
        # ... scanning logic ...
        return vulnerabilities
```

## Development

### Setup Development Environment

```bash
# Clone and setup
git clone https://github.com/cjp-afk/Pyrate.git
cd Pyrate

# Install with development dependencies
make install-dev

# Run tests
make test

# Format code
make format

# Run linting
make lint
```

### Project Structure

```
src/pyrate/
├── cli.py                 # Command-line interface
├── __init__.py           # Package initialization
├── core/                 # Core functionality
│   ├── config.py         # Configuration management
│   ├── scanner.py        # Main scanner logic
│   └── plugin_manager.py # Plugin management
├── models/               # Data models
│   ├── plugin.py         # Plugin base class
│   └── scan_result.py    # Scan result models
├── plugins/              # Built-in plugins
│   ├── info_disclosure.py
│   └── directory_traversal.py
├── reports/              # Report generation
│   └── generator.py
└── utils/                # Utility modules
    ├── http_client.py    # HTTP client wrapper
    └── logging.py        # Logging configuration
```

### Testing

```bash
# Run all tests
make test

# Run unit tests only
make test-quick

# Run integration tests
make test-integration

# Run with coverage
pytest --cov=pyrate --cov-report=html
```

## Docker Usage

### Building

```bash
# Build the image
docker build -t pyrate .

# Or use docker-compose
docker-compose build
```

### Running

```bash
# Run a scan
docker run -v $(pwd)/reports:/app/reports pyrate scan https://example.com

# Interactive mode
docker run -it pyrate bash

# With custom configuration
docker run -v $(pwd)/config:/app/config pyrate scan --config /app/config/custom.yaml https://example.com
```

## Production Deployment

### Using Docker Compose

```yaml
version: '3.8'
services:
  pyrate:
    build: .
    volumes:
      - ./reports:/app/reports
      - ./logs:/app/logs
      - ./config:/app/config
    environment:
      - PYRATE_LOGGING__LEVEL=INFO
      - PYRATE_REPORTS__OUTPUT_DIRECTORY=/app/reports
```

### Monitoring and Logging

- Structured logging with configurable levels
- Request/response logging for debugging
- Performance metrics tracking
- Health check endpoints (when running as service)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Workflow

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add/update tests
5. Run the test suite
6. Submit a pull request

## Security

If you discover a security vulnerability, please send an email to [security@pyrate.dev](mailto:security@pyrate.dev). All security vulnerabilities will be promptly addressed.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [UV](https://github.com/astral-sh/uv) for fast Python package management
- Uses [aiohttp](https://aiohttp.readthedocs.io/) for asynchronous HTTP requests
- Inspired by various open-source security scanning tools

## Roadmap

- [ ] Web interface for scan management
- [ ] API for integration with other tools
- [ ] More built-in vulnerability plugins
- [ ] Integration with popular security APIs
- [ ] Distributed scanning capabilities
- [ ] Machine learning-based vulnerability detection
