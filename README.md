# Pyrate

A web app vulnerability scanner built with Python and UV package manager.

## Features

- Command-line interface for easy scanning
- Basic security header checks
- CSRF token detection
- Configurable scanning parameters
- Extensible architecture for adding new vulnerability checks

## Installation

### Prerequisites

- Python 3.12+
- UV package manager

### Install UV

```bash
# Install UV
pip install uv
```

### Install Pyrate

```bash
# Clone the repository
git clone https://github.com/cjp-afk/Pyrate.git
cd Pyrate

# Install dependencies
uv sync

# Install in development mode
uv pip install -e .
```

## Usage

### Command Line Interface

```bash
# Basic scan
pyrate scan http://example.com

# Verbose output
pyrate --verbose scan http://example.com

# Save results to file
pyrate scan http://example.com --output results.txt

# Show version and info
pyrate --version
pyrate info
```

### Configuration

Configure Pyrate using environment variables:

```bash
export PYRATE_TIMEOUT=60          # Request timeout in seconds
export PYRATE_THREADS=4           # Number of concurrent threads  
export PYRATE_DELAY=1.0           # Delay between requests
export PYRATE_LOG_LEVEL=DEBUG     # Logging level
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
uv sync --dev

# Install pre-commit hooks
uv run pre-commit install
```

### Running Tests

```bash
# Run all tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=pyrate

# Run specific test file
uv run pytest tests/test_scanner.py
```

### Code Quality

```bash
# Format code
uv run black src/ tests/

# Lint code
uv run ruff src/ tests/

# Type checking
uv run mypy src/
```

### Project Structure

```
Pyrate/
├── src/
│   └── pyrate/
│       ├── __init__.py      # Package initialization
│       ├── cli.py           # Command-line interface
│       ├── scanner.py       # Core scanning functionality
│       └── config.py        # Configuration management
├── tests/                   # Test files
├── pyproject.toml          # Project configuration
├── README.md               # This file
├── LICENSE                 # Apache 2.0 License
└── .gitignore             # Git ignore patterns
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests and ensure they pass
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Security Disclaimer

This tool is for educational and authorized testing purposes only. Always ensure you have permission to scan target applications. The authors are not responsible for any misuse of this tool.
