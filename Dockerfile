# Multi-stage build for Pyrate vulnerability scanner
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install UV
RUN pip install uv

# Create non-root user
RUN useradd --create-home --shell /bin/bash pyrate

# Set work directory
WORKDIR /app

# Copy dependency files
COPY pyproject.toml ./
COPY README.md ./

# Install dependencies
RUN uv pip install --system -e .

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/pyrate/.local/bin:$PATH"

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --shell /bin/bash pyrate

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Set work directory
WORKDIR /app

# Copy application code
COPY --chown=pyrate:pyrate src/ ./src/
COPY --chown=pyrate:pyrate pyproject.toml ./
COPY --chown=pyrate:pyrate README.md ./

# Create directories
RUN mkdir -p /app/logs /app/reports /app/config && \
    chown -R pyrate:pyrate /app

# Switch to non-root user
USER pyrate

# Install the application
RUN pip install --user -e .

# Create sample configuration
RUN python -c "from pyrate.core.config import Config; Config.create_sample('config/pyrate-config.yaml')"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import pyrate; print('OK')" || exit 1

# Default command
CMD ["pyrate", "--help"]