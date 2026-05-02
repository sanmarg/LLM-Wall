FROM python:3.11-slim

LABEL maintainer="LLM Wall Team"
LABEL description="LLM Wall — Agentic Security Fabric for LLM Infrastructure"

# Create non-root user (Google security best practice)
RUN groupadd -r llmwall && useradd -r -g llmwall llmwall

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies (separate layer for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY llm_wall/ ./llm_wall/
COPY pyproject.toml .

# Create data directory for ledger persistence
RUN mkdir -p /app/data && chown -R llmwall:llmwall /app

USER llmwall

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

EXPOSE 8000

CMD ["python", "-m", "llm_wall.core.app"]
