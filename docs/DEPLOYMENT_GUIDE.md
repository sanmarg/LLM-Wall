# LLM Wall — Deployment Guide

## Prerequisites

- Python 3.11+
- Coral CLI (v0.4.1+) — `curl -fsSL https://coral-ai.com/install | sh`
- Node.js 18+ (for dashboard)
- LLM provider API keys (OpenAI, Ollama, etc.)

## Local Development

```bash
git clone https://github.com/sanmarg/LLM-Wall
cd LLM-Wall
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
uvicorn llm_wall.core.app:app --reload --port 9876
```

## Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Open `http://localhost:9876/dashboard`

## Coral Source Setup

```bash
# List available sources
coral source discover

# Add a source (requires env vars)
coral source add github
coral source add sentry
coral source add slack

# Test
coral sql "SELECT DISTINCT schema_name FROM coral.tables"
```

## Environment Variables

| Variable | Description |
| :--- | :--- |
| `CORAL_BIN` | Path to coral binary |
| `CORAL_CONFIG_DIR` | Coral config directory |
| `GITHUB_TOKEN` | GitHub API token |
| `SENTRY_AUTH_TOKEN` | Sentry auth token |
| `SLACK_BOT_TOKEN` | Slack bot token |
| `OPENAI_API_KEY` | OpenAI API key |

## Production

For production deployment, use process manager (systemd/supervisor) or containerize:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["uvicorn", "llm_wall.core.app:app", "--host", "0.0.0.0", "--port", "9876"]
```

## Testing

```bash
python test_e2e.py    # 63 E2E tests
python test_imports.py # Import verification
```
