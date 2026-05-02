# LLM Wall 🛡️ Agentic Security Fabric for LLM Infrastructure

> AI-native semantic firewall that intercepts, analyses and blocks out of scope prompts by user preventing misuse of tokens, and audits every LLM
> call using multi-agent Guardian analysis, MARL adaptive defense, Sentinel
> threat-intel mesh, and a blockchain audit ledger.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)](https://fastapi.tiangolo.com)
[![React 18](https://img.shields.io/badge/React-18-61dafb)](https://react.dev)

---

## Architecture

```
Client → NGINX → FastAPI Proxy
                    ├── Guardian Engine (4 parallel agents)
                    │     ├── Intent Agent     (LLM-based)
                    │     ├── Injection Agent  (regex + 27 patterns)
                    │     ├── CoT Inspector    (multi-turn analysis)
                    │     └── Risk Scorer      (weighted aggregation)
                    ├── MARL Engine (4 Q-learning agents, consensus vote)
                    ├── A2A Bus (pub/sub threat signals)
                    ├── MCP Broker (tool-call gating)
                    ├── Sentinel Node (IOC store + HTTP gossip mesh)
                    └── Blockchain Ledger (SHA-256 PoW + Merkle tree)
```

## Quick Start

### 1. Prerequisites

- Python 3.11+
- Node.js 20+
- [Ollama](https://ollama.ai) running locally (pull `llama3.2:3b`)

```bash
ollama pull llama3.2:3b
```

### 2. Setup

```bash
# Clone and enter the project
cd "d:\Devops\LLM Wall"

# Copy and edit environment config
cp .env.example .env
# Edit .env: add OPENAI_API_KEY, GEMINI_API_KEY, NVIDIA_API_KEY as needed

# Create Python virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS/Linux

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Run Backend

```bash
# From project root (with venv activated)
python -m llm_wall.core.app
```

Backend available at: **http://localhost:8000**
- Swagger UI: http://localhost:8000/docs
- Health: http://localhost:8000/health

### 4. Run Dashboard

```bash
cd dashboard
npm install
npm run dev
```

Dashboard at: **http://localhost:5173**

### 5. Docker Compose (all-in-one)

```bash
cp .env.example .env
# Edit .env with your API keys
docker compose up --build
```

- API: http://localhost:8000
- Dashboard: http://localhost:5173
- NGINX: http://localhost:80

---

## Supported LLM Providers

| Provider | Model | Key Env Var |
|---|---|---|
| Ollama (local) | `llama3.2:3b` (configurable) | None |
| OpenAI | `gpt-4o-mini` (configurable) | `OPENAI_API_KEY` |
| Google Gemini | `gemini-1.5-flash` | `GEMINI_API_KEY` |
| NVIDIA NIM | Kimi 2.5 / Mistral | `NVIDIA_API_KEY` |

Set `GUARDIAN_ANALYSIS_PROVIDER=ollama|openai|gemini|nvidia` to control which
LLM powers the Guardian classification agents.

---

## Using as a Proxy

LLM Wall is an **OpenAI-compatible drop-in proxy**. Point your existing client
at `http://localhost:8000` and add the provider header:

```python
import openai

client = openai.OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="not-needed",
    default_headers={"X-LLM-Provider": "ollama"},  # or openai/gemini/nvidia
)

response = client.chat.completions.create(
    model="llama3.2:3b",
    messages=[{"role": "user", "content": "Hello!"}],
)
```

Blocked requests return **HTTP 403** with a JSON body:
```json
{
  "error": {
    "type": "security_block",
    "risk_score": 87,
    "category": "prompt_injection",
    "explanation": "...",
    "request_id": "..."
  }
}
```

---

## Security Testing

```bash
# Run the built-in injection test suite (10 tests)
python scripts/test_injection.py --url http://localhost:8000

# Verify blockchain integrity
python scripts/verify_ledger.py --path ./data/ledger.json

# Run unit tests
pytest llm_wall/tests/ -v --cov=llm_wall
```

---

## Configuration Reference

All settings are in `.env`. Key variables:

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_ANALYSIS_PROVIDER` | `ollama` | LLM for Guardian agents |
| `GUARDIAN_RISK_THRESHOLD_BLOCK` | `75` | Score ≥ threshold → BLOCK |
| `GUARDIAN_RISK_THRESHOLD_QUARANTINE` | `50` | Score ≥ threshold → QUARANTINE |
| `SENTINEL_PEERS` | `""` | Comma-separated peer URLs |
| `LEDGER_DIFFICULTY` | `2` | Blockchain PoW difficulty 1-5 |
| `MARL_EPSILON` | `0.2` | MARL exploration rate |


---
