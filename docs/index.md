---
title: LLM Wall — Zero-Trust LLM Security Proxy
---

# LLM Wall

**Centralized Secure LLM Proxy** — Zero-Trust Security Layer for LLM APIs

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11+-blue)](https://python.org)
[![Coral](https://img.shields.io/badge/Coral-0.4.1-8A2BE2)](https://coral-ai.com)

> Control *who*, *how*, and *why* AI is used inside your organization.  
> Built with [Coral](https://coral-ai.com) for cross-source security investigation.

---

## What is LLM Wall?

An **open-source security proxy** that sits between your applications and LLM providers (OpenAI, Ollama, Gemini, NVIDIA). Every prompt is inspected by a multi-agent security engine before reaching the provider.

## Key Features

- 🧠 **Multi-agent threat detection** — 5 specialized agents analyze every prompt
- 🚫 **Zero-trust validation** — block prompt injection, jailbreaking, data exfiltration
- 🧾 **Immutable audit logs** — blockchain-backed ledger for non-repudiation
- 🌐 **Distributed threat intel** — peer-to-peer Sentinel mesh
- 🤖 **Adaptive decision engine** — Multi-Agent Reinforcement Learning (MARL)
- 🐚 **Coral SQL investigation** — cross-source threat hunting via Coral
- 🧬 **Auto-evolving patterns** — regex synthesis from org-specific data
- 🧩 **MCP tool support** — 6 Model Context Protocol tools

## Coral Integration (Hackathon Submission)

LLM Wall integrates [Coral](https://coral-ai.com) — the SQL query layer for APIs and databases — across five subsystems:

| Subsystem | Purpose | Coral Queries |
| :--- | :--- | :--- |
| IncidentInvestigator | Auto-investigate threats via A2A bus | GitHub, Sentry, Slack, PagerDuty, Datadog |
| PatternHunter | Discover org-specific attack patterns | GitHub repos, issues, comments, Notion, Slack |
| Honeypot Generator | Deploy decoy prompts as Sentinel IOCs | GitHub repos, issues, Notion, Slack |
| Policy Generator | Suggest Guardian thresholds from policies | Notion, GitHub issues, Confluence |
| MCP Tools | Ad-hoc SQL + catalog browsing | `coral_sql`, `coral_list_catalog`, `coral_search_catalog` |

All results stored on an **immutable blockchain ledger** for audit trail integrity.

## Architecture

```text
                ┌────────────────────┐
                │   Client Apps      │
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │    LLM Wall        │
                └─────────┬──────────┘
                          │
        ┌─────────────────┼─────────────────┬──────────────────┐
        ▼                 ▼                 ▼                  ▼
 ┌────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐
 │ Guardian   │   │  Sentinel     │   │   Ledger     │   │   Coral    │
 └────────────┘   └──────────────┘   └──────────────┘   └────────────┘
        │                                                    │
        ▼                                                    ▼
 ┌────────────────────┐                           ┌────────────────────┐
 │ External LLM APIs  │                           │  GitHub / Slack    │
 └────────────────────┘                           │  Sentry / Notion   │
                                                  │  Confluence / PD   │
                                                  └────────────────────┘
```

## Quick Start

```bash
git clone https://github.com/sanmarg/LLM-Wall
cd LLM-Wall

python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -r requirements.txt
uvicorn llm_wall.core.app:app --reload --port 9876
```

Then open the dashboard at `http://localhost:9876/dashboard` or use the OpenAI SDK:

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:9876/v1", api_key="internal-app-token")
print(client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": "Explain DevOps"}]).choices[0].message.content)
```

## Test Suite

```bash
python test_e2e.py   # 63 E2E tests covering all Coral endpoints
python test_imports.py  # Import verification
```

## Links

- **GitHub**: [https://github.com/sanmarg/LLM-Wall](https://github.com/sanmarg/LLM-Wall)
- **Coral**: [https://coral-ai.com](https://coral-ai.com)
- **MCP Specification**: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)
