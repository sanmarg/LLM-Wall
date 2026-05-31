# LLM Wall: Centralized Secure LLM Proxy

> **A Zero-Trust Security Layer for LLM APIs**
> Control *who*, *how*, and *why* AI is used inside your organization.
> Powered by [Coral](https://coral-ai.com) for cross-source security investigation.

---

## Coral Integration (Built with Coral)

LLM Wall uses **Coral** — the SQL query layer for APIs and databases — to power its threat investigation, pattern evolution, honeypot generation, and policy tuning subsystems. No data leaves your network; Coral runs entirely as a local CLI.

### 🔍 IncidentInvestigator
Subscribes to the A2A threat bus and automatically runs cross-source SQL queries (GitHub, Sentry, Slack, PagerDuty, Datadog) whenever a threat is detected or blocked. Results are stored on the blockchain ledger for an immutable audit trail.

### 🧬 PatternHunter
Queries your org's actual GitHub repos, Notion docs, and Slack channels via Coral SQL to find exposed prompts, internal terminology, and API key patterns — then uses an LLM to synthesise targeted regex patterns for the Guardian security engine.

### 🍯 Honeypot Generator
Reads real org data (private repo names, internal issue titles) through Coral, then generates deceptive decoy prompts that look like legitimate internal requests. Unique strings are registered as Sentinel IOCs — any request containing them is instantly flagged.

### ⚙️ Policy Generator
Queries Notion (security policies), Confluence (runbooks), and GitHub (incident reports) via Coral to understand your org's security posture, then uses an LLM to suggest optimal Guardian thresholds, critical categories, and fidelity rules.

### 🧩 MCP Tools
Three [Model Context Protocol](https://modelcontextprotocol.io) tools are registered:
- `coral_sql` — ad-hoc Coral SQL queries from MCP clients
- `coral_list_catalog` — list available Coral tables and schemas
- `coral_search_catalog` — full-text search across Coral's table catalog

### 📡 API Endpoints
All Coral subsystems are exposed via REST under `/api/coral/` (12 endpoints) and reflected in the live SSE dashboard stream.

---

## ❌ Problem

Today, LLM usage inside organizations is **largely ungoverned**:

* API keys are scattered across services
* No control over *what prompts are being sent*
* No enforcement of **business purpose**
* No protection against:
  * Prompt injection
  * Data exfiltration
  * Misuse (e.g., non-business queries)
* No audit trail or accountability

👉 Result: **Security, compliance, and cost risks grow silently**

---

## 💡 Solution

**LLM Wall** acts as a **centralized proxy layer** between your applications and LLM providers.

It enforces:

* 🔐 **Zero-trust prompt validation**
* 🎯 **Purpose-based access control**
* 🧠 **Multi-agent threat detection**
* 📊 **Risk scoring + decision engine**
* 🧾 **Immutable audit logging** (blockchain-backed)
* 🌐 **Distributed threat intelligence** (Sentinel mesh)
* 🐚 **Cross-source investigation** (Coral-powered)

---

## 🧠 Core Idea

> **LLM access should be governed like production database access.**

---

## 🏗️ Architecture

```text
                ┌────────────────────┐
                │   Client Apps      │
                │ (ML / Backend APIs)│
                └─────────┬──────────┘
                          │
                          ▼
                ┌────────────────────┐
                │    LLM Wall        │
                │  (FastAPI Proxy)   │
                └─────────┬──────────┘
                          │
        ┌─────────────────┼─────────────────┬──────────────────┐
        ▼                 ▼                 ▼                  ▼
 ┌────────────┐   ┌──────────────┐   ┌──────────────┐   ┌────────────┐
 │ Guardian   │   │  Sentinel     │   │   Ledger     │   │   Coral    │
 │ (Security) │   │ (Threat Mesh) │   │ (Audit Chain)│   │(Investigate)│
 └────────────┘   └──────────────┘   └──────────────┘   └────────────┘
        │                                                    │
        ▼                                                    ▼
 ┌────────────────────┐                           ┌────────────────────┐
 │ External LLM APIs  │                           │  GitHub / Slack    │
 │ OpenAI / Ollama    │                           │  Sentry / Notion   │
 │ Gemini / NVIDIA    │                           │  Confluence / PD   │
 └────────────────────┘                           └────────────────────┘
```

---

## 🛡️ Guardian Engine (Security Brain)

A multi-agent system that analyzes every prompt:

| Agent | Purpose |
| :--- | :--- |
| **Intent Agent** | Detects suspicious intent |
| **Injection Agent** | Detects prompt injection (jailbreaking) |
| **CoT Inspector** | Detects reasoning anomalies |
| **Fidelity Agent** | Enforces business-purpose alignment |
| **IOC Matcher** | Matches known threats against a database |

### Output

* **Risk Score:** (0–100)
* **Threat Category:** Identified vulnerability type
* **Action:** `allow` | `rate_limit` | `block`

---

## 🎯 Purpose Enforcement

Each deployment defines a strict system purpose:

```python
app_system_purpose = """
This system is a professional LLM interface for business operations.
It should not be used for personal, creative, or unrelated purposes.
"""
```

### Example Behavior

| Prompt | Result | Reason |
| :--- | :--- | :--- |
| "Explain DevOps" | ✅ **Allowed** | Business-related educational query |
| "Tell me a joke" | ❌ **Blocked** | Out of scope (Fidelity check failed) |
| "Write a story" | ❌ **Blocked** | Non-business creative request |

---

## ⚙️ Features

* ✅ **OpenAI-compatible API** (`/v1/chat/completions`)
* 🔐 **API key abstraction** (backend keys are never exposed to clients)
* 🧠 **Multi-agent security analysis** for defense-in-depth
* ⚖️ **Confidence-weighted risk scoring**
* 🚫 **Hard-block** for high-risk signals
* 🧾 **Blockchain-based audit logs** for non-repudiation
* 🤖 **MARL-based adaptive decision engine** (multi-agent RL)
* 🐚 **Coral SQL investigation** — query GitHub, Sentry, Slack, Datadog, etc.
* 🧬 **Auto-evolving detection patterns** from org-specific data
* 🍯 **Decoy honeypot deployment** to catch attackers probing with org knowledge
* 🧩 **MCP tool support** — 6 tools including 3 Coral-powered

---

## 🚀 Quick Start

### 1. Install Coral CLI

```bash
curl -fsSL https://coral-ai.com/install | sh
# or download from https://github.com/coral-ai/coral/releases
```

### 2. Run locally

```bash
git clone https://github.com/sanmarg/LLM-Wall
cd LLM-Wall

python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate

pip install -r requirements.txt
uvicorn llm_wall.core.app:app --reload --port 9876
```

### 3. Test via OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:9876/v1",
    api_key="internal-app-token"
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Explain DevOps"}]
)

print(response.choices[0].message.content)
```

### 4. Verify Coral Integration

```bash
# All 63 end-to-end tests should pass
python test_e2e.py

# Or check individual endpoints
curl http://localhost:9876/api/coral/status
curl http://localhost:9876/api/coral/sources
curl http://localhost:9876/api/coral/investigations
```

---

## 🌐 Dashboard

A real-time React dashboard is available at `http://localhost:9876/dashboard`:

```bash
cd dashboard
npm install
npm run dev
```

Features: live SSE threat stream, MARL heatmaps, Coral SQL console, investigation feed, Sentinel IOC browser, ledger explorer.

---

## 🏢 Organizational Benefits

### 1. Centralized Governance
Eliminate API key sprawl. Manage all provider connections (OpenAI, Gemini, Ollama) from a single control plane.

### 2. Enhanced Security
Protect against prompt injection and data exfiltration before data ever leaves your network.

### 3. Cost & Usage Control
Track usage per team and enforce strict rate limits to prevent runaway API costs.

### 4. Compliance & Observability
Immutable audit trail of every interaction via blockchain-backed ledger.

### 5. Cross-Source Investigation
When a threat is detected, automatically query GitHub, Sentry, Slack, PagerDuty, and Datadog in parallel via Coral SQL — store results on-chain.

---

## 🔮 Roadmap

* 🔐 **RBAC:** Per-application API keys and fine-grained permissions
* ☸️ **K8s Sidecar:** Deployment as a service mesh sidecar
* 📊 **Enhanced Dashboard:** Real-time risk and cost monitoring
* 🔍 **Lineage:** Tracking prompt evolution across multi-step agents
* 🐚 **More Coral sources:** Jira, Okta, Cloudflare, AWS, GCP

---

## 🧪 Test Suite

```bash
# Full E2E verification (63 tests covering all 12 Coral endpoints)
python test_e2e.py

# Import verification
python test_imports.py
```

---

## 📁 Project Structure

```
llm_wall/
├── api/
│   ├── coral_router.py        # 12 Coral endpoints
│   └── dashboard_router.py    # SSE stream with Coral stats
├── coral/
│   ├── engine.py              # CoralEngine (async subprocess wrapper)
│   ├── investigator.py        # A2A subscriber, 5 cross-source queries
│   ├── pattern_hunter.py      # Org-specific pattern synthesis
│   ├── honeypot.py            # Decoy prompt generation
│   └── policy_generator.py    # Threshold/recommendation engine
├── core/app.py                # FastAPI app factory
├── config.py                  # CoralSettings (6 env vars)
├── ledger/node.py             # record_investigation()
├── marl/engine.py             # record_coral_reward()
├── mcp/broker.py              # 6 MCP tools (3 Coral)
├── models.py                  # CoralSnapshot, CoralInvestigationReport
└── sentinel/node.py           # proactive_ioc_generation()
dashboard/
├── src/
│   ├── components/CoralInvestigation.jsx  # SQL console UI
│   └── App.jsx                             # Coral nav + KPI card
└── index.css                               # Coral component styles
test_e2e.py                    # 63 E2E tests
test_imports.py                # Import verification
```

---

## 📊 Example Risk Decision

```text
Risk: 80/100 (HIGH) | Primary threat: out_of_scope
  [intent_agent]   score=35 conf=0.60
  [fidelity_agent] score=80 conf=1.00: Out-of-scope request detected.
```

---

## 📄 License

This project is available under the MIT License.
