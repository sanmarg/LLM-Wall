# LLM Wall: Centralized Secure LLM Proxy

> **A Zero-Trust Security Layer for LLM APIs**
> Control *who*, *how*, and *why* AI is used inside your organization.

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
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
 ┌────────────┐   ┌──────────────┐   ┌──────────────┐
 │ Guardian   │   │  Sentinel     │   │   Ledger     │
 │ (Security) │   │ (Threat Mesh) │   │ (Audit Chain)│
 └────────────┘   └──────────────┘   └──────────────┘
        │
        ▼
 ┌────────────────────┐
 │ External LLM APIs  │
 │ OpenAI / Ollama    │
 │ Gemini / NVIDIA    │
 └────────────────────┘
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

Each deployment defines a strict system purpose to prevent "hallucination-as-a-service" or personal misuse:
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
* 🤖 **MARL-based adaptive decision engine**

---

## 📊 Example Risk Decision
```text
Risk: 80/100 (HIGH) | Primary threat: out_of_scope
  [intent_agent]   score=35 conf=0.60
  [fidelity_agent] score=80 conf=1.00: Out-of-scope request detected.
```

---

## 🚀 Quick Start

### 1. Run locally
```bash
git clone [https://github.com/yourusername/llm-wall](https://github.com/yourusername/llm-wall)
cd llm-wall

python -m venv .venv
source .venv/bin/activate 

pip install -r requirements.txt
uvicorn llm_wall.core.app:app --reload
```

### 2. Test via OpenAI SDK
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="internal-app-token"
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Explain DevOps"}]
)

print(response.choices[0].message.content)
```

---

## 🏢 Organizational Benefits

### 1. Centralized Governance
Eliminate API key sprawl. Manage all provider connections (OpenAI, Gemini, Ollama) from a single control plane.

### 2. Enhanced Security
Protect against prompt injection and data exfiltration before the data ever leaves your network.

### 3. Cost & Usage Control
Track usage per team and enforce strict rate limits to prevent runaway API costs from inefficient loops or misuse.

### 4. Compliance & Observability
Maintain a full, immutable audit trail of every interaction for regulatory requirements and forensic analysis.

---

## 🔮 Future Roadmap

* 🔐 **RBAC:** Per-application API keys and fine-grained permissions.
* ☸️ **K8s Sidecar:** Deployment as a service mesh sidecar.
* 📊 **Dashboard:** Real-time risk and cost monitoring in Grafana.
* 🔍 **Lineage:** Tracking prompt evolution across multi-step agents.
