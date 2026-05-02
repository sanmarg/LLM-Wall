---

# 🚧 LLM Wall — Centralized Secure LLM Proxy

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

```
App → LLM Wall → OpenAI / Ollama / Gemini / NVIDIA
```

It enforces:

* 🔐 Zero-trust prompt validation
* 🎯 Purpose-based access control
* 🧠 Multi-agent threat detection
* 📊 Risk scoring + decision engine
* 🧾 Immutable audit logging (blockchain-backed)
* 🌐 Distributed threat intelligence (Sentinel mesh)

---

## 🧠 Core Idea

> **LLM access should be governed like production database access.**

---

## 🏗️ Architecture

```
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

| Agent              | Purpose                             |
| ------------------ | ----------------------------------- |
| Intent Agent       | Detects suspicious intent           |
| Injection Agent    | Detects prompt injection            |
| CoT Inspector      | Detects reasoning anomalies         |
| **Fidelity Agent** | Enforces business-purpose alignment |
| IOC Matcher        | Matches known threats               |

### Output

* Risk Score (0–100)
* Threat Category
* Action: `allow | rate_limit | block`

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

| Prompt           | Result    |
| ---------------- | --------- |
| "Explain DevOps" | ✅ Allowed |
| "Tell me a joke" | ❌ Blocked |
| "Write a story"  | ❌ Blocked |

---

## ⚙️ Features

* ✅ OpenAI-compatible API (`/v1/chat/completions`)
* 🔐 API key abstraction (no direct exposure)
* 🧠 Multi-agent security analysis
* ⚖️ Confidence-weighted risk scoring
* 🚫 Hard-block for high-risk signals
* 📉 Rate limiting for borderline prompts
* 🧾 Blockchain-based audit logs
* 🌐 Distributed IOC sharing (Sentinel)
* 🤖 MARL-based adaptive decision engine

---

## 📊 Example Risk Decision

```
Risk: 80/100 (HIGH) | Primary threat: out_of_scope
  [intent_agent] score=35 conf=0.60
  [fidelity_agent] score=80 conf=1.00: Out-of-scope request
```

---

## 🚀 Demo

### Run locally

```bash
git clone https://github.com/yourusername/llm-wall
cd llm-wall

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt

uvicorn llm_wall.core.app:app --reload
```

---

### Test via OpenAI SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="not-needed"
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "user", "content": "Explain DevOps"}
    ]
)

print(response.choices[0].message.content)
```

---

## 📈 Benchmarks *(replace with real metrics)*

| Metric               | Value      |
| -------------------- | ---------- |
| Avg latency overhead | ~40–80 ms  |
| Detection accuracy   | ~85–92%    |
| False positives      | ~5–10%     |
| Throughput           | ~X req/sec |

---

## 🏢 How This Can Be Used in Organizations

### 1. Centralized LLM Governance

* Single controlled gateway for all LLM usage
* No direct API key exposure across services

---

### 2. Security & Compliance

* Detect and block prompt injection
* Prevent sensitive data leakage
* Enforce usage policies consistently

---

### 3. Cost Control

* Track usage per application/team
* Apply rate limits and quotas
* Prevent non-essential usage

---

### 4. Observability

* Full audit logs of:

  * prompts
  * decisions
  * risk scores

---

### 5. Multi-Model Abstraction

* Seamlessly switch between:

  * OpenAI
  * Ollama (on-prem)
  * Gemini
  * NVIDIA NIM

---

## 🏢 How This System Benefits Organizations

Modern organizations are rapidly integrating LLMs into critical workflows—ranging from customer-facing systems to internal automation. However, this adoption often happens without centralized control, introducing security and operational risks.

**LLM Wall introduces a governed access layer for AI usage.**

---

### 🔐 Secure Customer-Facing AI Systems

* Prevent unintended data exposure
* Block adversarial prompts
* Keep interactions aligned with business goals

---

### ⚙️ Controlled AI Usage in Critical Workflows

* Validate prompts against intended use-cases
* Restrict unsafe or irrelevant queries
* Maintain predictable system behavior

---

### 🧭 Governance for Internal AI Tools

* Enforce purpose-based access control
* Reduce misuse and non-work queries
* Standardize AI behavior across teams

---

### 📊 Auditability and Compliance

* Traceable logs of all AI interactions
* Explainable risk scoring
* Structured audit trails for review

---

### 🌐 Centralized Control Plane

```
Application → LLM Wall → LLM Providers
```

* Eliminates API key sprawl
* Enables provider abstraction
* Simplifies monitoring and control

---

### 🛡️ Defense-in-Depth

* Multiple independent detection agents
* No single point of failure
* Reduced reliance on model-native safety

---

## 🔮 Future Roadmap

* 🔐 Per-app API keys + RBAC
* ☸️ Kubernetes-native deployment (sidecar model)
* 📊 Observability dashboard (Grafana)
* 🧠 Fine-tuned local Guardian models
* 🔍 Prompt lineage tracing
* 🧾 SIEM integration (Splunk, ELK)

---
