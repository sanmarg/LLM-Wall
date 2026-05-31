# LLM Wall — Architecture Guide

## Overview

LLM Wall is a centralized zero-trust security proxy for LLM APIs. Every prompt passes through a multi-agent security engine before reaching the provider, and all actions are logged to an immutable blockchain ledger.

## Core Components

### Guardian Engine (Security Brain)
- **Intent Agent** — detects suspicious intent and prompt injection
- **Injection Agent** — detects jailbreaking and prompt manipulation
- **CoT Inspector** — detects reasoning anomalies in chain-of-thought
- **Fidelity Agent** — enforces business-purpose alignment
- **IOC Matcher** — matches known threats against a database

### Sentinel Mesh
P2P threat intelligence network. Each node shares IOCs (Indicators of Compromise) with peers via gossip protocol.

### Blockchain Ledger
Immutable audit trail with proof-of-work mining at configurable difficulty. Each block contains threat events, decisions, and Coral investigation reports.

### MARL Engine
4 Q-learning agents (gateway, tool, context, escalate) that adapt security decisions based on reward signals from external systems.

### Coral Integration
Cross-source SQL investigation system using the Coral CLI. Runs queries against GitHub, Sentry, Slack, PagerDuty, Datadog, Notion, and Confluence.

## Request Flow

1. Client sends prompt to `/v1/chat/completions`
2. Guardian agents analyze in parallel
3. Risk score computed from weighted confidences
4. Decision: allow / rate_limit / block
5. If threat detected → Coral IncidentInvestigator runs cross-source queries
6. All actions logged to blockchain ledger

## Coral Subsystems

- **IncidentInvestigator** — A2A subscriber, runs 5 SQL queries on threat events
- **PatternHunter** — Scans repos/docs for exposed prompts, synthesizes regex
- **Honeypot Generator** — Creates decoy prompts from org data, registers as IOCs
- **Policy Generator** — Reads Notion/Confluence/GitHub for security posture
- **MCP Tools** — coral_sql, coral_list_catalog, coral_search_catalog
