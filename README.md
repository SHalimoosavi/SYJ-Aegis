<div align="center">

# 🛡️ SYJ-AEGIS

### Open-Source AI Agent Security & Governance Engine

![Typing SVG](https://readme-typing-svg.demolab.com/?font=Fira+Code&size=20&pause=1200&color=00E5A0&center=true&vCenter=true&width=650&lines=Scan+Locally.+Understand+Completely.;Report+Transparently.+Remediate+Safely.;Zero+Dependencies+%E2%80%A2+Local-First+%E2%80%A2+Termux+Native)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/Runtime%20Dependencies-Zero-brightgreen)
![Platform](https://img.shields.io/badge/Platform-Termux%20%7C%20Linux%20%7C%20ARM64-informational)
![Static Analysis](https://img.shields.io/badge/Analysis-Local%20%26%20Static-blue)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)

**What can this AI system access, what can it do, what risks does it introduce, and is it ready for production?**

</div>

---

## 📑 Table of Contents

- [Why SYJ-Aegis Exists](#-why-syj-aegis-exists)
- [What It Solves](#-what-it-solves)
- [How It Works](#️-how-it-works)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Example Output](#-example-output)
- [Development Roadmap](#-development-roadmap)
- [Design Philosophy](#-design-philosophy)
- [Repository Structure](#️-repository-structure)
- [Testing](#-testing)
- [Contributing](#-contributing)
- [License](#-license)
- [Disclaimer](#️-disclaimer)

---

## 🎯 Why SYJ-Aegis Exists

AI agents don't just answer questions anymore — they're wired directly into shells, databases, filesystems, Git repos, vector stores, and internal company systems. Every one of those wires is a new security boundary, and most teams shipping agents today have no structured way to answer basic questions about it:

- What tools can this agent actually call?
- What permissions do those tools carry — read, write, execute, network, destructive?
- Is user input reaching a privileged prompt unchecked?
- Could retrieved RAG content cross an authorization boundary nobody thought about?
- Is a hardcoded API key sitting in a prompt template right now?

Most existing AI security tooling either requires uploading your source code to someone else's cloud, or bolts a dozen third-party dependencies onto your project just to run a scan. SYJ-Aegis takes the opposite approach: it's a **local-first, dependency-free, static analysis engine** you can run from a single Python standard-library install — including directly on a phone via Termux — that never sends your code anywhere.

## 🧩 What It Solves

| Problem | SYJ-Aegis Module |
|---|---|
| Hardcoded secrets in code, config, and prompt templates | 🔥 **AI-Firewall** — Secret Detection |
| Untrusted input reaching privileged LLM prompts | 🔥 **AI-Firewall** — Prompt Security |
| RAG pipelines with no visible authorization boundary | 🔥 **AI-Firewall** — RAG Security |
| Model output flowing straight into a shell or SQL call | 🔥 **AI-Firewall** — Output Security |
| No visibility into what tools an agent can call, or with what permissions | 🛡️ **AgentGuard** — Tool Inventory & Permission Model |
| Agents accumulating dangerous permission combinations unnoticed | 🛡️ **AgentGuard** — Excessive Agency Detection |
| No inventory of what AI systems exist across a codebase | 📋 **AIGovern** — AI System Register, Data Map & Risk Register |

## 🏗️ How It Works

```mermaid
flowchart TD
    A[Your AI Project] --> B[aegis scan]
    B --> C[Project Discovery Engine]
    B --> D[🔥 AI-Firewall]
    B --> E[🛡️ AgentGuard]
    B --> F[📋 AIGovern]
    C --> G[(.aegis/*.json)]
    D --> G
    E --> G
    F --> G
    G --> H[Static HTML Report]
    H --> I[Open Locally]
    H --> J[Publish via GitHub Pages]
```

Everything the engine finds carries **evidence** — a real file path and line number — and a **confidence level**, so nothing in the report is asserted more strongly than static analysis can actually support.

## 📦 Installation

### Termux (Android / ARM64) — primary target

```bash
pkg update && pkg install python git -y

git clone https://github.com/SHalimoosavi/SYJ-Aegis.git
cd SYJ-Aegis

python -m venv .venv
source .venv/bin/activate

pip install -e .

aegis --help
```

### Linux / macOS

```bash
git clone https://github.com/SHalimoosavi/SYJ-Aegis.git
cd SYJ-Aegis

python3 -m venv .venv
source .venv/bin/activate

pip install -e .

aegis --help
```

No compiled extensions, no native build tools, no internet access required after cloning — the scanner itself is pure Python standard library.

## 🚀 Quick Start

```bash
# Scan a project
aegis scan ./my-ai-agent

# Check version
aegis version

# See all commands
aegis --help
```

A scan produces a `.aegis/` directory in the target project containing machine-readable JSON findings plus a self-contained, static HTML report you can open directly in a browser or publish via GitHub Pages — no backend required.

> Some CLI subcommands described in the full specification (`aegis inventory`, `aegis agents`, `aegis secrets`, `aegis report`, `aegis rules list`) are on the roadmap below and may not all be wired up yet depending on which phase is currently merged — check `aegis --help` in your checkout for the authoritative, current list.

## 📊 Example Output

Illustrative shape of a finding (see your generated `findings.json` for the exact current schema):

```json
{
  "id": "AEGIS-AI-001",
  "category": "prompt_security",
  "severity": "HIGH",
  "confidence": "MEDIUM",
  "file": "agents/customer_agent.py",
  "line": 42,
  "description": "Untrusted user-controlled content is incorporated into a privileged instruction path.",
  "recommendation": "Separate trusted instructions from untrusted content and apply explicit trust-boundary handling."
}
```

## 🔥 Phase 3 — AI-Firewall

Phase 3 adds conservative, evidence-backed static checks for AI-specific security boundaries without attempting runtime or cross-function data-flow analysis. The scanner remains standard-library-only, local-first, deterministic, and non-executing.

Implemented on the `phase-3-ai-firewall` branch:

- Hardcoded secrets in string literals assigned to prompt/instruction/system-like variables.
- Prompt-injection exposure where request/function-parameter input is directly incorporated into an LLM prompt within the same function.
- Direct PII-like data exposure to logging, LLM, or network sinks.
- Vector-store/RAG detection with authorization-filter review for retrieval calls. Unverified access filtering is reported as `UNCLEAR` / `REVIEW REQUIRED` rather than as a confirmed isolation failure.
- LLM output flowing into dangerous execution, SQL, or filesystem sinks within the same function.
- Phase 3 findings use the `AEGIS-AI-0xx` rule namespace and the existing Finding model.

Phase 3 intentionally does not perform cross-function or cross-file taint tracking. Cases that cannot be resolved by direct same-function evidence are not promoted to false certainty.

## 📋 Phase 5 – AIGovern

AIGovern adds the governance and policy layer on top of the existing static security scanner.

The implementation is evidence-backed and local-only. It uses Python AST analysis and does not execute, import, evaluate, or dynamically load scanned project code.

### Implemented governance capabilities

This section documents the actually implemented Phase 5 capabilities:

- AI System Register — detects statically observable AI-library imports and model invocation patterns in Python source.
- Data Map — records observable data-like flows with source, classification, sink, and file/line evidence.
- Risk Register — maps existing evidence-based security findings to governance risks.
- Control Mapping — maps detected risks to governance controls and domains.
- Governance Findings — creates separate evidence-backed governance findings derived from existing scanner findings.
- Deterministic governance output — written to `.aegis/governance.json` using deterministic JSON serialization.
- Scanner integration — AIGovern runs as an additive layer without changing the existing Phase 1–4 security finding stream.

### Governance artifact

A Phase 5 scan produces a governance artifact alongside the existing security artifacts. It contains the AI System Register, Data Map, Risk Register, Control Mapping, and Governance Findings.

Where static evidence is insufficient to establish a fact, AIGovern does not invent the missing information.

### Phase 5 validation

The implementation is validated by positive and negative fixtures covering AI-system detection, data mapping, risk/control mapping, evidence-backed governance findings, scanner integration, and deterministic governance output.

## 🧭 Development Roadmap

| Phase | Module | Scope | Status |
|:---:|---|---|:---:|
| 1 | Core Scanner | Project discovery, secret detection, JSON + HTML reporting | ✅ Merged |
| 2 | 🛡️ AgentGuard | Tool inventory, permission model, excessive-agency detection | ✅ Merged |
| 3 | 🔥 AI-Firewall | Prompt security, data exposure, RAG security, output security | ✅ Merged |
| 4 | 📊 GitHub Pages Dashboard | Self-scan dashboard, live severity summary, module status, static report publishing | ✅ Merged |
| 5 | 📋 AIGovern | AI system register, data map, risk register, governance controls, evidence-backed governance findings | 🚧 In Progress |
| 6 | Production Hardening | CI/CD mode, SARIF output, baselines, suppressions, full docs, GitHub Actions | 📋 Planned |
