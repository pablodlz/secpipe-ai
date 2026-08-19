<div align="center">

# 🛡️ secpipe

### The zero-cost security pipeline your **AI operates itself** — so every AI-built project ships secure.

[![CI](https://github.com/pablodlz/secpipe-ai/actions/workflows/ci-security.yml/badge.svg)](https://github.com/pablodlz/secpipe-ai/actions/workflows/ci-security.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Container](https://img.shields.io/badge/ghcr.io-secpipe--ai-2496ED?logo=docker&logoColor=white)](https://github.com/pablodlz/secpipe-ai/pkgs/container/secpipe-ai)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![MCP ready](https://img.shields.io/badge/MCP-ready-6E56CF)](#-mcp-the-agent-native-interface)
![Cost](https://img.shields.io/badge/cost-%240%2Fmonth-brightgreen)

**Language-agnostic · AI-agnostic · Keyless · Self-hosted · Composes best-of-breed free tools**

</div>

---

> **AI writes code fast — and introduces vulnerabilities at scale.** secpipe makes the *same* AI that
> writes your code **find, fix, and verify** those vulnerabilities, guided by rules it can't quietly
> bypass. No API key. No SaaS bill. No human in the loop for the routine 80% — only for the risky 20%.

secpipe is a **DevSecOps engine designed to be operated by an AI agent** (Claude Code, Cursor, Copilot, Aider…).
You apply it to a project *before* development starts; from then on, the project's AI develops **secure by
default** — scanning, fixing, and verifying its own work behind guardrails enforced by your git hooks and CI,
not by the AI's goodwill.

It's **free by construction** (only free/open-source scanners), **runs anywhere** (container, any CI, or local),
and works with **any language** and **any AI**.

---

## ✨ Why secpipe is different

|  | **secpipe** | Copilot Autofix | Snyk / Mobb / Semgrep Assistant |
| --- | :---: | :---: | :---: |
| **Cost** | **$0, self-hosted** | free for OSS only | paid / metered |
| **Needs its own AI API key** | **No** — the agent already runs | — | Yes (account) |
| **Fixes findings from any scanner** | **Yes** (SARIF+CWE) | CodeQL only | varies |
| **Operated by the AI itself (MCP-native)** | **Yes** | No | No |
| **Verifier that doesn't trust the AI's word** | **Deterministic** (scanner + tests + no-suppression) | — | — |
| **Enforcement the AI can't bypass** | **git hooks + CI** | — | — |
| **Runs offline / no external service** | **Yes** | No (cloud) | No |

The core insight: **the operator is the AI.** So secpipe doesn't embed an LLM (and needs no key) — it provides
the **findings, the deterministic judge, and the guardrails**; the AI agent that's already running does the fixing.

---

## 🔁 How it works — the Detect → Repair → Verify loop

```mermaid
flowchart LR
    A["secpipe scan<br/><b>DETECT</b>"] --> B{"blocking<br/>findings?"}
    B -- "no" --> OK(["gate PASS ✓"])
    B -- "sensitive<br/>(auth · crypto · secret)" --> ESC["escalate → human"]
    B -- "yes" --> FIX["the AGENT fixes<br/><b>REPAIR · keyless</b>"]
    FIX --> V["secpipe verify<br/><b>VERIFY · deterministic</b>"]
    V -- "REJECT<br/>(with actionable reasons)" --> FIX
    V -- "ACCEPT" --> OK
    classDef ok fill:#e6f7ef,stroke:#1FA971;
    classDef esc fill:#fcefdc,stroke:#e09830;
    class OK ok;
    class ESC esc;
```

- **DETECT** — `secpipe scan` runs the scanners, normalizes every result into one contract (`cwe`, `severity`,
  `file`, `line`, `fingerprint`, `escalate`), dedups, and applies a **fail-closed gate**.
- **REPAIR** — the AI agent reads the structured findings and fixes them with its own model (or `secpipe fix`
  applies deterministic codemods for the mechanical ones). **No key needed.**
- **VERIFY** — `secpipe verify` is the **deterministic, independent judge**: it accepts a fix *only* if the
  scanner no longer flags it, the diff adds **no suppression**, and the tests pass. The *machine* approves — never
  the agent's word. Anything sensitive is **escalated**, not auto-fixed.

---

## 🚀 Quickstart

```bash
# 1. Install the engine + free scanners (Windows / Linux / macOS)
python install.py            # or: ./setup.sh  |  .\setup.ps1

# 2. Adopt secpipe in any project (one command)
secpipe init                 # writes .secpipe.yml + AGENTS.md + git hook + CI workflow + .mcp.json

# 3. The loop
secpipe scan .               # DETECT — JSON findings for the AI (or --format sarif for GitHub code scanning)
secpipe fix .                # REPAIR — apply deterministic codemods (the rest is the agent's job)
secpipe verify .             # VERIFY — deterministic gate + no-suppression + tests
```

Prefer zero install? The published container has **everything** baked in:

```bash
docker run --rm -v "$PWD:/work" ghcr.io/pablodlz/secpipe-ai:latest scan /work
```

`secpipe init` is **plug-and-play**: zero-config works out of the box with strong, secure defaults — the
`.secpipe.yml` is optional and only there to tune, never to weaken.

---

## 🧩 Architecture — one engine, three surfaces

secpipe is a small, pure-domain core (Clean + Hexagonal) with swappable adapters and **three thin entrypoints**.
CI/CD speaks the CLI/container; the AI agent speaks **MCP**.

```mermaid
flowchart TB
    subgraph S["Surfaces (driving adapters)"]
        CLI["🖥️ CLI<br/><code>secpipe …</code>"]
        MCP["🤖 MCP server<br/><code>secpipe mcp</code>"]
        IMG["📦 Container /<br/>GitHub Action"]
    end
    S --> ENG["<b>secpipe engine</b><br/>(pure domain + application)"]
    ENG --> SCAN["Scanners (free)<br/>gitleaks · semgrep · trivy<br/>bandit · pip-audit"]
    ENG --> NORM["Normalize →<br/><b>SARIF + CWE</b> contract"]
    ENG --> GATE["Fail-closed gate<br/>+ abstention (escalate)"]
    ENG --> VER["Deterministic verify<br/>+ fix memory"]
    NORM --> OUT["JSON for the AI ·<br/>SARIF for code scanning"]
    classDef eng fill:#efecfb,stroke:#6E56CF;
    class ENG eng;
```

**Composes best-of-breed, doesn't reinvent.** The scanners, remediation (Codemodder), and supply-chain checks
(OpenSSF Scorecard, StepSecurity Harden-Runner) are proven free tools. secpipe's value is the **glue**: one
AI-friendly contract, the deterministic verifier, the guardrails, and the agent-native interface.

---

## 🔒 The guardrail: *who guards the guard?*

If the same AI writes the code, runs the gate, **and** fixes findings, what stops it from just… silencing a
finding to go green? This is the hardest problem in AI-operated security — and secpipe answers it by separating
**orientation** (advice the agent could ignore) from **enforcement** (structural, agent-independent):

```mermaid
flowchart LR
    subgraph O["🧭 Orientation — the agent may ignore"]
        AG["AGENTS.md<br/>(security context)"]
        MT["MCP tools"]
    end
    subgraph E["⛔ Enforcement — agent-independent"]
        HK["git pre-commit hook<br/>blocks # nosec / # noqa / secrets"]
        CI["CI + fail-closed gate<br/>required status checks"]
    end
    DEV["AI develops"]
    AG -.guides.-> DEV
    MT -.guides.-> DEV
    DEV --> HK --> CI --> MAIN[("🔐 protected main")]
    classDef enf fill:#fbe4e1,stroke:#c0392b;
    class HK,CI enf;
```

- **A fix is never "make CI green."** The pre-commit hook **blocks** any diff that adds `# nosec` / `# noqa` /
  `nosemgrep` or a staged secret. The gate is **fail-closed** (unknown/error ⇒ block).
- **The policy lives in the engine**, not in the consumer repo — the AI can't rewrite the ruler that judges it.
- **The verifier is deterministic** — objective evidence (scanner + tests), not the model's self-assessment.

*This lesson was learned the hard way in offensive security (a guard that taught its own bypass); secpipe bakes
the fix in from commit zero.*

---

## 🤖 MCP — the agent-native interface

`secpipe init` registers an **MCP server** (`.mcp.json`). Any MCP-capable agent gets first-class tools and drives
the loop with **structured JSON**, no shell parsing:

| Tool | Purpose |
| --- | --- |
| `secpipe_scan` | DETECT — findings + gate verdict |
| `secpipe_fix` | REPAIR — deterministic codemods |
| `secpipe_verify` | VERIFY — deterministic judge |
| `secpipe_recall` / `secpipe_remember` | verified-fix memory (patterns, never code) |
| `secpipe_doctor` | tool availability |

The server is **JSON-RPC 2.0 over stdio, stdlib-only** (zero external dependency — a smaller supply-chain surface,
fitting for a security tool) and **local** by design. It's the *ergonomic* layer; enforcement stays in the hooks + CI.

---

## 🛠️ Commands

| Command | What it does |
| --- | --- |
| `secpipe init` | Adopt secpipe in a project (config + `AGENTS.md` + hook + workflow + `.mcp.json`) |
| `secpipe scan [--format json\|sarif]` | Run the scanners, normalize, apply the gate |
| `secpipe fix [--dry-run]` | Apply deterministic codemods |
| `secpipe verify [--base REF]` | Deterministic judge: gate + no-suppression + tests |
| `secpipe hook` | Pre-commit enforcement (blocks suppression + staged secrets) |
| `secpipe mcp` | Start the MCP server (stdio) |
| `secpipe remember` / `recall` | Record / recall verified-fix patterns |
| `secpipe doctor` | Show which scanners are available |

---

## 🧰 What's inside (all free)

| Dimension | Tools composed |
| --- | --- |
| **SAST** | Semgrep CE · Bandit (Python) |
| **SCA** | Trivy · pip-audit (Python) |
| **Secrets** | gitleaks |
| **IaC / containers** | Trivy |
| **Remediation** | Codemodder (Pixee) — deterministic codemods |
| **Supply-chain** | OpenSSF Scorecard · StepSecurity Harden-Runner · SHA-pinned actions · Dependabot |

Missing tools simply `skip` (they never break the run); a scanner that **errors** trips the **fail-closed** gate.

---

## 📥 Adoption models — GitHub-first, with a fallback

```mermaid
flowchart LR
    ENG["secpipe engine<br/>(versioned image)"]
    ENG --> A["<b>Referenced (default)</b><br/>reusable GitHub workflow<br/>@vX → gets updates"]
    ENG --> B["<b>Template / local</b><br/>use-as-template or<br/>docker run · any CI"]
```

Both modes consume the **same versioned engine** — you adapt only a tiny `.secpipe.yml` + a thin wrapper, never
the logic. That's how secpipe stays reusable **without drift**.

---

## 🛡️ Security posture (it eats its own dog food)

secpipe's own repository is its **first consumer**: every push runs the pipeline on itself.

- **Fail-closed everywhere** · secrets never committed (gitleaks in CI + pre-commit)
- **Supply-chain hardened** · all GitHub Actions **pinned by commit SHA** · container binaries verified by **SHA-256**
- **OpenSSF Scorecard** + **Harden-Runner** (egress monitoring) + **Dependabot** · `main` is branch-protected
- **Strict quality gate** on every change · Ruff (incl. Bandit rules) + mypy `--strict` + Bandit + tests

See [`SECURITY.md`](SECURITY.md) and the threat model in [`docs/specs/03-security.md`](docs/specs/03-security.md).

---

## 📈 Status & roadmap

**Core complete (v0.4.0):** engine · 5 real scanners · SARIF/CWE contract · fail-closed gate · `init`/`hook`
adoption · **keyless Detect→Repair→Verify** · deterministic verifier · abstention · fix memory · **MCP server** ·
public container image · green CI.

```mermaid
flowchart LR
    P0["Phase 0<br/>Foundation ✅"] --> P1["Phase 1<br/>Scan engine ✅"] --> P2["Phase 2<br/>Adoption ✅"] --> P3["Phase 3<br/>Auto-fix DRV ✅"] --> P4["Phase 4<br/>Integrate everywhere ▶"]
```

Full plan and design specs live in [`docs/specs/`](docs/specs/) (foundation-to-features, incl. the strategies
distilled from prior art) and the decisions in [`docs/adr/`](docs/adr/).

---

## ❓ FAQ

**Do I need an OpenAI/Anthropic API key?** No. The AI operating your project already has model access — *it*
does the fixing. secpipe provides the findings, the deterministic judge, and the guardrails. (A headless
"PR-bot" mode that calls an LLM itself is an optional future add-on — that one would need a key.)

**Which languages?** Any. The engine runs as a container; the scanners are multi-language. Python-specific
scanners (Bandit, pip-audit) auto-enable when Python is detected.

**Which AI agents?** Any. `AGENTS.md` is the neutral standard (with optional shims for Claude/Cursor/Copilot),
and the MCP server works with any MCP-capable agent. Crucially, enforcement (hooks + CI) is **agent-independent**.

**Is it really free?** Yes — only free/OSS scanners, self-hosted, no metering. `semgrep`/`codemodder` don't run
natively on Windows (they run in the Linux container/CI); everything else runs on Windows too.

**Can it just silence findings to pass?** No — that's the whole design. Suppression is blocked at commit time,
the policy isn't editable by the consumer, and the verifier is deterministic.

---

## 🤝 Contributing & License

Contributions are welcome — issues and PRs. All changes go through the same green gate secpipe applies to
everything else.

Licensed under **[Apache-2.0](LICENSE)** — permissive, with an explicit patent grant (fitting for security tooling).

<div align="center">

*Built to be the best zero-cost security pipeline on the market — operated by AI, for AI-built software.*

</div>
