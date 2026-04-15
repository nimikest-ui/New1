# TopAgent (PENTESTGPT) — AGENTS.md

## Quick Reference
| | |
|---|---|
| **Stack** | Python 3.10+ · OpenAI API · SQLite · ChromaDB · Typer · Rich |
| **Install** | `pip install -e ".[dev]"` or `pip install -r requirements.txt` |
| **Run pentest** | `pentestgpt run <target> --steps 10` |
| **KB CLI** | `kb sync` · `kb doctor` · `kb stats` · `kb agent_init` · `kb run` |
| **Tests** | `PYTHONPATH=src pytest tests/ -v` (84 tests) |
| **Config** | `config/config.yaml` (copy from `config.yaml.example`) |
| **Entry points** | `pentestgpt` → `src/pentestgpt/ui/cli.py:main` · `kb` → `src/pentestgpt/kb/cli.py:main` |

---

## Table of Contents
1. [What This Is](#what-this-is)
2. [Architecture](#architecture)
3. [Installation & Setup](#installation--setup)
4. [Configuration](#configuration)
5. [CLI Reference](#cli-reference)
6. [The Reasoning Pipeline](#the-reasoning-pipeline)
7. [Knowledge Base (KB) System](#knowledge-base-kb-system)
8. [Tool Registry & Execution](#tool-registry--execution)
9. [Memory & Persistence](#memory--persistence)
10. [Self-Improvement Loop](#self-improvement-loop)
11. [Campaign Mode](#campaign-mode)
12. [Skills System](#skills-system)
13. [Prompt Engineering](#prompt-engineering)
14. [Project Structure](#project-structure)
15. [Development Guide](#development-guide)
16. [Security & Scope Enforcement](#security--scope-enforcement)
17. [Troubleshooting](#troubleshooting)

---

## What This Is

TopAgent (PENTESTGPT) is an LLM-empowered automated penetration testing framework for Kali Linux. It combines a structured **Reasoner → Generator → Executor → Parser** pipeline with a **10-source intelligence Knowledge Base**, **tiered LLM execution** for cost control, and a **self-improvement loop** that turns successful runs into reusable playbooks.

### Design Philosophy
- **Fast by default**: Tier 1 uses a cheap model with a 2K token budget — most decisions come from cached KB data, not expensive LLM calls.
- **Escalate when stuck**: Auto-promotes to Tier 2/3 after N iterations without new findings.
- **No hallucinated tools**: The Reasoner only suggests tools present in the KB. Commands are generated from real Kali tool specs.
- **Learn from runs**: Every successful engagement is saved as a JSON recipe + SKILL.md for future reuse.
- **PTES-aligned**: Follows Penetration Testing Execution Standard phases: Recon → Enumeration → Vuln Scan → Exploit → Post-Exploit → Report.

### Core Capabilities
- Single-target and multi-target (campaign) penetration testing
- 10-source threat intelligence ingestion (MITRE ATT&CK, NVD, CISA KEV, OTX, ThreatFox, URLhaus, VirusTotal, Shodan, AbuseIPDB, Kali help pages)
- Tiered LLM execution (3 tiers with automatic escalation)
- Structured output parsing for nmap, gobuster, nikto, sqlmap, hydra, enum4linux (regex-based) + LLM fallback
- Natural language database queries with SQL injection protection
- Knowledge graph for cross-target correlation
- Vector search memory for pattern recall
- HTML/Markdown report generation
- Skill store with ChromaDB indexing

---

## Architecture

```
                         ┌─────────────────────────────────┐
                         │           User / CLI            │
                         │  pentestgpt run 192.168.1.50    │
                         └────────────┬────────────────────┘
                                      │
                         ┌────────────▼────────────────────┐
                         │        Scope Checker            │
                         │  Validates target is in-scope   │
                         └────────────┬────────────────────┘
                                      │
               ┌──────────────────────▼──────────────────────┐
               │              REASONING LOOP                  │
               │                                              │
               │  ┌──────────┐   ┌───────────┐   ┌────────┐ │
               │  │ Reasoner │──▶│ Generator │──▶│Executor│ │
               │  │ (Tiered) │   │ (Commands)│   │ (Shell)│ │
               │  └────┬─────┘   └───────────┘   └───┬────┘ │
               │       │                              │      │
               │       │    ┌──────────┐              │      │
               │       │    │  Parser  │◀─────────────┘      │
               │       │    │ (Output) │                     │
               │       │    └────┬─────┘                     │
               │       │         │                           │
               │       ▼         ▼                           │
               │  ┌──────────────────────┐                   │
               │  │      Task Tree       │                   │
               │  │ (State + Findings)   │                   │
               │  └──────────────────────┘                   │
               └──────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┬┴──────────────────┐
                    ▼                 ▼                    ▼
            ┌──────────────┐  ┌─────────────┐   ┌──────────────┐
            │  KB (SQLite) │  │   Memory    │   │    Reflect   │
            │ 31 Kali tools│  │ VectorStore │   │ Recipe+Skill │
            │ 1100+ CVEs   │  │ KnowledgeGr │   │  Generation  │
            │ 500+ IOCs    │  │ SessionDiary│   │              │
            └──────────────┘  └─────────────┘   └──────────────┘
```

### Component Interactions

| Component | Input | Output | LLM Call? |
|-----------|-------|--------|-----------|
| **Reasoner** | Task tree state + KB tools context | JSON decision (action, task, suggested_tools) | Yes (tiered) |
| **Generator** | Task description + category | Shell commands list | Yes |
| **Executor** | Shell command string | stdout, stderr, return code, elapsed time | No |
| **Parser** | Raw tool output + command | Structured findings list | Regex first, LLM fallback |
| **Reflect** | Run results (commands, findings) | JSON recipe + SKILL.md | No |
| **KB Ingesters** | External APIs/feeds | SQLite rows | No |

---

## Installation & Setup

### Prerequisites
- **Kali Linux** (or any Linux with pentest tools installed)
- **Python 3.10+**
- **OpenAI API key** (for LLM reasoning/generation)

### Install

```bash
cd /home/nimi/ai-agents/TopAgent

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Or install as editable package (recommended)
pip install -e ".[dev]"

# Install optional embedding support
pip install -e ".[embeddings]"
```

### First-Time Setup

```bash
# 1. Copy config template
cp config/config.yaml.example config/config.yaml

# 2. Set your OpenAI API key (pick one method)
export OPENAI_API_KEY="sk-..."
# OR edit config/config.yaml → llm.api_key
# OR create config/.env with OPENAI_API_KEY=sk-...

# 3. Initialize the Knowledge Base
kb doctor          # Verify setup
kb sync --source cisa_kev --source kali_help   # Free sources, no API keys needed

# 4. Check KB health
kb stats
```

### Optional API Keys (for premium intelligence sources)
Set as environment variables or in `config/config.yaml` under `kb:`:

| Variable | Source | Free? |
|----------|--------|-------|
| `OPENAI_API_KEY` | LLM reasoning (required) | No |
| `NVD_API_KEY` | NIST NVD (higher rate limit) | Yes (register at nvd.nist.gov) |
| `OTX_API_KEY` | AlienVault OTX pulses | Yes (register at otx.alienvault.com) |
| `VT_API_KEY` | VirusTotal file hashes | Yes (register at virustotal.com) |
| `SHODAN_API_KEY` | Shodan internet scanning | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB reputation | Yes (register at abuseipdb.com) |

---

## Configuration

Configuration lives in `config/config.yaml` (YAML format). Environment variables override file values.

```yaml
# ── LLM Provider ────────────────────────────────────────────────────────────
llm:
  provider: openai              # openai | azure
  model: gpt-4o                 # Default model (overridden by tier config)
  api_key: ""                   # Or set OPENAI_API_KEY env var
  temperature: 0.2              # Lower = more deterministic
  max_tokens: 4096              # Max output tokens per call

# ── Scope ────────────────────────────────────────────────────────────────────
scope:
  targets: []                   # ["192.168.1.0/24", "10.0.0.0/24"]
  excluded: []                  # IPs/ranges to never touch

# ── Session ──────────────────────────────────────────────────────────────────
session:
  log_dir: "./logs"
  auto_execute: false           # true = run commands without confirmation
  max_iterations: 50            # Safety stop

# ── Tiered Execution (NimiPlaybook) ─────────────────────────────────────────
tier:
  initial: 1                    # Start at Tier 1 (cheapest)
  escalate_after: 5             # Promote tier after N stale iterations
  models:
    tier1: gpt-4o-mini          # Fast & cheap — KB cache decisions
    tier2: gpt-4o               # Balanced cost/quality
    tier3: gpt-4-turbo          # Deep analysis — full synthesis

# ── Knowledge Base ───────────────────────────────────────────────────────────
kb:
  db_path: "./db/kali_tools.db"
  token_budget:
    tier1: 2000
    tier2: 4000
    tier3: 8000
  # Optional API keys (can also use env vars)
  otx_api_key: ""
  vt_api_key: ""
  shodan_api_key: ""
  abuseipdb_api_key: ""
  nvd_api_key: ""
```

### Tier System Explained

| Tier | Model | Token Budget | When Used |
|------|-------|-------------|-----------|
| **1** | gpt-4o-mini | 2,000 | Default. Fast decisions from KB-cached tool lists. Handles most recon/enum steps. |
| **2** | gpt-4o | 4,000 | Auto-escalated after 5 iterations without new findings. Deeper analysis for stuck situations. |
| **3** | gpt-4-turbo | 8,000 | Full synthesis mode. Complex exploitation chains, novel attack paths. |

Escalation is automatic: if the Reasoner produces no new findings for `escalate_after` iterations, it bumps the tier and resets the counter.

---

## CLI Reference

### `pentestgpt` — Main Agent CLI

```bash
# Run a penetration test against a single target
pentestgpt run <target> [--steps N]
#   target:  IP address or hostname
#   --steps: Max reasoning iterations (default: 5)
#
# Example:
pentestgpt run 192.168.1.50 --steps 20

# Run a multi-target campaign
pentestgpt campaign <name> <target1> [target2 ...] [--no-run]
#   name:     Campaign identifier
#   targets:  Space-separated IPs/hostnames
#   --no-run: Create campaign record but don't execute
#
# Example:
pentestgpt campaign "Q1-RedTeam" 192.168.1.0/24 10.0.0.0/24

# Query the vector memory store
pentestgpt memory --query "sql injection" --top-k 5
pentestgpt memory --target 192.168.1.50

# Natural language database query
pentestgpt db-query "What credentials were found on 192.168.1.1?"

# Generate a report
pentestgpt report <session_id> [--format markdown|html] [--output-dir ./reports]

# Manage skills
pentestgpt skills list
pentestgpt skills search "ssh brute force"
pentestgpt skills show nmap_scan
```

### `kb` — Knowledge Base CLI

```bash
# Sync all 10 intelligence sources
kb sync

# Sync specific sources only
kb sync --source cisa_kev --source kali_help --source nvd

# Available sources:
#   mitre_attck, nvd, cisa_kev, otx, threatfox, urlhaus,
#   virustotal, shodan, abuseipdb, kali_help

# Health check (DB, API keys, tools in PATH, Python packages)
kb doctor

# Show KB statistics
kb stats

# Deep-research a topic and synthesize a playbook
kb agent_init "Log4Shell exploitation techniques"

# Run a playbook against a target
kb run <playbook_name> --target <IP> [--tier 1|2|3] [--dry-run]
```

---

## The Reasoning Pipeline

Each `pentestgpt run` execution follows this loop:

### Step-by-Step Flow

```
1. INIT
   ├── Load config (config.yaml + env vars)
   ├── Create ScopeChecker with target
   ├── Create TaskTree rooted at target
   ├── Open KaliToolsDb (SQLite KB)
   └── Initialize Reasoner(tier=1), Generator, Executor, Parser

2. LOOP (for each step, up to --steps):
   │
   ├── REASONER.decide(task_tree)
   │   ├── Identify current task category (recon/enum/vuln_scan/exploit/...)
   │   ├── Query KB → tools_for_task_category() → formatted tool list
   │   ├── Count findings → maybe escalate tier if stale
   │   ├── Prepend memory context (if available)
   │   ├── Call LLM (model = current tier's model, budget = tier's budget)
   │   └── Return JSON: {action, task_title, task_category, task_description,
   │                      reasoning, suggested_tools}
   │
   ├── REASONER.apply_decision(decision, tree)
   │   ├── If action="new_task" → tree.add_task()
   │   ├── If action="next_task" → mark next pending task in-progress
   │   └── If action="done" → return None (exit loop)
   │
   ├── GENERATOR.generate(task, target)
   │   ├── Build prompt with category-specific tool hints
   │   ├── Call LLM → get commands list
   │   └── Replace <TARGET> placeholders with actual target
   │
   ├── EXECUTOR.run(command, target) — for each command
   │   ├── ScopeChecker.assert_command_in_scope()
   │   ├── subprocess.run() with timeout (120s default)
   │   └── Return ShellResult(stdout, stderr, returncode, elapsed_secs)
   │
   ├── PARSER.parse(command, output, task)
   │   ├── Try structured regex parser (nmap, gobuster, nikto, sqlmap, hydra, enum4linux)
   │   ├── If no structured parser matches → LLM fallback parser
   │   └── Return {findings: [...], summary: "..."}
   │
   └── Task.add_finding() for each finding; Task.mark_completed()

3. REFLECT (after loop completes)
   ├── reflect_on_run() → JSON recipe + SKILL.md
   └── Close KaliToolsDb
```

### What the Reasoner Sees

The Reasoner receives a prompt containing:
1. **System prompt**: PTES methodology, JSON output format, tool constraints
2. **Memory context** (optional): Relevant past findings from vector store
3. **KB tools context**: "AVAILABLE KALI TOOLS (from KB – use ONLY these)" with up to 12 tools matching the current task category
4. **Task tree summary**: Current state of all tasks, findings, commands run

### Task Categories

| Category | Maps to PTES Phase | Example Tools from KB |
|----------|--------------------|-----------------------|
| `reconnaissance` | Intelligence Gathering | nmap, amass, theHarvester, whois |
| `enumeration` | Enumeration | gobuster, enum4linux, smbclient, ffuf |
| `vulnerability_scanning` | Vulnerability Analysis | nikto, nuclei, wpscan, nmap --script vuln |
| `exploitation` | Exploitation | sqlmap, hydra, metasploit, john |
| `post_exploitation` | Post-Exploitation | linpeas, winpeas, bloodhound, mimikatz |
| `reporting` | Reporting | (internal report generator) |
| `other` | — | Generic fallback |

---

## Knowledge Base (KB) System

The KB is a SQLite database (`db/kali_tools.db`) with 3 tables and 10 ingesters that populate it from external threat intelligence sources.

### Database Schema

```sql
-- 31 pre-seeded Kali tools with MITRE ATT&CK phase mapping
kali_tools (
  id INTEGER PRIMARY KEY,
  tool_name TEXT UNIQUE,        -- e.g., "nmap", "sqlmap"
  category TEXT,                -- e.g., "scanner", "exploitation"
  attack_phase TEXT,            -- MITRE phase: "reconnaissance", "initial-access", etc.
  one_line_desc TEXT,           -- Short description
  man_page_compressed TEXT,     -- Compressed --help output (from kali_help ingester)
  cve_refs TEXT,                -- Associated CVEs
  last_updated TIMESTAMP
)

-- CVE entries from NVD + CISA KEV
cve_entries (
  id INTEGER PRIMARY KEY,
  cve_id TEXT UNIQUE,           -- e.g., "CVE-2021-44228"
  title TEXT,
  severity TEXT,                -- CRITICAL, HIGH, MEDIUM, LOW
  cvss_score REAL,
  description TEXT,
  kali_tool TEXT,               -- Guessed Kali tool for exploitation
  attack_phase TEXT,
  published TEXT,
  last_updated TIMESTAMP
)

-- IOCs from ThreatFox, URLhaus, OTX, VirusTotal, Shodan, AbuseIPDB
threat_intel (
  id INTEGER PRIMARY KEY,
  source TEXT,                  -- "threatfox", "urlhaus", "otx", etc.
  type TEXT,                    -- "ip", "url", "hash", "domain"
  value TEXT,                   -- The actual IOC value
  context TEXT,                 -- Malware family, tags, etc.
  severity TEXT,
  last_updated TIMESTAMP
)
```

### Pre-Seeded Kali Tools (31)

The KB ships with 31 Kali Linux tools pre-mapped to MITRE ATT&CK phases:

| Tool | Category | Attack Phase |
|------|----------|-------------|
| nmap | scanner | reconnaissance |
| masscan | scanner | reconnaissance |
| amass | osint | reconnaissance |
| theHarvester | osint | reconnaissance |
| whois | osint | reconnaissance |
| gobuster | web | enumeration |
| ffuf | web | enumeration |
| feroxbuster | web | enumeration |
| dirb | web | enumeration |
| enum4linux | smb | enumeration |
| smbclient | smb | enumeration |
| nikto | web | vulnerability-scanning |
| wpscan | web | vulnerability-scanning |
| nuclei | scanner | vulnerability-scanning |
| openvas | scanner | vulnerability-scanning |
| sqlmap | exploitation | initial-access |
| hydra | brute-force | credential-access |
| john | password | credential-access |
| hashcat | password | credential-access |
| medusa | brute-force | credential-access |
| metasploit | exploitation | initial-access |
| msfvenom | payload | execution |
| searchsploit | exploitation | initial-access |
| responder | mitm | credential-access |
| impacket | exploitation | lateral-movement |
| crackmapexec | exploitation | lateral-movement |
| evil-winrm | exploitation | lateral-movement |
| bloodhound | post-exploit | discovery |
| linpeas | post-exploit | privilege-escalation |
| winpeas | post-exploit | privilege-escalation |
| netcat | utility | command-and-control |

### 10 Intelligence Ingesters

| # | Source | Module | Auth | What It Provides |
|---|--------|--------|------|-----------------|
| 1 | **MITRE ATT&CK** | `mitre_attck.py` | None | Enterprise techniques + software → kali_tools with normalized phases |
| 2 | **NVD (NIST)** | `nvd.py` | Optional (`NVD_API_KEY`) | Last 30 days of CVEs → cve_entries with guessed Kali tool |
| 3 | **CISA KEV** | `cisa_kev.py` | None | Actively exploited vulnerabilities → cve_entries |
| 4 | **OTX (AlienVault)** | `otx.py` | Required (`OTX_API_KEY`) | Pulse indicators (IPs, domains, hashes) → threat_intel |
| 5 | **ThreatFox** | `threatfox.py` | None | Recent IOCs with malware families → threat_intel |
| 6 | **URLhaus** | `urlhaus.py` | None | Recently reported malicious URLs → threat_intel |
| 7 | **VirusTotal** | `virustotal.py` | Required (`VT_API_KEY`) | Malicious file hashes → threat_intel |
| 8 | **Shodan** | `shodan.py` | Required (`SHODAN_API_KEY`) | Vulnerable services on the internet → threat_intel |
| 9 | **AbuseIPDB** | `abuseipdb.py` | Required (`ABUSEIPDB_API_KEY`) | High-confidence abuse IPs → threat_intel |
| 10 | **Kali Help** | `kali_help.py` | None (local) | `--help` output from installed tools → kali_tools.man_page_compressed |

**Free sources (no API key):** MITRE ATT&CK, CISA KEV, ThreatFox, URLhaus, Kali Help
**Free with registration:** NVD, OTX, VirusTotal, AbuseIPDB

### How KB Feeds Into Reasoning

When the Reasoner prepares a decision:

1. It determines the current task category (e.g., `enumeration`)
2. Calls `kali_tools_db.tools_for_task_category("enumeration")`
3. This maps the category to MITRE phases and queries matching tools
4. Returns up to 12 tools formatted as:
   ```
   AVAILABLE KALI TOOLS (from KB – use ONLY these):
     - gobuster [enumeration]: Directory/file brute-forcing
     - ffuf [enumeration]: Fast web fuzzer for directories and vhosts
     - enum4linux [enumeration]: SMB/Samba enumeration tool
     ...
   ```
5. This context is injected into the LLM prompt, constraining tool selection

---

## Tool Registry & Execution

### Tool Registry (`src/pentestgpt/executor/tool_registry.py`)

12 tools pre-registered with OpenAI function-calling schemas:

| Tool | Risk Level | Kali Command Template |
|------|-----------|----------------------|
| nmap | PASSIVE | `nmap -sV -sC <TARGET>` |
| gobuster | ACTIVE | `gobuster dir -u http://<TARGET> -w /usr/share/wordlists/dirb/common.txt` |
| nikto | ACTIVE | `nikto -h <TARGET>` |
| sqlmap | ACTIVE | `sqlmap -u http://<TARGET> --batch` |
| hydra | DESTRUCTIVE | `hydra -L users.txt -P passwords.txt <TARGET> ssh` |
| enum4linux | PASSIVE | `enum4linux -a <TARGET>` |
| smbclient | PASSIVE | `smbclient -L //<TARGET>/ -N` |
| wpscan | ACTIVE | `wpscan --url http://<TARGET>` |
| theHarvester | PASSIVE | `theHarvester -d <TARGET> -b all` |
| masscan | ACTIVE | `masscan <TARGET> -p1-65535 --rate=1000` |
| ffuf | ACTIVE | `ffuf -u http://<TARGET>/FUZZ -w /usr/share/wordlists/dirb/common.txt` |
| curl | PASSIVE | `curl -sI http://<TARGET>` |

**Risk Levels:**
- `PASSIVE` — Read-only, no modification to target
- `ACTIVE` — May trigger IDS/IPS alerts
- `DESTRUCTIVE` — May modify target state (brute-force, exploitation)

### Shell Executor (`src/pentestgpt/executor/shell_executor.py`)

- Runs commands via `subprocess.run()` with configurable timeout (default 120s)
- **Scope enforcement**: Before execution, extracts all IPs/hostnames from the command and validates against the ScopeChecker
- Returns `ShellResult(stdout, stderr, returncode, elapsed_secs)`
- Timeout returns code 124

### Planner-Summarizer (`src/pentestgpt/executor/planner_summarizer.py`)

Alternative execution mode using OpenAI function calling (ReAct-style):
1. LLM selects a tool from the registry using function calling
2. Executor runs the tool
3. LLM summarizes the output
4. Findings are extracted and fed back into the conversation

---

## Memory & Persistence

### Four Memory Stores

| Store | Backend | Purpose |
|-------|---------|---------|
| **KnowledgeGraph** | SQLite (`entities` + `relations` tables) | Track hosts, ports, services, credentials, and relationships across targets |
| **VectorStore** | ChromaDB (optional) | Semantic search over past findings, tool outputs, and context |
| **SessionDiary** | On-disk JSON/Markdown | Per-session notes organized by "wings" (sections) with tunnel tracking |
| **SkillStore** | Disk (SKILL.md) + ChromaDB | Reusable pentest skill persistence with vector search |

### Knowledge Graph

```python
from pentestgpt.memory.knowledge_graph import KnowledgeGraph

kg = KnowledgeGraph()
kg.add_host_info("192.168.1.50", port=22, service="ssh", version="OpenSSH 8.4")
kg.add_host_info("192.168.1.50", port=80, service="http", version="Apache 2.4")
kg.add_credential("192.168.1.50", "ssh", "admin", "password123")

ports = kg.get_open_ports("192.168.1.50")     # [(22, 'ssh', 'OpenSSH 8.4'), ...]
creds = kg.get_credentials("192.168.1.50")    # [('ssh', 'admin', 'password123')]
relations = kg.get_by_target("192.168.1.50")  # All entities for this target
```

### Database (GptDb)

Full relational database (SQLAlchemy + SQLite) for structured pentest data:

```python
from pentestgpt.db.gptdb import GptDb

db = GptDb(cfg)

# Store findings programmatically
db.store_finding(task_id=1, target_id=1, finding_type="open_port",
                 severity="info", description="Port 22 open (SSH)")
db.store_credential(target_id=1, service="ssh", port=22,
                    username="admin", password_hash="...", is_valid=True)
db.store_vulnerability(target_id=1, cve_id="CVE-2021-44228",
                       title="Log4Shell", severity="critical",
                       description="...", service="java")

# Natural language queries (LLM translates to SQL)
result = db.query("What credentials were found on 192.168.1.1?")
# Returns formatted markdown table

# Session summaries
summary = db.get_session_summary(session_id=42)
```

**Safety**: Natural language queries are validated to be SELECT-only with no multi-statement injection.

---

## Self-Improvement Loop

After every successful `pentestgpt run`, the `reflect_on_run()` function:

### 1. Saves a JSON Recipe

Written to `artifacts/tool_recipes/<name>.json`:

```json
{
  "name": "run_192.168.1.50",
  "target_hint": "192.168.1.50",
  "commands": [
    "nmap -sV -sC 192.168.1.50",
    "gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/dirb/common.txt"
  ],
  "findings": [
    "Open port 22/tcp (ssh): OpenSSH 8.4",
    "Open port 80/tcp (http): Apache 2.4",
    "Web path found: /admin [HTTP 200]"
  ],
  "created_at": "2026-04-14T20:29:46Z",
  "source": "reflect",
  "last_updated": "2026-04-14T20:29:57Z"
}
```

If a recipe already exists for the same playbook name, it **merges** — keeping existing commands and appending new unique ones.

### 2. Generates a SKILL.md

Written to `memory/skills/<name>.md`:

```markdown
---
name: run_192.168.1.50
description: Auto-generated skill from successful pentest run
category: pentest
status: verified
trigger_pattern: run 192 168 1 50
created_at: 2026-04-14T20:29:57Z
source: reflect
---

# run_192.168.1.50

## Commands Used
- `nmap -sV -sC 192.168.1.50`
- `gobuster dir -u http://192.168.1.50 -w /usr/share/wordlists/dirb/common.txt`

## Findings
- Open port 22/tcp (ssh): OpenSSH 8.4
- Open port 80/tcp (http): Apache 2.4
- Web path found: /admin [HTTP 200]
```

### 3. Updates Tool Effectiveness

Increments `success_count` in `kali_tools.db` for each tool used in a successful run (via word matching on command strings).

---

## Campaign Mode

Multi-target campaigns are managed by `CampaignManager`:

```bash
pentestgpt campaign "Q1-RedTeam" 192.168.1.50 192.168.1.51 10.0.0.1
```

This:
1. Creates a campaign session in the database
2. Spawns a `PhaseController` per target
3. Each target follows: Recon → Enum → Vuln Scan → Exploit → Post-Exploit
4. Results and findings are persisted to the DB throughout
5. The Knowledge Graph tracks cross-target relationships (shared credentials, lateral movement paths)

### Campaign Architecture

```
CampaignManager
├── start_campaign(name, targets) → session_id
├── run(session_id) → async execution
│   ├── PhaseController (target 1)
│   │   ├── Recon phase → TaskTree
│   │   ├── Enum phase → TaskTree
│   │   └── ...
│   ├── PhaseController (target 2)
│   │   └── ...
│   └── PhaseController (target N)
│       └── ...
├── LateralMovement module
│   └── Identifies pivot opportunities between compromised hosts
└── PrivilegeEscalation module
    └── Attempts local privilege escalation on compromised hosts
```

---

## Skills System

Skills are reusable pentest playbooks stored as SKILL.md files with YAML frontmatter.

### Skill Format

```yaml
---
name: ssh_brute_force
description: Brute force SSH credentials using hydra
trigger_pattern: ssh brute|ssh password|ssh crack
category: exploitation
status: active
---

# ssh_brute_force

## Commands
- `hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt <TARGET> ssh`

## Success Condition
Hydra reports valid credentials

## Failure Signatures
- "0 valid passwords found"
- "Connection refused"
```

### Skill Lifecycle

1. **Auto-generated** by `reflect_on_run()` after successful engagements
2. **Stored** in `memory/skills/` as `.md` files
3. **Indexed** in ChromaDB for semantic search (optional)
4. **Searched** via `pentestgpt skills search "ssh brute"` or programmatically
5. **Executed** by the SkillExecutor with `<TARGET>` placeholder replacement
6. **Consolidated** periodically via LLM to merge similar skills

### Skill Statuses

| Status | Meaning |
|--------|---------|
| `DRAFT` | Newly auto-generated, not yet reviewed |
| `ACTIVE` | Reviewed and approved for reuse |
| `DEPRECATED` | Outdated or superseded |

---

## Prompt Engineering

All LLM prompts are stored as YAML files in `prompts/` and loaded at runtime:

| File | Role | Output Format |
|------|------|---------------|
| `reasoner.yaml` | Decide next pentest action from task tree | JSON: {action, task_title, task_category, task_description, reasoning, suggested_tools} |
| `generator.yaml` | Generate Kali Linux commands for a task | JSON: {commands: [...], notes: "..."} |
| `planner.yaml` | ReAct-style tool selection (function calling mode) | Tool calls or "DONE:" text |
| `parser.yaml` | Extract findings from raw tool output | JSON: {findings: [...], summary: "..."} |
| `summarizer.yaml` | Summarize tool output as bullet points | 3-7 bullet points |
| `skill_writer.yaml` | Synthesize successful runs into Skill definitions | JSON: {name, description, trigger_pattern, commands, ...} |

### Prompt Loading

```python
from pentestgpt.prompts import load_prompt

# Loads prompts/reasoner.yaml → returns the "system" key value
system_prompt = load_prompt("reasoner", fallback="default prompt string")
```

If the YAML file doesn't exist, the hardcoded fallback in the Python module is used.

---

## Project Structure

```
TopAgent/
├── AGENTS.md                          # This file
├── Readme.md                          # Basic readme
├── newplan.txt                        # NimiPlaybook design spec (reference)
├── pyproject.toml                     # Package config + entry points
├── requirements.txt                   # Runtime dependencies
│
├── config/
│   ├── config.yaml.example            # Configuration template
│   └── .env.example                   # Environment variable template
│
├── prompts/                           # LLM prompt templates (YAML)
│   ├── reasoner.yaml                  # Task tree reasoning
│   ├── generator.yaml                 # Command generation
│   ├── planner.yaml                   # ReAct-style planning
│   ├── parser.yaml                    # Output parsing
│   ├── summarizer.yaml                # Output summarization
│   └── skill_writer.yaml              # Skill synthesis
│
├── src/pentestgpt/                    # Main Python package
│   ├── __init__.py
│   ├── config.py                      # YAML config loader + env overlay
│   ├── prompts.py                     # YAML prompt loader
│   ├── scope.py                       # Scope enforcement (IP/CIDR/hostname)
│   │
│   ├── reasoning/                     # LLM orchestration
│   │   ├── reasoner.py                # Tiered Reasoner (Tier 1/2/3 + KB injection)
│   │   └── task_tree.py               # Task/TaskTree data structures
│   │
│   ├── generation/                    # Command generation
│   │   └── generator.py               # LLM → Kali commands with category hints
│   │
│   ├── executor/                      # Command execution
│   │   ├── shell_executor.py          # subprocess.run() with scope check + timeout
│   │   ├── tool_registry.py           # 12 tools with OpenAI function schemas
│   │   ├── planner_summarizer.py      # ReAct loop (plan→execute→summarize)
│   │   └── interactive_session.py     # pexpect-based interactive shell
│   │
│   ├── parser/                        # Output processing
│   │   └── parser.py                  # Regex parsers (nmap/gobuster/nikto/sqlmap/
│   │                                  #   hydra/enum4linux) + LLM fallback
│   │
│   ├── kb/                            # Knowledge Base system
│   │   ├── cli.py                     # Typer CLI: sync, doctor, stats, agent_init, run
│   │   ├── kali_tools_db.py           # SQLite: 3 tables, 31 seeded tools, query API
│   │   └── ingesters/                 # 10 intelligence source ingesters
│   │       ├── base.py                # BaseIngester ABC
│   │       ├── mitre_attck.py         # MITRE ATT&CK Enterprise (attackcti)
│   │       ├── nvd.py                 # NVD/CVE last 30 days (nvdlib)
│   │       ├── cisa_kev.py            # CISA Known Exploited Vulns (free JSON)
│   │       ├── otx.py                 # AlienVault OTX pulses (API key)
│   │       ├── threatfox.py           # ThreatFox IOCs (abuse.ch)
│   │       ├── urlhaus.py             # URLhaus malicious URLs (abuse.ch CSV)
│   │       ├── virustotal.py          # VirusTotal file hashes (API key)
│   │       ├── shodan.py              # Shodan vulnerable services (API key)
│   │       ├── abuseipdb.py           # AbuseIPDB IP reputation (API key)
│   │       └── kali_help.py           # Local tool --help enrichment
│   │
│   ├── core/                          # Self-improvement
│   │   └── reflect.py                 # Recipe + SKILL.md generation from runs
│   │
│   ├── memory/                        # Multi-store memory
│   │   ├── knowledge_graph.py         # SQLite entity/relation graph
│   │   ├── vector_store.py            # ChromaDB vector search
│   │   ├── session_diary.py           # Per-session Markdown notes
│   │   ├── memory_store.py            # Unified memory interface
│   │   └── skill_store.py             # Skill persistence + ChromaDB index
│   │
│   ├── skills/                        # Skill system
│   │   ├── skill.py                   # Skill dataclass + SKILL.md serialization
│   │   ├── skill_store.py             # Storage + search + consolidation
│   │   ├── skill_executor.py          # Execute skills with <TARGET> replacement
│   │   └── skill_writer.py            # LLM-based skill synthesis
│   │
│   ├── db/                            # Database layer
│   │   ├── gptdb.py                   # NL→SQL queries + structured storage
│   │   ├── schema.py                  # SQLAlchemy ORM models
│   │   └── vector_index.py            # Findings vector index
│   │
│   ├── campaign/                      # Multi-target orchestration
│   │   ├── campaign_manager.py        # Campaign lifecycle + async execution
│   │   ├── phase_controller.py        # Per-target PTES phase sequencing
│   │   ├── lateral_movement.py        # Cross-target pivot identification
│   │   └── privilege_escalation.py    # Local privesc automation
│   │
│   ├── aci/                           # Agent-Computer Interfaces
│   │   ├── base.py                    # Base ACI class
│   │   ├── shell_interface.py         # Standard shell
│   │   ├── msf_interface.py           # Metasploit console
│   │   ├── gdb_interface.py           # GDB debugger
│   │   └── web_interface.py           # Browser automation
│   │
│   ├── reporting/                     # Report generation
│   │   └── report_generator.py        # Markdown/HTML reports from session data
│   │
│   └── ui/                            # User interfaces
│       ├── cli.py                     # Main argparse CLI (pentestgpt command)
│       └── interactive_menu.py        # Arrow-key interactive menu + chat mode
│
├── tests/                             # Test suite (84 tests)
│   ├── test_executor.py               # ShellExecutor, ToolRegistry, PlannerSummarizer
│   ├── test_memory.py                 # KnowledgeGraph, SessionDiary, VectorStore
│   ├── test_skills.py                 # Skill serialization, SkillStore, SkillExecutor
│   ├── test_db.py                     # Schema, GptDb, VectorIndex
│   ├── test_aci.py                    # Agent-Computer Interfaces
│   └── test_campaign.py               # Campaign management
│
├── artifacts/                         # Generated artifacts
│   ├── tool_recipes/                  # JSON recipes from reflect_on_run()
│   └── playbooks/                     # Generated playbooks
│
├── db/                                # SQLite databases
│   └── kali_tools.db                  # KB database (auto-created)
│
├── memory/                            # Persistent memory
│   └── skills/                        # Generated SKILL.md files
```

---

## Development Guide

### Running Tests

```bash
# Activate virtual environment
source .venv/bin/activate

# Run all tests
PYTHONPATH=src pytest tests/ -v

# Run a specific test file
PYTHONPATH=src pytest tests/test_executor.py -v

# Run with coverage (if pytest-cov installed)
PYTHONPATH=src pytest tests/ --cov=pentestgpt --cov-report=term-missing
```

All 84 tests pass without requiring an OpenAI API key or network access.

### Adding a New Intelligence Ingester

1. Create `src/pentestgpt/kb/ingesters/my_source.py`:

```python
from pentestgpt.kb.ingesters.base import BaseIngester

class MySourceIngester(BaseIngester):
    def run(self) -> int:
        # Fetch data from your source
        resp = self._safe_get("https://api.example.com/feed")
        if resp is None:
            return 0

        count = 0
        for item in resp.json().get("data", []):
            self.db.upsert_threat_intel(
                source="my_source",
                ioc_type=item["type"],
                value=item["value"],
                context=item.get("context", ""),
                severity=item.get("severity", "medium"),
            )
            count += 1
        return count
```

2. Register it in `src/pentestgpt/kb/cli.py`:
   - Import the ingester class
   - Add to the `INGESTERS` dict
   - Add to the `SOURCE_CHOICES` list

### Adding a New Tool to the Registry

1. Add to `src/pentestgpt/executor/tool_registry.py`:

```python
ToolSpec(
    name="my_tool",
    description="Description of what it does",
    risk_level=ToolRiskLevel.ACTIVE,
    kali_command="my_tool -options <TARGET>",
    openai_function_schema={
        "type": "function",
        "function": {
            "name": "my_tool",
            "description": "...",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target IP"},
                    "flags": {"type": "string", "description": "Additional flags"},
                },
                "required": ["target"],
            },
        },
    },
)
```

2. Add structured parser in `src/pentestgpt/parser/parser.py` if the tool has well-known output format.

### Adding a New Tool to the KB Seed

Edit `src/pentestgpt/kb/kali_tools_db.py` → `_seed_if_empty()` method → add to the `seed_tools` list:

```python
("my_tool", "category", "mitre-phase", "One-line description"),
```

---

## Security & Scope Enforcement

### Scope Checker

Every command execution goes through `ScopeChecker`:

1. **Target validation**: IPs checked against allowed CIDR ranges; hostnames checked against patterns
2. **Exclusion rules**: Explicitly excluded IPs/ranges are blocked even if in target scope
3. **Command-level scanning**: `extract_hosts_from_command()` uses regex to find all IPs and hostnames in a command string and validates each

```python
scope = ScopeChecker(
    targets=["192.168.1.0/24", "example.com"],
    excluded=["192.168.1.1"]  # Gateway — don't touch
)

scope.is_in_scope("192.168.1.50")     # True
scope.is_in_scope("192.168.1.1")      # False (excluded)
scope.is_in_scope("10.0.0.1")         # False (not in scope)
scope.is_in_scope("sub.example.com")  # True (hostname match)

# Will raise ScopeViolation if command targets out-of-scope host
scope.assert_command_in_scope("nmap 192.168.1.50 10.0.0.1", "192.168.1.50")
```

### Database Query Safety

The `GptDb.query()` method:
- Only allows `SELECT` statements (rejects UPDATE, DELETE, INSERT, DROP, ALTER)
- Blocks multi-statement queries (no `;` chaining)
- Uses parameterized queries where possible
- LLM generates SQL from natural language with few-shot examples

### Ethical Framework

- All prompts include "licensed security professional with explicit written authorization"
- PTES methodology enforced in reasoning prompts
- Tool risk levels clearly documented (PASSIVE/ACTIVE/DESTRUCTIVE)
- `auto_execute: false` by default — human confirms each command
- `max_iterations` safety stop prevents runaway loops

---

## Troubleshooting

### Common Issues

**"No module named pentestgpt"**
```bash
# Option 1: Set PYTHONPATH
export PYTHONPATH=src
pentestgpt run 192.168.1.50

# Option 2: Install as package
pip install -e .
```

**"OpenAI API key not set"**
```bash
export OPENAI_API_KEY="sk-..."
# Or add to config/config.yaml or config/.env
```

**`kb sync` fails for a source**
- Run `kb doctor` to check API keys and tool availability
- Sync individual sources: `kb sync --source cisa_kev`
- ThreatFox API may require updated authentication — use other free sources

**"ScopeViolation" errors**
- Check `config/config.yaml` → `scope.targets` includes your target
- Or leave `targets: []` for unrestricted scope (development only)

**Tests fail with import errors**
```bash
PYTHONPATH=src pytest tests/ -v
```

**Tool not found in PATH (e.g., "metasploit not found")**
```bash
# Install on Kali Linux
sudo apt install metasploit-framework
# Or check: which msfconsole
```

### Verifying the KB

```bash
# Full health check
kb doctor

# Expected output:
#   DB exists: ✓ (31 tools)
#   OPENAI_API_KEY: ✓
#   Kali tools in PATH: nmap ✓  gobuster ✓  sqlmap ✓  hydra ✓  nikto ✓
#   Python packages: attackcti ✓  nvdlib ✓  stix2 ✓

# View statistics
kb stats

# Expected output:
#   Kali tools:  31
#   CVE entries: 1100+
#   Threat IOCs: 500+
```

---

*Generated: 2026-04-14*
