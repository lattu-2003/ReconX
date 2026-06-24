```
╦═╗┌─┐┌─┐┌─┐┌┐┌╔═╗
╠╦╝├┤ │  │ ││││╠╩╗
╩╚═└─┘└─┘└─┘┘└┘╚═╝
```

# ReconX — Attack Surface Intelligence Framework

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)
![License MIT](https://img.shields.io/badge/License-MIT-green)
![Platform Linux](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)

---

## What is ReconX?

ReconX is an **intelligence layer** for attack surface reconnaissance — it is **NOT** a wrapper around existing tools.

While traditional recon scripts simply chain tools together and dump raw output, ReconX **orchestrates** tool execution, **correlates** findings across modules, **enriches** data with context, **scores** assets by risk, and **reports** actionable intelligence in multiple formats.

Every discovered asset flows through a unified pipeline where it is deduplicated, validated, classified, scored, and stored in a structured database. The result is not a pile of text files — it's a prioritized, queryable attack surface map.

---

## Why ReconX?

### Traditional Workflow

```
subfinder -d target.com -o subs.txt
cat subs.txt | httpx -o live.txt
cat live.txt | katana -o urls.txt
cat urls.txt | nuclei -o findings.txt

# Now what?
# - Thousands of lines across 4 files
# - No correlation between findings
# - No prioritization
# - No change tracking
# - Manual analysis required
```

### ReconX Workflow

```
reconx deep target.com

# Complete pipeline with intelligence:
# ✔ Asset Discovery     → deduplicated, scope-validated subdomains
# ✔ Port Scanning       → correlated with each subdomain
# ✔ HTTP Validation     → live hosts with tech fingerprinting
# ✔ Visual Recon        → screenshot capture for rapid triage
# ✔ Web Crawling        → endpoint extraction + classification
# ✔ Historical Recon    → Wayback Machine + GAU archive mining
# ✔ JS Intelligence     → secrets, API keys, endpoints from JS files
# ✔ Risk Scoring        → every asset scored 0-100
# ✔ Vuln Scanning       → smart, targeted Nuclei scanning
# ✔ Change Detection    → diff against previous scans
# ✔ Reporting           → HTML, JSON, Markdown reports generated
```

---

## Features

| | Feature | Description |
|---|---|---|
| 🔍 | **Asset Discovery** | Subdomain enumeration via Subfinder with scope validation |
| 🔌 | **Port Scanning** | Fast port scanning via Naabu with service correlation |
| 🌐 | **HTTP Validation** | Live host detection with technology fingerprinting via Httpx |
| 📸 | **Visual Recon** | Automated screenshot capture for rapid visual triage |
| 🕷️ | **Web Crawling** | Deep endpoint extraction and URL harvesting via Katana |
| 📜 | **Historical Recon** | Wayback Machine and archive mining via GAU |
| ⚡ | **JS Intelligence** | JavaScript file analysis for secrets, API keys, and hidden endpoints |
| 🏷️ | **Endpoint Classification** | Automatic categorization of discovered URLs by type and risk |
| 📊 | **Risk Scoring** | Intelligent 0–100 scoring based on tech stack, status codes, and keywords |
| 🛡️ | **Smart Vulnerability Scanning** | Targeted Nuclei scans informed by discovered technology context |
| 🔄 | **Change Detection** | Diff-based comparison between scan runs for continuous monitoring |
| 🎯 | **Scope Management** | Wildcard-aware scope enforcement with in/out-of-scope rules |
| 📋 | **Multi-format Reporting** | Professional HTML, structured JSON, and readable Markdown reports |
| 🔒 | **Security Hardened** | Input validation, path traversal protection, and full audit logging |

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/lattu-2003/reconx.git
cd reconx

# Create virtual environment (required on Kali/Parrot/modern Debian)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and install
pip install --upgrade pip setuptools wheel
pip install -e .

# Verify all tools are available
reconx status

# Run your first scan
reconx quick target.com
```

> **Note:** See [DEPLOYMENT.md](DEPLOYMENT.md) for full installation instructions including prerequisite tools.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        ReconX Pipeline                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Target ──► Scope      ──► Subfinder  ──► Naabu   ──► Httpx    │
│             Validation      (discover)     (ports)     (probe)  │
│                                                                 │
│          ──► Katana    ──► GAU        ──► JS       ──► Nuclei   │
│              (crawl)       (history)      (analyze)    (scan)   │
│                                                                 │
│          ──► Endpoint  ──► Risk       ──► Change   ──► Report   │
│              Classify      Scoring        Detect       Generate │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  SQLite DB ◄──── All results stored ────► Audit Log             │
└─────────────────────────────────────────────────────────────────┘
```

Each module receives validated input from the previous stage, processes it through the corresponding external tool (subprocess, never shell), and feeds enriched output into the next stage. All data is persisted to a local SQLite database for querying, comparison, and reporting.

---

## Scan Profiles

| Profile | Modules Executed | Use Case |
|---|---|---|
| **quick** | Subfinder → Httpx | Rapid triage of a new target in under 2 minutes |
| **standard** | Subfinder → Naabu → Httpx → Katana → Nuclei | Normal bug bounty or pentest workflow |
| **deep** | All modules (incl. GAU, JS analysis, screenshots) | Maximum coverage for high-value targets |

```bash
reconx quick target.com       # Fast recon
reconx standard target.com    # Balanced coverage
reconx deep target.com        # Full intelligence
```

---

## Security

ReconX is built with security as a first-class concern:

1. **Input Validation** — All targets and parameters are validated against strict patterns
2. **Command Injection Prevention** — Subprocess calls use `shell=False` with argument lists, never string interpolation
3. **Path Traversal Protection** — All file paths are validated and confined to the workspace
4. **Scope Enforcement** — Targets are checked against the defined scope before every operation
5. **Output Sanitization** — Tool output is sanitized before processing and storage
6. **Audit Logging** — Every command executed is logged with full arguments and timestamps
7. **Rate Limiting** — Configurable rate limits to prevent accidental abuse

---

## Documentation

| Document | Description |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Full installation and deployment guide |
| [USAGE.md](USAGE.md) | Comprehensive usage manual and command reference |

---

## Requirements

- **Python** 3.12 or higher
- **Operating System:** Linux (Parrot OS, Kali Linux, Ubuntu recommended)
- **Go** 1.21+ (for installing ProjectDiscovery tools)
- **External Tools:** Subfinder, Naabu, Httpx, Katana, Nuclei, GAU

---

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## ⚠️ Disclaimer

**This tool is intended for authorized security testing and research only.**

Users are solely responsible for obtaining proper written authorization before scanning any target. Unauthorized scanning of systems you do not own or have explicit permission to test is illegal and unethical. The authors of ReconX assume no liability for misuse of this software. Always comply with applicable laws, regulations, and the target's terms of service.
