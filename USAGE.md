# ReconX — Usage Manual

Comprehensive guide to using ReconX for attack surface reconnaissance.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
  - [reconx quick](#reconx-quick-target)
  - [reconx standard](#reconx-standard-target)
  - [reconx deep](#reconx-deep-target)
  - [reconx report](#reconx-report-target)
  - [reconx compare](#reconx-compare-target)
  - [reconx scope](#reconx-scope-addremoveshow)
  - [reconx status](#reconx-status)
- [Scan Profiles Deep Dive](#scan-profiles-deep-dive)
- [Workflow Examples](#workflow-examples)
- [Understanding Risk Scores](#understanding-risk-scores)
- [Reading Reports](#reading-reports)
- [Advanced Configuration](#advanced-configuration)
- [Best Practices](#best-practices)
- [Legal & Ethical Disclaimer](#legal--ethical-disclaimer)

---

## Quick Start

Get your first scan running in under 2 minutes:

```bash
# 1. Verify all tools are installed
reconx status

# 2. Run a quick scan against your authorized target
reconx quick target.com

# 3. View the generated report
# Reports are saved to ~/.reconx/results/target.com/
```

That's it. ReconX discovers subdomains, probes for live hosts, and generates a structured report — all in a single command.

---

## Command Reference

### `reconx quick <target>`

**Rapid triage scan** — the fastest way to assess a new target.

```bash
reconx quick target.com
```

**Pipeline:** Subfinder → Httpx

**What it does:**
1. Enumerates subdomains using Subfinder
2. Probes discovered subdomains with Httpx to identify live hosts
3. Extracts basic technology fingerprints from HTTP responses
4. Calculates initial risk scores for each live asset
5. Generates a summary report

**Use case:** You've just been handed a new scope. Run `quick` to get an immediate picture of the attack surface before committing to a full scan.

**Example:**

```bash
$ reconx quick example.com

ReconX — Quick Scan
Target: example.com

[1/2] Subdomain Discovery (Subfinder)
  ✔ Found 147 subdomains

[2/2] HTTP Probing (Httpx)
  ✔ 89 live hosts identified

Summary:
  Subdomains: 147
  Live Hosts:  89
  Risk: High    12 assets
        Medium  34 assets
        Low     43 assets

Report saved: ~/.reconx/results/example.com/quick_20250620.html
```

---

### `reconx standard <target>`

**Balanced reconnaissance** — full pipeline without historical and JS analysis.

```bash
reconx standard target.com
```

**Pipeline:** Subfinder → Naabu → Httpx → Katana → Nuclei

**What it does:**
1. Enumerates subdomains
2. Scans ports on discovered assets
3. Probes live hosts with technology fingerprinting
4. Crawls discovered web applications for endpoints
5. Classifies and scores all discovered endpoints
6. Runs targeted Nuclei vulnerability scans
7. Generates a full report

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--threads` | `10` | Number of concurrent threads per tool |
| `--rate-limit` | `150` | Maximum requests per second |
| `--timeout` | `30` | Timeout in seconds for each tool |
| `--ports` | `top-100` | Port list: `top-100`, `top-1000`, `full`, or custom (e.g., `80,443,8080`) |

**Examples:**

```bash
# Standard scan with defaults
reconx standard target.com

# Slower, stealthier scan
reconx standard target.com --threads 3 --rate-limit 50

# Scan specific ports
reconx standard target.com --ports 80,443,8080,8443

# Full port scan with higher timeout
reconx standard target.com --ports full --timeout 60
```

---

### `reconx deep <target>`

**Maximum coverage** — every module enabled, including historical recon and JS intelligence.

```bash
reconx deep target.com
```

**Pipeline:** Subfinder → Naabu → Httpx → Screenshots → Katana → GAU → JS Analysis → Endpoint Classification → Risk Scoring → Nuclei → Change Detection → Report

**What it does:**
Everything in `standard`, plus:
1. Captures screenshots of all live hosts for visual triage
2. Mines historical URLs from Wayback Machine and other archives via GAU
3. Downloads and analyzes JavaScript files for secrets, API keys, and hidden endpoints
4. Performs comprehensive endpoint classification
5. Runs change detection against the previous scan (if one exists)

**Flags:** Same as `standard`, plus:

| Flag | Default | Description |
|---|---|---|
| `--screenshots` | `true` | Enable/disable screenshot capture |
| `--js-analysis` | `true` | Enable/disable JavaScript analysis |

**Examples:**

```bash
# Full deep scan
reconx deep target.com

# Deep scan without screenshots (faster)
reconx deep target.com --screenshots false

# Deep scan with stealth settings
reconx deep target.com --threads 2 --rate-limit 30
```

> [!IMPORTANT]
> Deep scans take significantly longer than quick or standard scans. Use this profile for high-value targets where maximum coverage is essential.

---

### `reconx report <target>`

**Generate or regenerate reports** from existing scan data.

```bash
reconx report target.com
```

**Flags:**

| Flag | Default | Description |
|---|---|---|
| `--format` | `all` | Output format: `html`, `json`, `markdown`, or `all` |

**Examples:**

```bash
# Generate all report formats
reconx report target.com

# Generate only JSON (for automation/integration)
reconx report target.com --format json

# Generate only HTML (for client delivery)
reconx report target.com --format html

# Generate only Markdown (for notes/wikis)
reconx report target.com --format markdown
```

**Report locations:**

```
~/.reconx/results/<target>/
├── report_20250620_143022.html
├── report_20250620_143022.json
└── report_20250620_143022.md
```

---

### `reconx compare <target>`

**Diff two scans** to identify changes in the attack surface.

```bash
reconx compare target.com
```

**What it does:**
1. Loads the two most recent scan results for the target
2. Compares subdomains: identifies new and removed entries
3. Compares live hosts: identifies newly responsive and newly down hosts
4. Compares findings: identifies new vulnerabilities and resolved ones
5. Outputs a change summary

**Example:**

```bash
$ reconx compare target.com

ReconX — Change Detection
Target: target.com
Comparing: scan_20250615 → scan_20250620

Subdomains:
  + new-api.target.com        (NEW)
  + staging-v2.target.com     (NEW)
  - old-portal.target.com     (REMOVED)

Live Hosts:
  + https://new-api.target.com   (NEW — 200 OK)
  - http://legacy.target.com     (DOWN)

Findings:
  + [MEDIUM] Exposed .git directory on staging-v2.target.com
  + [LOW]    Missing security headers on new-api.target.com

Changes saved: ~/.reconx/results/target.com/compare_20250620.json
```

---

### `reconx scope add/remove/show`

**Manage the scan scope** to control what gets scanned.

#### Add targets to scope

```bash
# Add a single domain
reconx scope add target.com

# Add a wildcard (all subdomains)
reconx scope add "*.target.com"

# Add multiple domains
reconx scope add target.com api.target.com cdn.target.com
```

#### Remove targets from scope

```bash
# Remove a domain
reconx scope remove staging.target.com

# Exclude a specific subdomain from a wildcard scope
reconx scope remove internal.target.com
```

#### View current scope

```bash
$ reconx scope show

ReconX — Scope Configuration

In-Scope:
  ✔ *.target.com
  ✔ api.partner.com

Out-of-Scope:
  ✘ internal.target.com
  ✘ vpn.target.com
```

**Wildcard examples:**

| Pattern | Matches |
|---|---|
| `target.com` | Only `target.com` |
| `*.target.com` | Any subdomain: `api.target.com`, `dev.target.com`, etc. |
| `*.api.target.com` | Nested subdomains: `v1.api.target.com`, `v2.api.target.com` |

> [!NOTE]
> Scope is enforced before every tool execution. Discovered assets that fall outside scope are logged but not processed further.

---

### `reconx status`

**Check tool availability** and system readiness.

```bash
reconx status
```

Verifies that all required external tools are installed and accessible on `PATH`. Reports the version of each tool found.

---

## Scan Profiles Deep Dive

### When to Use Each Profile

#### Quick — "What am I looking at?"

**Scenario:** A client just sent you a list of 5 root domains for a new engagement. Before planning your approach, you need to understand the size and shape of the attack surface.

```bash
reconx quick client-domain.com
```

**Time:** 1–3 minutes per domain
**Output:** Subdomain count, live host count, initial risk distribution

#### Standard — "Normal workday recon"

**Scenario:** You're working a bug bounty program and need thorough coverage of a target. You want to find subdomains, open ports, live web apps, crawl them for endpoints, and run vulnerability checks.

```bash
reconx standard bugbounty-target.com --ports top-1000
```

**Time:** 10–30 minutes depending on target size
**Output:** Full asset inventory with ports, endpoints, technologies, and vulnerability findings

#### Deep — "Leave no stone unturned"

**Scenario:** You have a high-value target with a large payout. You want historical URLs that might reveal forgotten endpoints, JavaScript analysis to find API keys, and screenshots for manual review.

```bash
reconx deep high-value-target.com
```

**Time:** 30–90 minutes depending on target size
**Output:** Complete intelligence package with historical data, JS secrets, screenshots, and change detection

---

## Workflow Examples

### 1. Bug Bounty Workflow

Step-by-step workflow for a typical bug bounty engagement:

```bash
# Step 1: Define scope
reconx scope add "*.target.com"
reconx scope remove vpn.target.com
reconx scope remove mail.target.com

# Step 2: Quick triage to understand the surface
reconx quick target.com

# Step 3: Review the quick report, identify interesting areas

# Step 4: Full standard scan
reconx standard target.com --ports top-1000

# Step 5: Review risk scores — focus on high/critical assets first
# Open the HTML report for visual review

# Step 6: For promising targets, run deep scan
reconx deep target.com

# Step 7: Generate a clean report for your records
reconx report target.com --format all
```

### 2. Penetration Testing Workflow

Structured approach for a professional penetration test:

```bash
# Step 1: Define strict scope from the engagement contract
reconx scope add target.com
reconx scope add "*.target.com"
reconx scope remove "*.internal.target.com"

# Step 2: Standard scan with conservative rate limiting
reconx standard target.com --threads 5 --rate-limit 50

# Step 3: Deep scan for thorough coverage
reconx deep target.com --threads 5 --rate-limit 50

# Step 4: Generate client-ready report
reconx report target.com --format html

# Step 5: Export raw data for manual analysis
reconx report target.com --format json
```

### 3. Continuous Monitoring Workflow

Ongoing attack surface monitoring for long-term programs:

```bash
# Initial baseline scan
reconx deep target.com

# Weekly re-scan (cron job or manual)
reconx standard target.com

# After each re-scan, check for changes
reconx compare target.com

# Review new findings and act on critical changes
# Investigate new subdomains, new open ports, new vulnerabilities
```

Set up a cron job for automated weekly scans:

```bash
# Run every Monday at 2 AM
0 2 * * 1 /path/to/.venv/bin/reconx standard target.com && /path/to/.venv/bin/reconx compare target.com
```

---

## Understanding Risk Scores

ReconX assigns every discovered asset a **risk score from 0 to 100**. The score is calculated based on multiple factors observed during reconnaissance.

### Score Calculation

The risk score is a weighted sum of bonuses applied when specific indicators are detected:

#### Keyword Bonuses

Points added when URLs or paths contain high-value keywords:

| Keyword | Points | Rationale |
|---|---|---|
| `admin` | +15 | Administrative interface — high-value target |
| `api` | +10 | API endpoint — potential data exposure |
| `login` | +10 | Authentication page — credential attacks |
| `upload` | +15 | File upload — potential RCE vector |
| `config` | +15 | Configuration file — sensitive data leak |
| `backup` | +15 | Backup file — data exposure |
| `debug` | +20 | Debug endpoint — information disclosure |
| `test` | +10 | Test/staging — often less secured |
| `dev` | +10 | Development environment — weaker controls |
| `staging` | +10 | Staging environment — pre-production |
| `.env` | +20 | Environment file — credentials/secrets |
| `.git` | +20 | Git repository — source code exposure |
| `wp-admin` | +15 | WordPress admin — well-known attack surface |
| `phpmyadmin` | +20 | Database admin — critical if exposed |
| `graphql` | +10 | GraphQL endpoint — introspection attacks |
| `swagger` | +15 | API documentation — information disclosure |

#### Technology Bonuses

Points added based on detected technology stack:

| Technology | Points | Rationale |
|---|---|---|
| WordPress | +10 | Large plugin attack surface |
| Joomla | +10 | Known CMS vulnerabilities |
| Drupal | +10 | Complex CMS with history of CVEs |
| PHP | +5 | Language with common misconfigurations |
| ASP.NET | +5 | Often paired with legacy configurations |
| Tomcat | +10 | Application server — management console |
| Jenkins | +15 | CI/CD — code execution if exposed |
| GitLab | +10 | Source code management — high value |
| Grafana | +10 | Monitoring — internal data exposure |
| Kibana | +10 | Log analytics — sensitive data |
| Elasticsearch | +15 | Database — often unsecured by default |
| Redis | +15 | Cache/DB — commonly exposed without auth |

#### Status Code Bonuses

Points added based on HTTP response codes:

| Status Code | Points | Rationale |
|---|---|---|
| 200 | +5 | Accessible — baseline score |
| 301/302 | +0 | Redirect — minimal direct risk |
| 401 | +10 | Auth required — worth investigating |
| 403 | +10 | Forbidden — potential bypass opportunity |
| 500 | +15 | Server error — misconfig or vulnerability |
| 502/503 | +5 | Backend issue — potential infrastructure info |

### Score Interpretation

| Score Range | Severity | Recommended Action |
|---|---|---|
| **0 – 25** | 🟢 Low | Standard monitoring, lowest priority |
| **25 – 50** | 🟡 Medium | Review during normal workflow |
| **50 – 75** | 🟠 High | Investigate promptly, potential findings |
| **75 – 100** | 🔴 Critical | Investigate immediately, likely high-value targets |

---

## Reading Reports

### HTML Report

The HTML report is designed for visual review and client delivery. Sections include:

1. **Executive Summary** — Target, scan profile, date, total counts
2. **Asset Inventory** — Table of all discovered subdomains and their status
3. **Live Hosts** — Detailed view of responsive hosts with technologies
4. **Risk Dashboard** — Distribution chart of risk scores
5. **High-Risk Assets** — Prioritized list of assets scoring 50+
6. **Vulnerability Findings** — Nuclei results organized by severity
7. **Endpoints** — Classified URL list with categories
8. **Change Detection** — Diff summary (if previous scan exists)

### JSON Report

Structured data for automation and integration:

```json
{
  "meta": {
    "target": "target.com",
    "profile": "standard",
    "timestamp": "2025-06-20T14:30:22Z",
    "version": "1.0.0"
  },
  "summary": {
    "subdomains_total": 147,
    "live_hosts": 89,
    "open_ports": 234,
    "endpoints": 1547,
    "findings": 12
  },
  "subdomains": [...],
  "hosts": [...],
  "ports": [...],
  "endpoints": [...],
  "findings": [...],
  "risk_scores": [...]
}
```

### Markdown Report

Clean text format suitable for note-taking, wikis, and documentation:

```markdown
# ReconX Report — target.com
**Profile:** standard | **Date:** 2025-06-20

## Summary
- Subdomains: 147
- Live Hosts: 89
- Findings: 12 (3 High, 5 Medium, 4 Low)

## High-Risk Assets
| Asset | Score | Reason |
|---|---|---|
| admin.target.com | 85 | Admin panel, WordPress, debug enabled |
| api-dev.target.com | 72 | Dev API, Swagger exposed |
...
```

---

## Advanced Configuration

### Environment Variables

All configuration can be controlled via environment variables with the `RECONX_` prefix:

| Variable | Default | Description |
|---|---|---|
| `RECONX_DB_PATH` | `~/.reconx/reconx.db` | SQLite database path |
| `RECONX_RESULTS_DIR` | `~/.reconx/results` | Results and reports directory |
| `RECONX_LOG_LEVEL` | `INFO` | Log level: DEBUG, INFO, WARNING, ERROR |
| `RECONX_THREADS` | `10` | Default thread count |
| `RECONX_RATE_LIMIT` | `150` | Max requests per second |
| `RECONX_TIMEOUT` | `30` | Tool execution timeout (seconds) |
| `RECONX_AUDIT_LOG` | `~/.reconx/audit.log` | Audit log file path |
| `RECONX_PORTS` | `top-100` | Default port list |

### Custom Port Lists

```bash
# Top 100 most common ports (fast)
reconx standard target.com --ports top-100

# Top 1000 ports (thorough)
reconx standard target.com --ports top-1000

# Full 65535 port scan (slow but complete)
reconx standard target.com --ports full

# Custom port list
reconx standard target.com --ports 80,443,8080,8443,9090,3000,5000

# Common web + database ports
reconx standard target.com --ports 80,443,3306,5432,6379,27017,9200
```

### Rate Limiting for Stealth

Reduce scan speed to avoid detection and minimize impact:

```bash
# Ultra-stealth: 10 req/s, 2 threads
reconx standard target.com --rate-limit 10 --threads 2

# Low-profile: 30 req/s, 3 threads
reconx standard target.com --rate-limit 30 --threads 3

# Normal: 150 req/s, 10 threads (default)
reconx standard target.com

# Aggressive (authorized internal testing only): 500 req/s, 50 threads
reconx standard target.com --rate-limit 500 --threads 50
```

### Thread Tuning

Thread count affects how many concurrent operations each tool performs:

| Threads | Use Case |
|---|---|
| 1–3 | Stealth / rate-limited environments |
| 5–10 | Standard external testing |
| 10–25 | Fast internal network testing |
| 25–50 | Authorized aggressive testing |

> [!WARNING]
> High thread counts combined with high rate limits can overwhelm targets or trigger WAF blocks. Always start conservative and escalate.

---

## Best Practices

### 1. Always Verify Authorization Before Scanning

Never scan a target without explicit written authorization. Verify your scope document covers the domains and IP ranges you're about to test.

### 2. Start with Quick, Escalate to Deep

Begin with `reconx quick` to understand the surface, then run `standard` for thorough coverage. Only use `deep` when the target warrants maximum effort.

### 3. Review Risk Scores Before Manual Testing

Focus manual testing on assets with risk scores above 50. These are the most likely to yield findings and provide the best return on your time.

### 4. Use Scope Management for Every Engagement

Always define your scope in ReconX before scanning. This prevents accidental out-of-scope scanning and provides a clear audit trail.

```bash
reconx scope add "*.target.com"
reconx scope remove internal.target.com
reconx scope show  # Verify before scanning
```

### 5. Run Compare Regularly for Continuous Programs

For long-running bug bounty programs, run scans weekly and use `reconx compare` to catch new assets before other researchers do.

### 6. Keep Tools Updated

Reconnaissance tools are updated frequently with new features, bug fixes, and signature updates. Update regularly:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
# ... update all tools
```

### 7. Review Audit Logs After Engagements

ReconX logs every command executed with full arguments and timestamps. Review the audit log (`~/.reconx/audit.log`) after each engagement to ensure all activity was within scope and can be documented for your report.

```bash
cat ~/.reconx/audit.log | grep "target.com"
```

---

## Legal & Ethical Disclaimer

> [!CAUTION]
> **This tool is designed for authorized security testing only.**

### Your Responsibilities

1. **Obtain written authorization** before scanning any target. A verbal agreement is not sufficient.
2. **Verify scope boundaries** — ensure every domain, subdomain, and IP range you scan is explicitly covered in your authorization document.
3. **Comply with all applicable laws** — unauthorized computer access is a criminal offense in most jurisdictions (CFAA in the US, Computer Misuse Act in the UK, and equivalent laws worldwide).
4. **Respect rate limits and availability** — even with authorization, do not overwhelm production systems. Use appropriate thread and rate-limit settings.
5. **Report findings responsibly** — follow responsible disclosure practices. Do not publicly disclose vulnerabilities without the target organization's consent.
6. **Maintain confidentiality** — treat all data discovered during testing as confidential. Do not share scan results, reports, or findings with unauthorized parties.

### Liability

The authors and contributors of ReconX provide this software "as-is" without warranty of any kind. Users are solely responsible for their use of this tool. The authors assume no liability for damages resulting from the use or misuse of this software.

### Bug Bounty Programs

When using ReconX for bug bounty programs:
- Read and follow the program's rules of engagement
- Respect out-of-scope designations
- Do not test for denial-of-service unless explicitly permitted
- Report findings through the program's official channel
- Do not access, modify, or exfiltrate user data

**When in doubt, don't scan. Ask first.**
