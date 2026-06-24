# ReconX — Deployment Guide

Complete guide for installing ReconX and all required dependencies on Linux.

---

## Prerequisites

Before starting, ensure you have (or will install) the following:

| Requirement | Minimum Version | Check Command |
|---|---|---|
| Python | 3.12+ | `python3 --version` |
| Go | 1.21+ | `go version` |
| Git | any | `git --version` |
| pip | any | `pip --version` |
| libpcap-dev | any | `dpkg -l libpcap-dev` |

> [!IMPORTANT]
> **libpcap-dev** is required for Naabu (port scanner) to compile. Installation will fail without it.

---

## Step 1: System Preparation (Parrot OS / Kali / Ubuntu)

Update your system and install core dependencies:

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv git golang libpcap-dev
```

Verify Python version:

```bash
python3 --version
# Expected: Python 3.12.x or higher
```

> [!NOTE]
> On Parrot OS and Kali, Python 3.12+ and Go are typically pre-installed. On Ubuntu, you may need to add a PPA for Python 3.12.

---

## Step 2: Go Setup

If Go is already installed via `apt` and is version 1.21+, skip this step.

### Manual Go Installation

```bash
# Download Go
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz

# Remove any previous installation and extract
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz

# Clean up
rm go1.22.4.linux-amd64.tar.gz
```

### Configure Go Environment

Add the following to your shell profile (`~/.bashrc`, `~/.zshrc`, or `~/.profile`):

```bash
# Go environment
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
```

Apply changes:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

Verify:

```bash
go version
# Expected: go version go1.22.4 linux/amd64 (or higher)
```

---

## Step 3: Install Reconnaissance Tools

Install each tool individually using `go install`. All binaries will be placed in `$GOPATH/bin`.

### Subfinder — Subdomain Discovery

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### Naabu — Port Scanner

```bash
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```

> [!NOTE]
> Naabu requires `libpcap-dev` to compile. If the build fails, run: `sudo apt install -y libpcap-dev`

### Httpx — HTTP Probing & Fingerprinting

```bash
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Katana — Web Crawler

```bash
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

### Nuclei — Vulnerability Scanner

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### GAU — Historical URL Fetcher

```bash
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

### Verify All Tools

Run each command to confirm installation:

```bash
subfinder -version
naabu -version
httpx -version
katana -version
nuclei -version
gau -version
```

All commands should print a version string without errors. If any command returns `command not found`, see the [Troubleshooting](#troubleshooting) section.

---

## Step 4: Install ReconX

### Clone and Install

```bash
# Clone the repository
git clone https://github.com/lattu-2003/reconx.git
cd reconx

# Create a virtual environment (REQUIRED on Kali/Parrot/modern Debian — PEP 668)
python3 -m venv .venv
source .venv/bin/activate

# Upgrade pip and core build tools
pip install --upgrade pip setuptools wheel

# Install ReconX in editable/development mode
pip install -e .
```

> [!IMPORTANT]
> Modern Debian-based distros (Kali, Parrot, Ubuntu 23.04+) enforce **PEP 668** — you **must** use a virtual environment. Running `pip install` outside a venv will fail with `error: externally-managed-environment`.

### Verify the CLI

```bash
reconx --help
```

You should see the ReconX help output with available commands.

---

## Step 5: Verify Installation

Run the built-in status check to verify all dependencies:

```bash
reconx status
```

### Expected Output

```
ReconX — Tool Status
┌──────────┬──────────┬───────────┐
│ Tool     │ Status   │ Version   │
├──────────┼──────────┼───────────┤
│ subfinder│ ✅ Found │ v2.6.7    │
│ naabu    │ ✅ Found │ v2.3.2    │
│ httpx    │ ✅ Found │ v1.6.9    │
│ katana   │ ✅ Found │ v1.1.2    │
│ nuclei   │ ✅ Found │ v3.3.6    │
│ gau      │ ✅ Found │ v2.2.3    │
└──────────┴──────────┴───────────┘
All tools available. ReconX is ready.
```

If any tool shows `❌ Not Found`, install it using the commands in [Step 3](#step-3-install-reconnaissance-tools).

---

## Step 6: Initial Configuration

ReconX uses environment variables with the `RECONX_` prefix for configuration. You can set these in your shell or via a `.env` file in the project root.

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `RECONX_DB_PATH` | `~/.reconx/reconx.db` | Path to the SQLite database |
| `RECONX_RESULTS_DIR` | `~/.reconx/results` | Directory for scan results and reports |
| `RECONX_LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `RECONX_THREADS` | `10` | Default thread count for tools |
| `RECONX_RATE_LIMIT` | `150` | Default rate limit (requests/second) |
| `RECONX_TIMEOUT` | `30` | Default timeout in seconds for tool execution |
| `RECONX_AUDIT_LOG` | `~/.reconx/audit.log` | Path to the audit log file |

### Using a .env File

Create a `.env` file in the ReconX project root:

```bash
# .env — ReconX Configuration
RECONX_DB_PATH=/home/user/.reconx/reconx.db
RECONX_RESULTS_DIR=/home/user/.reconx/results
RECONX_LOG_LEVEL=INFO
RECONX_THREADS=10
RECONX_RATE_LIMIT=150
RECONX_TIMEOUT=30
```

ReconX will automatically load this file on startup.

---

## Updating

### Update Reconnaissance Tools

Re-run the same `go install` commands to update each tool to the latest version:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
```

### Update Nuclei Templates

```bash
nuclei -update-templates
```

### Update ReconX

```bash
cd reconx
git pull
pip install -e .
```

---

## Troubleshooting

### `command not found` for Go tools

**Cause:** `$GOPATH/bin` is not in your `PATH`.

**Fix:**

```bash
# Add to your shell profile (~/.bashrc or ~/.zshrc):
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

# Then reload:
source ~/.bashrc
```

### Naabu permission error (`socket: operation not permitted`)

**Cause:** Naabu uses raw sockets for SYN scanning, which requires elevated privileges.

**Fix (Option A — run as root):**

```bash
sudo reconx standard target.com
```

**Fix (Option B — set capability):**

```bash
sudo setcap cap_net_raw=ep $(which naabu)
```

### Go install fails with build errors

**Cause:** Go version is too old for the tool's `go.mod` requirements.

**Fix:**

```bash
go version
# If below 1.21, reinstall Go using the manual installation in Step 2
```

### Python version mismatch

**Cause:** System default `python3` points to an older version.

**Fix:**

```bash
# Check available versions
ls /usr/bin/python3*

# Use the specific version
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Database locked errors

**Cause:** Another ReconX process is running or a scan was interrupted.

**Fix:**

```bash
# Check for running processes
ps aux | grep reconx

# If no processes are running, the lock is stale:
rm ~/.reconx/reconx.db-journal
```

---

## Uninstallation

### Remove ReconX

```bash
# Deactivate virtual environment if active
deactivate

# Uninstall the package
pip uninstall reconx

# Remove ReconX data (database, results, audit logs)
rm -rf ~/.reconx

# Optionally remove the source code
rm -rf /path/to/reconx
```

### Remove Go Tools (optional)

```bash
rm -f $GOPATH/bin/subfinder
rm -f $GOPATH/bin/naabu
rm -f $GOPATH/bin/httpx
rm -f $GOPATH/bin/katana
rm -f $GOPATH/bin/nuclei
rm -f $GOPATH/bin/gau
```
