"""
ReconX Core Utilities

Shared helper functions for deduplication, JSONL parsing,
file handling, and data formatting.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def parse_jsonl(raw_output: str) -> list[dict[str, Any]]:
    """
    Parse newline-delimited JSON (JSONL) output from CLI tools.

    ProjectDiscovery tools (subfinder, httpx, naabu, katana, nuclei)
    all emit one JSON object per line. Non-JSON lines (banners,
    progress indicators) are silently skipped.

    Args:
        raw_output: Raw stdout string from a tool subprocess.

    Returns:
        List of parsed JSON objects.
    """
    results: list[dict[str, Any]] = []
    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                results.append(obj)
        except (json.JSONDecodeError, ValueError):
            continue
    return results


def deduplicate(items: list[str]) -> list[str]:
    """
    Deduplicate a list of strings while preserving order.

    Args:
        items: List of strings, possibly with duplicates.

    Returns:
        Deduplicated list maintaining original order.
    """
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip().lower()
        if normalized and normalized not in seen:
            seen.add(normalized)
            result.append(item.strip())
    return result


def deduplicate_dicts(
    items: list[dict[str, Any]], key: str
) -> list[dict[str, Any]]:
    """
    Deduplicate a list of dictionaries by a specific key.

    Args:
        items: List of dicts to deduplicate.
        key: Dictionary key to use for deduplication.

    Returns:
        Deduplicated list maintaining original order.
    """
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for item in items:
        value = str(item.get(key, "")).strip().lower()
        if value and value not in seen:
            seen.add(value)
            result.append(item)
    return result


def sanitize_filename(domain: str) -> str:
    """
    Convert a domain name into a safe filename.

    Args:
        domain: Domain name (e.g., 'admin.target.com').

    Returns:
        Filesystem-safe string (e.g., 'admin_target_com').
    """
    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    # Remove trailing slashes/paths
    domain = domain.split("/")[0]
    # Replace unsafe characters
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", domain)
    return safe.strip("._-") or "unknown"


def ensure_dir(path: Path) -> Path:
    """
    Create a directory and all parents if they don't exist.

    Args:
        path: Directory path to create.

    Returns:
        The created/existing directory path.
    """
    path.mkdir(parents=True, exist_ok=True)
    return path


def extract_root_domain(subdomain: str) -> str:
    """
    Extract the root domain from a subdomain.

    Examples:
        admin.test.target.com -> target.com
        target.com -> target.com

    Args:
        subdomain: Full subdomain string.

    Returns:
        Root domain (last two parts).
    """
    parts = subdomain.strip().lower().split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return subdomain.strip().lower()


def build_url(host: str, port: int | None = None, scheme: str | None = None) -> str:
    """
    Build a URL from host and optional port/scheme.

    Args:
        host: Hostname or IP address.
        port: Optional port number.
        scheme: Optional scheme (http/https). Auto-detected from port if not given.

    Returns:
        Formatted URL string.
    """
    if "://" in host:
        return host

    if scheme is None:
        if port in (443, 8443):
            scheme = "https"
        else:
            scheme = "http"

    if port and port not in (80, 443):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def extract_host_from_url(url: str) -> str:
    """
    Extract hostname from a URL.

    Args:
        url: Full URL string.

    Returns:
        Hostname component.
    """
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return url


def format_count(count: int) -> str:
    """
    Format a number with commas for display.

    Args:
        count: Integer to format.

    Returns:
        Formatted string (e.g., '1,234').
    """
    return f"{count:,}"


def write_lines_to_file(filepath: Path, lines: list[str]) -> Path:
    """
    Write a list of strings to a file, one per line.

    Used to create input files for tools (e.g., target lists).

    Args:
        filepath: Output file path.
        lines: List of strings to write.

    Returns:
        The filepath that was written.
    """
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return filepath


def read_targets_file(filepath: Path) -> list[str]:
    """
    Read a targets file (one target per line).

    Strips whitespace, ignores empty lines and comments (#).

    Args:
        filepath: Path to targets file.

    Returns:
        List of target strings.
    """
    if not filepath.exists():
        return []
    lines: list[str] = []
    for line in filepath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines
