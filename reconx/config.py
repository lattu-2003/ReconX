"""
ReconX Configuration Module

Pydantic-based settings management with scan profile definitions.
Supports environment variables with RECONX_ prefix and .env files.
"""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScanProfile(str, Enum):
    """Available scan profiles with increasing depth."""

    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"


# Modules activated per scan profile
PROFILE_MODULES: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: [
        "discovery",
        "validation",
    ],
    ScanProfile.STANDARD: [
        "discovery",
        "ports",
        "validation",
        "screenshots",
        "crawling",
        "classification",
        "intelligence",
        "scoring",
        "vulnerability",
        "changes",
    ],
    ScanProfile.DEEP: [
        "discovery",
        "ports",
        "validation",
        "screenshots",
        "crawling",
        "historical",
        "javascript",
        "classification",
        "intelligence",
        "scoring",
        "vulnerability",
        "changes",
    ],
}


class ReconXConfig(BaseSettings):
    """
    Global configuration for ReconX.

    Values can be overridden via environment variables prefixed with RECONX_
    or via a .env file in the working directory.
    """

    model_config = SettingsConfigDict(
        env_prefix="RECONX_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ── Paths ──────────────────────────────────────────────────────────
    base_dir: Path = Field(
        default_factory=lambda: Path.home() / ".reconx",
        description="Root directory for all ReconX data",
    )
    db_name: str = Field(
        default="reconx.db",
        description="SQLite database filename",
    )
    results_dir_name: str = Field(
        default="results",
        description="Subdirectory name for scan results",
    )

    # ── Scan Parameters ────────────────────────────────────────────────
    threads: int = Field(default=50, ge=1, le=500, description="Concurrent threads")
    rate_limit: int = Field(default=150, ge=1, description="Requests per second limit")
    timeout: int = Field(default=30, ge=5, le=300, description="Tool timeout in seconds")
    scan_timeout: int = Field(
        default=600, ge=60, le=7200, description="Max seconds per tool execution"
    )

    # ── Port Configuration ─────────────────────────────────────────────
    default_ports: str = Field(
        default="80,443,8080,8443,3000,5000,9200",
        description="Comma-separated default ports for Naabu",
    )

    # ── Nuclei Configuration ───────────────────────────────────────────
    nuclei_severity: str = Field(
        default="low,medium,high,critical",
        description="Nuclei severity filter",
    )
    nuclei_rate_limit: int = Field(
        default=150, ge=1, description="Nuclei rate limit"
    )

    # ── Crawling Configuration ─────────────────────────────────────────
    crawl_depth: int = Field(default=3, ge=1, le=10, description="Katana crawl depth")

    # ── Display Configuration ──────────────────────────────────────────
    show_secrets: bool = Field(
        default=False,
        description="Show full secret values in CLI output (default: masked)",
    )
    verbose: bool = Field(default=False, description="Enable verbose output")

    # ── Computed Properties ────────────────────────────────────────────

    @property
    def db_path(self) -> Path:
        """Full path to the SQLite database."""
        return self.base_dir / self.db_name

    @property
    def results_dir(self) -> Path:
        """Full path to the results directory."""
        return self.base_dir / self.results_dir_name

    @property
    def audit_log_path(self) -> Path:
        """Full path to the audit log."""
        return self.base_dir / "audit.log"

    @property
    def screenshots_dir(self) -> Path:
        """Full path to the screenshots directory."""
        return self.results_dir / "screenshots"

    @property
    def reports_dir(self) -> Path:
        """Full path to the reports directory."""
        return self.results_dir / "reports"

    @property
    def db_url(self) -> str:
        """SQLAlchemy async database URL."""
        return f"sqlite+aiosqlite:///{self.db_path}"

    @property
    def port_list(self) -> list[int]:
        """Parse default_ports string into list of integers."""
        return [int(p.strip()) for p in self.default_ports.split(",") if p.strip()]

    # ── Validators ─────────────────────────────────────────────────────

    @field_validator("default_ports")
    @classmethod
    def validate_ports(cls, v: str) -> str:
        """Ensure all ports are valid integers in range."""
        for part in v.split(","):
            part = part.strip()
            if part:
                port = int(part)
                if not (1 <= port <= 65535):
                    raise ValueError(f"Port {port} out of valid range (1-65535)")
        return v

    # ── Directory Setup ────────────────────────────────────────────────

    def ensure_directories(self) -> None:
        """Create all required directories with secure permissions."""
        dirs = [
            self.base_dir,
            self.results_dir,
            self.screenshots_dir,
            self.reports_dir,
        ]
        for d in dirs:
            d.mkdir(parents=True, exist_ok=True)
            # Set owner-only permissions on Linux
            if os.name == "posix":
                os.chmod(d, 0o700)
