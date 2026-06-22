"""
ReconX Scan Orchestrator

Coordinates the execution of all scanning modules in the
correct order based on the selected scan profile.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconx import __version__
from reconx.config import ReconXConfig, ScanProfile, PROFILE_MODULES
from reconx.core.runner import ToolRunner
from reconx.core.scope import ScopeManager
from reconx.core.security import AuditLogger, FileSecurityManager
from reconx.database.engine import DatabaseManager
from reconx.database.repository import ReconRepository

# Module imports
from reconx.modules.discovery import DiscoveryModule
from reconx.modules.ports import PortsModule
from reconx.modules.validation import ValidationModule
from reconx.modules.screenshots import ScreenshotsModule
from reconx.modules.crawling import CrawlingModule
from reconx.modules.historical import HistoricalModule
from reconx.modules.javascript import JavaScriptModule
from reconx.modules.classification import ClassificationModule
from reconx.modules.intelligence import IntelligenceModule
from reconx.modules.scoring import ScoringModule
from reconx.modules.vulnerability import VulnerabilityModule
from reconx.modules.changes import ChangesModule

console = Console()


BANNER = r"""
[bold cyan]
  ____                    __  __
 |  _ \ ___  ___ ___  _ _\ \/ /
 | |_) / _ \/ __/ _ \| '_ \  /
 |  _ <  __/ (_| (_) | | | /  \
 |_| \_\___|\___\___/|_| /_/\_\
[/bold cyan]
[dim]  Attack Surface Intelligence Framework v{version}[/dim]
"""


class ScanEngine:
    """
    Central scan orchestrator.

    Coordinates all modules in the correct execution order
    based on the selected scan profile. Manages database
    lifecycle, scope validation, and reporting.
    """

    def __init__(self, config: ReconXConfig) -> None:
        self._config = config
        self._db: DatabaseManager | None = None
        self._repo: ReconRepository | None = None
        self._runner: ToolRunner | None = None
        self._scope: ScopeManager | None = None
        self._audit: AuditLogger | None = None

    async def _initialize(self) -> None:
        """Initialize all infrastructure components."""
        # Ensure directories exist with proper permissions
        self._config.ensure_directories()

        # Initialize audit logger
        self._audit = AuditLogger(self._config.audit_log_path)

        # Initialize database
        self._db = DatabaseManager(self._config.db_url)
        await self._db.initialize()
        self._repo = ReconRepository(self._db.session_factory)

        # Initialize tool runner
        self._runner = ToolRunner(
            audit_logger=self._audit,
            timeout=self._config.scan_timeout,
        )

        # Initialize scope manager
        self._scope = ScopeManager(self._repo)
        await self._scope.load_scope()

    async def _cleanup(self) -> None:
        """Clean up resources."""
        if self._db:
            await self._db.close()

        # Clean up temp directory
        temp_dir = self._config.base_dir / "tmp"
        if temp_dir.exists():
            for f in temp_dir.iterdir():
                if f.is_file():
                    f.unlink()

    async def run_scan(
        self,
        targets: list[str],
        profile: ScanProfile,
    ) -> int:
        """
        Execute a full scan with the given profile.

        Args:
            targets: List of target domains.
            profile: Scan profile (quick/standard/deep).

        Returns:
            Scan ID of the completed scan.
        """
        console.print(BANNER.format(version=__version__))
        console.print(
            Panel(
                f"[bold]Target{'s' if len(targets) > 1 else ''}:[/] "
                + ", ".join(targets)
                + f"\n[bold]Profile:[/] {profile.value.upper()}"
                + f"\n[bold]Modules:[/] {len(PROFILE_MODULES[profile])}",
                title="Scan Configuration",
                border_style="cyan",
            )
        )

        await self._initialize()

        try:
            # Validate scope
            validated_targets = self._scope.validate_targets(targets)
            if not validated_targets:
                console.print(
                    "[bold red]✗ All targets are out of scope. Aborting.[/]"
                )
                return -1

            # Create scan record
            scan = await self._repo.create_scan(
                target=",".join(validated_targets),
                scan_type=profile.value,
            )
            scan_id = scan.id

            # Log scan start
            self._audit.log_scan_start(
                target=",".join(validated_targets),
                profile=profile.value,
            )

            active_modules = PROFILE_MODULES[profile]
            console.print(
                f"\n[bold]Starting {profile.value.upper()} scan "
                f"({len(active_modules)} modules)...[/]\n"
            )

            # ── Module Execution Pipeline ─────────────────────────

            # Track results for downstream modules
            subdomains: list[str] = []
            hosts_with_ports: list[str] = []
            live_urls: list[str] = []
            all_urls: list[str] = []
            js_files: list[str] = []
            all_technologies: list[str] = []
            profiles = []

            # Module 1: Discovery
            if "discovery" in active_modules:
                discovery = DiscoveryModule(
                    self._config, self._runner, self._repo
                )
                result = await discovery.run(scan_id, validated_targets)
                subdomains = result.subdomains

            # Module 2: Port Discovery
            if "ports" in active_modules and subdomains:
                ports_mod = PortsModule(
                    self._config, self._runner, self._repo
                )
                result = await ports_mod.run(scan_id, subdomains)
                hosts_with_ports = result.hosts_with_ports

            # Module 3: Validation
            if "validation" in active_modules and subdomains:
                validation = ValidationModule(
                    self._config, self._runner, self._repo
                )
                take_screenshots = "screenshots" in active_modules
                result = await validation.run(
                    scan_id,
                    subdomains,
                    ports_data=hosts_with_ports or None,
                    take_screenshots=take_screenshots,
                )
                live_urls = result.urls

                # Extract technologies for smart Nuclei scanning
                for host_data in result.live_hosts:
                    techs = host_data.get("tech", [])
                    if isinstance(techs, list):
                        all_technologies.extend(techs)

            # Module 4: Screenshots
            if "screenshots" in active_modules:
                screenshots = ScreenshotsModule(self._config, self._repo)
                await screenshots.run(scan_id)

            # Module 5: Crawling
            if "crawling" in active_modules and live_urls:
                crawling = CrawlingModule(
                    self._config, self._runner, self._repo
                )
                result = await crawling.run(scan_id, live_urls)
                all_urls = result.urls
                js_files = result.js_files

            # Module 6: Historical
            if "historical" in active_modules:
                historical = HistoricalModule(
                    self._config, self._runner, self._repo
                )
                result = await historical.run(
                    scan_id, validated_targets, known_urls=all_urls
                )
                all_urls.extend(result.urls)

            # Module 7: JavaScript Intelligence
            if "javascript" in active_modules and js_files:
                js_intel = JavaScriptModule(self._config, self._repo)
                result = await js_intel.run(scan_id, js_files)
                # Add discovered endpoints to URL pool
                all_urls.extend(result.endpoints)

            # Module 8: Classification
            if "classification" in active_modules and all_urls:
                classification = ClassificationModule(
                    self._config, self._repo
                )
                await classification.run(scan_id, all_urls)

            # Module 9: Intelligence
            if "intelligence" in active_modules:
                intelligence = IntelligenceModule(
                    self._config, self._repo
                )
                result = await intelligence.run(scan_id)
                profiles = result.profiles

            # Module 10: Scoring
            if "scoring" in active_modules and profiles:
                scoring = ScoringModule(self._config, self._repo)
                await scoring.run(scan_id, profiles)

            # Module 11: Vulnerability Scanning
            if "vulnerability" in active_modules and live_urls:
                vuln = VulnerabilityModule(
                    self._config, self._runner, self._repo
                )
                await vuln.run(
                    scan_id, live_urls, all_technologies=all_technologies
                )

            # Module 12: Change Detection
            if "changes" in active_modules:
                changes = ChangesModule(self._config, self._repo)
                for target in validated_targets:
                    await changes.run(scan_id, target)

            # ── Scan Complete ─────────────────────────────────────

            # Update scan status
            await self._repo.update_scan_status(
                scan_id, "completed", finished_at=datetime.now(timezone.utc)
            )

            # Get and display summary
            summary = await self._repo.get_scan_summary(scan_id)
            self._display_summary(summary, profile)

            # Log completion
            self._audit.log_scan_complete(
                scan_id, summary.get("findings", 0)
            )

            return scan_id

        except Exception as e:
            console.print(f"\n[bold red]✗ Scan failed:[/] {e}")
            if self._repo and scan_id:
                await self._repo.update_scan_status(
                    scan_id, "failed", finished_at=datetime.now(timezone.utc)
                )
            raise

        finally:
            await self._cleanup()

    def _display_summary(
        self, summary: dict, profile: ScanProfile
    ) -> None:
        """Display scan completion summary."""
        table = Table(title="Scan Summary", show_lines=True)
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="bold")

        metrics = [
            ("Subdomains", summary.get("subdomains", 0)),
            ("Open Ports", summary.get("ports", 0)),
            ("Live Hosts", summary.get("hosts", 0)),
            ("URLs Discovered", summary.get("urls", 0)),
            ("Historical URLs", summary.get("historical_urls", 0)),
            ("JS Files", summary.get("js_files", 0)),
            ("JS Findings", summary.get("js_findings", 0)),
            ("Classified Endpoints", summary.get("classifications", 0)),
            ("Asset Profiles", summary.get("asset_profiles", 0)),
            ("Findings", summary.get("findings", 0)),
        ]

        for metric, count in metrics:
            if count > 0:
                table.add_row(metric, f"{count:,}")

        console.print("\n")
        console.print(table)
        console.print(
            f"\n[bold green]✓ Scan complete![/] "
            f"Profile: {profile.value.upper()}\n"
        )

    async def check_tools(self) -> dict[str, bool]:
        """Check availability of all required tools."""
        self._runner = ToolRunner()
        return self._runner.check_all_tools()

    async def get_scope(self) -> dict[str, list[str]]:
        """Get current scope rules."""
        await self._initialize()
        try:
            return await self._scope.get_scope_display()
        finally:
            await self._cleanup()

    async def add_scope(self, target: str, scope_type: str = "include") -> None:
        """Add a scope rule."""
        await self._initialize()
        try:
            await self._scope.add_target(target, scope_type)
        finally:
            await self._cleanup()

    async def remove_scope(self, target: str) -> None:
        """Remove a scope rule."""
        await self._initialize()
        try:
            await self._scope.remove_target(target)
        finally:
            await self._cleanup()
