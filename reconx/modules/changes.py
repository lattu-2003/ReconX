"""
Module 12: Change Detection

Compares current scan results against previous scans to
detect newly exposed assets, technologies, and findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table

from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class ChangeEvent:
    """A single detected change."""

    event_type: str
    detail: str


@dataclass
class ChangeResult:
    """Result of change detection."""

    new_subdomains: list[str] = field(default_factory=list)
    removed_subdomains: list[str] = field(default_factory=list)
    new_hosts: list[str] = field(default_factory=list)
    removed_hosts: list[str] = field(default_factory=list)
    new_findings: list[str] = field(default_factory=list)
    events: list[ChangeEvent] = field(default_factory=list)
    has_changes: bool = False


class ChangesModule:
    """
    Change Detection Engine.

    Compares the current scan against the most recent previous
    scan for the same target. Detects:
    - New and removed subdomains
    - New and disappeared live hosts
    - New vulnerability findings
    - New technologies appearing on hosts
    """

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    async def run(
        self, scan_id: int, target: str
    ) -> ChangeResult:
        """
        Compare current scan with previous scan.

        Args:
            scan_id: Current scan ID.
            target: Target domain being scanned.

        Returns:
            ChangeResult with all detected changes.
        """
        console.print("[bold cyan]▶ Module 12:[/] Change Detection")

        # Get previous scan
        prev_scan = await self._repo.get_previous_scan(target, scan_id)
        if prev_scan is None:
            console.print(
                "  [dim]No previous scan found for comparison "
                "(first scan for this target)[/]\n"
            )
            return ChangeResult()

        prev_scan_id = prev_scan.id
        result = ChangeResult()
        events: list[dict] = []

        # ── Compare Subdomains ─────────────────────────────────────
        current_subs = await self._repo.get_subdomains(scan_id)
        previous_subs = await self._repo.get_subdomains(prev_scan_id)

        current_sub_set = {s.subdomain for s in current_subs}
        previous_sub_set = {s.subdomain for s in previous_subs}

        new_subs = current_sub_set - previous_sub_set
        removed_subs = previous_sub_set - current_sub_set

        if new_subs:
            result.new_subdomains = sorted(new_subs)
            for sub in new_subs:
                events.append({
                    "target": target,
                    "event_type": "new_subdomain",
                    "detail": sub,
                    "detected_at": datetime.now(timezone.utc),
                })

        if removed_subs:
            result.removed_subdomains = sorted(removed_subs)
            for sub in removed_subs:
                events.append({
                    "target": target,
                    "event_type": "removed_subdomain",
                    "detail": sub,
                    "detected_at": datetime.now(timezone.utc),
                })

        # ── Compare Live Hosts ─────────────────────────────────────
        current_hosts = await self._repo.get_hosts(scan_id)
        previous_hosts = await self._repo.get_hosts(prev_scan_id)

        current_host_set = {h.url for h in current_hosts}
        previous_host_set = {h.url for h in previous_hosts}

        new_hosts = current_host_set - previous_host_set
        removed_hosts = previous_host_set - current_host_set

        if new_hosts:
            result.new_hosts = sorted(new_hosts)
            for host in new_hosts:
                events.append({
                    "target": target,
                    "event_type": "new_host",
                    "detail": host,
                    "detected_at": datetime.now(timezone.utc),
                })

        if removed_hosts:
            result.removed_hosts = sorted(removed_hosts)
            for host in removed_hosts:
                events.append({
                    "target": target,
                    "event_type": "removed_host",
                    "detail": host,
                    "detected_at": datetime.now(timezone.utc),
                })

        # ── Compare Findings ───────────────────────────────────────
        current_findings = await self._repo.get_findings(scan_id)
        previous_findings = await self._repo.get_findings(prev_scan_id)

        current_finding_keys = {
            f"{f.template}:{f.host}" for f in current_findings
        }
        previous_finding_keys = {
            f"{f.template}:{f.host}" for f in previous_findings
        }

        new_finding_keys = current_finding_keys - previous_finding_keys
        if new_finding_keys:
            result.new_findings = sorted(new_finding_keys)
            for finding_key in new_finding_keys:
                events.append({
                    "target": target,
                    "event_type": "new_finding",
                    "detail": finding_key,
                    "detected_at": datetime.now(timezone.utc),
                })

        # Store change events
        if events:
            await self._repo.add_change_events(events)
            result.has_changes = True

        # Build events list for result
        result.events = [
            ChangeEvent(event_type=e["event_type"], detail=e["detail"])
            for e in events
        ]

        # ── Display Changes ────────────────────────────────────────
        if result.has_changes:
            table = Table(title="Changes Detected", show_lines=False)
            table.add_column("Type", style="cyan")
            table.add_column("Count", justify="right", style="bold")
            table.add_column("Details", style="dim")

            if result.new_subdomains:
                table.add_row(
                    "New Subdomains",
                    str(len(result.new_subdomains)),
                    ", ".join(result.new_subdomains[:5])
                    + ("..." if len(result.new_subdomains) > 5 else ""),
                )
            if result.removed_subdomains:
                table.add_row(
                    "Removed Subdomains",
                    str(len(result.removed_subdomains)),
                    ", ".join(result.removed_subdomains[:5])
                    + ("..." if len(result.removed_subdomains) > 5 else ""),
                )
            if result.new_hosts:
                table.add_row(
                    "New Live Hosts",
                    str(len(result.new_hosts)),
                    ", ".join(result.new_hosts[:5])
                    + ("..." if len(result.new_hosts) > 5 else ""),
                )
            if result.removed_hosts:
                table.add_row(
                    "Disappeared Hosts",
                    str(len(result.removed_hosts)),
                    ", ".join(result.removed_hosts[:5])
                    + ("..." if len(result.removed_hosts) > 5 else ""),
                )
            if result.new_findings:
                table.add_row(
                    "New Findings",
                    str(len(result.new_findings)),
                    ", ".join(result.new_findings[:3])
                    + ("..." if len(result.new_findings) > 3 else ""),
                )

            console.print(table)
            console.print()
        else:
            console.print("  [dim]No changes detected since last scan[/]\n")

        return result
