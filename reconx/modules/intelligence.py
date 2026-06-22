"""
Module 9: Attack Surface Intelligence Engine

Correlates findings across all modules to build intelligence
profiles for each discovered host.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.utils import extract_host_from_url
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class AssetProfile:
    """Intelligence profile for a single host."""

    host: str = ""
    technologies: list[str] = field(default_factory=list)
    interesting_paths: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    js_secrets_count: int = 0
    status_code: int | None = None
    title: str = ""
    risk_score: int = 0
    reasons: list[str] = field(default_factory=list)


@dataclass
class IntelligenceResult:
    """Result of intelligence engine."""

    profiles: list[AssetProfile] = field(default_factory=list)
    count: int = 0


class IntelligenceModule:
    """
    Attack Surface Intelligence Engine.

    Aggregates and correlates data from all previous modules
    to build comprehensive per-host intelligence profiles.
    Each profile includes technologies, interesting endpoints,
    port exposure, and secret findings.
    """

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    async def run(self, scan_id: int) -> IntelligenceResult:
        """
        Build intelligence profiles from all collected data.

        Args:
            scan_id: Current scan ID for data retrieval.

        Returns:
            IntelligenceResult with per-host profiles.
        """
        console.print("[bold cyan]▶ Module 9:[/] Attack Surface Intelligence")

        # Gather data from all sources
        hosts = await self._repo.get_hosts(scan_id)
        ports = await self._repo.get_ports(scan_id)
        classifications = await self._repo.get_classifications(scan_id)
        js_findings = await self._repo.get_js_findings(scan_id)

        if not hosts:
            console.print("  [yellow]⚠[/] No hosts data to build profiles\n")
            return IntelligenceResult()

        # Index ports by host
        ports_by_host: dict[str, list[int]] = {}
        for port_entry in ports:
            h = port_entry.host.lower()
            if h not in ports_by_host:
                ports_by_host[h] = []
            ports_by_host[h].append(port_entry.port)

        # Index classifications by host
        paths_by_host: dict[str, list[str]] = {}
        for cls_entry in classifications:
            h = extract_host_from_url(cls_entry.url).lower()
            if h not in paths_by_host:
                paths_by_host[h] = []
            paths_by_host[h].append(f"[{cls_entry.category}] {cls_entry.url}")

        # Count JS secrets by source host
        secrets_by_host: dict[str, int] = {}
        for js_finding in js_findings:
            h = extract_host_from_url(js_finding.source_url).lower()
            secrets_by_host[h] = secrets_by_host.get(h, 0) + 1

        # Build profiles
        profiles: list[AssetProfile] = []
        db_records: list[dict] = []

        for host_entry in hosts:
            host_url = host_entry.url
            hostname = extract_host_from_url(host_url).lower()

            # Parse technologies
            try:
                techs = json.loads(host_entry.technologies) if host_entry.technologies else []
            except (json.JSONDecodeError, TypeError):
                techs = []

            profile = AssetProfile(
                host=host_url,
                technologies=techs,
                interesting_paths=paths_by_host.get(hostname, []),
                open_ports=ports_by_host.get(hostname, []),
                js_secrets_count=secrets_by_host.get(hostname, 0),
                status_code=host_entry.status_code,
                title=host_entry.title or "",
            )
            profiles.append(profile)

            db_records.append({
                "host": host_url,
                "technologies": json.dumps(techs),
                "interesting_paths": json.dumps(profile.interesting_paths),
                "risk_score": 0,
                "reasons": json.dumps([]),
                "timestamp": datetime.now(timezone.utc),
            })

        # Store profiles in database
        if db_records:
            await self._repo.add_asset_profiles(scan_id, db_records)

        result = IntelligenceResult(
            profiles=profiles,
            count=len(profiles),
        )

        console.print(
            f"  [bold green]✓ Intelligence profiles built:[/] "
            f"{result.count} host profiles\n"
        )
        return result
