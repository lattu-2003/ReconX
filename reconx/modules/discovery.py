"""
Module 1: Asset Discovery

Orchestrates Subfinder for subdomain enumeration.
Supports single and multiple targets with deduplication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.runner import ToolRunner
from reconx.core.security import InputValidator
from reconx.core.utils import deduplicate_dicts, extract_root_domain
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class DiscoveryResult:
    """Result of subdomain discovery."""

    subdomains: list[str] = field(default_factory=list)
    raw_results: list[dict] = field(default_factory=list)
    count: int = 0


class DiscoveryModule:
    """
    Subdomain discovery using Subfinder.

    Discovers all subdomains for given target domains using
    passive sources. Results are deduplicated and stored in
    the database.
    """

    def __init__(
        self,
        config: ReconXConfig,
        runner: ToolRunner,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._runner = runner
        self._repo = repo

    async def run(self, scan_id: int, targets: list[str]) -> DiscoveryResult:
        """
        Run subdomain discovery for all targets.

        Args:
            scan_id: Current scan ID for database storage.
            targets: List of root domains to enumerate.

        Returns:
            DiscoveryResult with all discovered subdomains.
        """
        console.print("[bold cyan]▶ Module 1:[/] Asset Discovery (Subfinder)")
        all_results: list[dict] = []

        for target in targets:
            target = InputValidator.validate_domain(target)
            console.print(f"  [dim]Enumerating subdomains for:[/] {target}")

            args = [
                "-d", target,
                "-json",
                "-all",
                "-silent",
            ]

            if self._config.threads:
                args.extend(["-t", str(self._config.threads)])

            try:
                results = await self._runner.run(
                    "subfinder",
                    args,
                    parse_json=True,
                    target=target,
                )

                if isinstance(results, list):
                    all_results.extend(results)
                    console.print(
                        f"  [green]✓[/] Found [bold]{len(results)}[/] "
                        f"subdomains for {target}"
                    )
                else:
                    console.print(f"  [yellow]⚠[/] No JSON output for {target}")

            except Exception as e:
                console.print(f"  [red]✗[/] Error discovering {target}: {e}")

        # Deduplicate by host field
        unique_results = deduplicate_dicts(all_results, "host")

        # Prepare database records
        db_records: list[dict] = []
        subdomain_list: list[str] = []

        for item in unique_results:
            host = item.get("host", "").strip().lower()
            if not host:
                continue

            subdomain_list.append(host)
            db_records.append({
                "root_domain": extract_root_domain(host),
                "subdomain": host,
                "source": item.get("source", "subfinder"),
                "created_at": datetime.now(timezone.utc),
            })

        # Store in database
        if db_records:
            await self._repo.add_subdomains(scan_id, db_records)

        result = DiscoveryResult(
            subdomains=subdomain_list,
            raw_results=unique_results,
            count=len(subdomain_list),
        )

        console.print(
            f"  [bold green]✓ Discovery complete:[/] "
            f"{result.count} unique subdomains\n"
        )
        return result
