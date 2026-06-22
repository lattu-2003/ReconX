"""
Module 6: Historical Reconnaissance

Orchestrates Gau to discover historical URLs from
Wayback Machine, Common Crawl, OTX, and URLScan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.runner import ToolRunner
from reconx.core.security import InputValidator
from reconx.core.utils import deduplicate
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class HistoricalResult:
    """Result of historical URL discovery."""

    urls: list[str] = field(default_factory=list)
    count: int = 0


class HistoricalModule:
    """
    Historical URL discovery using Gau.

    Gau aggregates URLs from multiple sources:
    - Wayback Machine
    - Common Crawl
    - Open Threat Exchange (OTX)
    - URLScan.io

    Discovers deprecated APIs, hidden panels, old endpoints,
    and backup files that may still be accessible.
    """

    # File extensions to filter out (not useful for recon)
    EXCLUDED_EXTENSIONS = frozenset({
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
        ".css", ".woff", ".woff2", ".ttf", ".eot",
        ".mp4", ".mp3", ".avi", ".mov",
        ".pdf",
    })

    def __init__(
        self,
        config: ReconXConfig,
        runner: ToolRunner,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._runner = runner
        self._repo = repo

    def _is_useful_url(self, url: str) -> bool:
        """Filter out static assets and media files."""
        url_lower = url.lower().split("?")[0]
        return not any(url_lower.endswith(ext) for ext in self.EXCLUDED_EXTENSIONS)

    async def run(
        self,
        scan_id: int,
        targets: list[str],
        known_urls: list[str] | None = None,
    ) -> HistoricalResult:
        """
        Discover historical URLs for all targets.

        Args:
            scan_id: Current scan ID for database storage.
            targets: List of root domains to query.
            known_urls: Already-known URLs to exclude from results.

        Returns:
            HistoricalResult with newly discovered historical URLs.
        """
        console.print("[bold cyan]▶ Module 6:[/] Historical Recon (Gau)")

        known_set = set(u.lower() for u in (known_urls or []))
        all_urls: list[str] = []

        for target in targets:
            target = InputValidator.validate_domain(target)
            console.print(f"  [dim]Querying historical sources for:[/] {target}")

            args = [
                target,
                "--json",
                "--subs",
            ]

            try:
                results = await self._runner.run(
                    "gau",
                    args,
                    parse_json=True,
                    target=target,
                )

                if isinstance(results, list):
                    for item in results:
                        url = item.get("url", "").strip()
                        if (
                            url
                            and url.lower() not in known_set
                            and self._is_useful_url(url)
                        ):
                            all_urls.append(url)

                    console.print(
                        f"  [green]✓[/] Retrieved {len(results)} entries "
                        f"for {target}"
                    )
                else:
                    # Gau might return plain text (one URL per line)
                    if isinstance(results, str):
                        for line in results.strip().splitlines():
                            url = line.strip()
                            if (
                                url
                                and url.lower() not in known_set
                                and self._is_useful_url(url)
                            ):
                                all_urls.append(url)

            except Exception as e:
                console.print(f"  [red]✗[/] Error querying {target}: {e}")

        # Deduplicate
        unique_urls = deduplicate(all_urls)

        # Store in database
        if unique_urls:
            db_records = [
                {
                    "url": url,
                    "source": "gau",
                    "timestamp": datetime.now(timezone.utc),
                }
                for url in unique_urls
            ]
            await self._repo.add_historical_urls(scan_id, db_records)

        result = HistoricalResult(
            urls=unique_urls,
            count=len(unique_urls),
        )

        console.print(
            f"  [bold green]✓ Historical recon complete:[/] "
            f"{result.count} unique URLs\n"
        )
        return result
