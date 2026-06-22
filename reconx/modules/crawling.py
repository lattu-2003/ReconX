"""
Module 5: Crawling Engine

Orchestrates Katana for web crawling to discover URLs,
parameters, forms, APIs, JavaScript files, and endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.runner import ToolRunner
from reconx.core.utils import deduplicate_dicts, write_lines_to_file
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class CrawlResult:
    """Result of web crawling."""

    urls: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    raw_results: list[dict] = field(default_factory=list)
    count: int = 0


class CrawlingModule:
    """
    Web crawling using Katana.

    Crawls live hosts to discover URLs, JavaScript files,
    API endpoints, forms, and parameters. Feeds downstream
    modules (JS Intelligence, Classification).
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

    async def run(
        self, scan_id: int, live_urls: list[str]
    ) -> CrawlResult:
        """
        Crawl all live hosts for URLs and resources.

        Args:
            scan_id: Current scan ID for database storage.
            live_urls: List of live URLs from validation.

        Returns:
            CrawlResult with discovered URLs and JS files.
        """
        console.print("[bold cyan]▶ Module 5:[/] Crawling Engine (Katana)")

        if not live_urls:
            console.print("  [yellow]⚠[/] No live URLs to crawl\n")
            return CrawlResult()

        console.print(f"  [dim]Crawling {len(live_urls)} live hosts[/]")

        # Write URLs to temp file
        temp_dir = self._config.base_dir / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        input_file = temp_dir / f"katana_input_{scan_id}.txt"

        try:
            write_lines_to_file(input_file, live_urls)

            args = [
                "-list", str(input_file),
                "-json",
                "-silent",
                "-js-crawl",
                "-depth", str(self._config.crawl_depth),
                "-known-files", "all",
                "-concurrency", str(self._config.threads),
                "-rate-limit", str(self._config.rate_limit),
            ]

            results = await self._runner.run(
                "katana",
                args,
                parse_json=True,
                target="crawling",
            )

            if not isinstance(results, list):
                console.print("  [yellow]⚠[/] No results from Katana\n")
                return CrawlResult()

            # Deduplicate by endpoint
            unique_results = deduplicate_dicts(results, "request")

            # Separate URLs and JS files
            url_records: list[dict] = []
            js_files: list[str] = []
            all_urls: list[str] = []

            for item in unique_results:
                endpoint = (
                    item.get("request", {}).get("endpoint", "")
                    if isinstance(item.get("request"), dict)
                    else item.get("request", "")
                )
                if not endpoint:
                    endpoint = item.get("endpoint", "")
                if not endpoint:
                    continue

                source_host = item.get("source", "katana")
                all_urls.append(endpoint)

                # Identify JavaScript files
                if any(
                    endpoint.lower().endswith(ext)
                    for ext in (".js", ".mjs", ".jsx")
                ):
                    js_files.append(endpoint)

                url_records.append({
                    "host": source_host,
                    "url": endpoint,
                    "source": "katana",
                    "timestamp": datetime.now(timezone.utc),
                })

            # Store URLs in database
            if url_records:
                await self._repo.add_urls(scan_id, url_records)

            # Store JS files in database
            if js_files:
                js_records = [
                    {
                        "url": js_url,
                        "host": js_url.split("/")[2] if len(js_url.split("/")) > 2 else "",
                        "timestamp": datetime.now(timezone.utc),
                    }
                    for js_url in js_files
                ]
                await self._repo.add_js_files(scan_id, js_records)

            result = CrawlResult(
                urls=all_urls,
                js_files=js_files,
                raw_results=unique_results,
                count=len(all_urls),
            )

            console.print(
                f"  [bold green]✓ Crawling complete:[/] "
                f"{result.count} URLs, {len(js_files)} JS files\n"
            )
            return result

        finally:
            if input_file.exists():
                input_file.unlink()
