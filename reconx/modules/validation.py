"""
Module 3: Asset Validation

Orchestrates Httpx to probe discovered hosts and collect
status codes, titles, technologies, IPs, and ASN information.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.runner import ToolRunner
from reconx.core.utils import build_url, deduplicate_dicts, write_lines_to_file
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class ValidationResult:
    """Result of HTTP validation."""

    live_hosts: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    count: int = 0


class ValidationModule:
    """
    HTTP validation using Httpx.

    Probes discovered hosts to determine which are alive,
    collecting rich metadata including status codes, page titles,
    technologies, and IP/ASN information.
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

    def _build_probe_list(
        self,
        subdomains: list[str],
        ports_data: list[str] | None = None,
    ) -> list[str]:
        """
        Build list of URLs to probe from subdomains and ports.

        Combines plain subdomains with host:port entries from Naabu.
        """
        targets: set[str] = set()

        # Add standard HTTP/HTTPS for each subdomain
        for sub in subdomains:
            targets.add(sub)

        # Add host:port combinations from port scanning
        if ports_data:
            for entry in ports_data:
                targets.add(entry)

        return sorted(targets)

    async def run(
        self,
        scan_id: int,
        subdomains: list[str],
        ports_data: list[str] | None = None,
        take_screenshots: bool = False,
    ) -> ValidationResult:
        """
        Run HTTP validation on all discovered hosts.

        Args:
            scan_id: Current scan ID for database storage.
            subdomains: List of subdomains to probe.
            ports_data: Optional list of host:port strings from Naabu.
            take_screenshots: Whether to capture screenshots.

        Returns:
            ValidationResult with live host details.
        """
        console.print("[bold cyan]▶ Module 3:[/] Asset Validation (Httpx)")

        probe_list = self._build_probe_list(subdomains, ports_data)
        if not probe_list:
            console.print("  [yellow]⚠[/] No targets to validate\n")
            return ValidationResult()

        console.print(f"  [dim]Probing {len(probe_list)} targets[/]")

        # Write targets to temp file
        temp_dir = self._config.base_dir / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        input_file = temp_dir / f"httpx_input_{scan_id}.txt"

        try:
            write_lines_to_file(input_file, probe_list)

            args = [
                "-list", str(input_file),
                "-json",
                "-silent",
                "-status-code",
                "-title",
                "-tech-detect",
                "-ip",
                "-asn",
                "-follow-redirects",
                "-threads", str(self._config.threads),
                "-rate-limit", str(self._config.rate_limit),
                "-timeout", str(self._config.timeout),
            ]

            # Add screenshot flag if requested
            if take_screenshots:
                screenshot_dir = self._config.screenshots_dir
                screenshot_dir.mkdir(parents=True, exist_ok=True)
                args.extend([
                    "-screenshot",
                    "-screenshot-path", str(screenshot_dir),
                ])

            results = await self._runner.run(
                "httpx",
                args,
                parse_json=True,
                target="validation",
            )

            if not isinstance(results, list):
                console.print("  [yellow]⚠[/] No results from Httpx\n")
                return ValidationResult()

            # Deduplicate by URL
            unique_results = deduplicate_dicts(results, "url")

            # Prepare database records
            db_records: list[dict] = []
            live_urls: list[str] = []

            for item in unique_results:
                url = item.get("url", "").strip()
                if not url:
                    continue

                live_urls.append(url)

                # Extract technologies as JSON string
                techs = item.get("tech", [])
                if isinstance(techs, list):
                    techs_json = json.dumps(techs)
                else:
                    techs_json = json.dumps([])

                # Handle ASN info
                asn_info = item.get("asn", {})
                asn_str = ""
                if isinstance(asn_info, dict):
                    asn_str = asn_info.get("as_number", "")
                elif isinstance(asn_info, str):
                    asn_str = asn_info

                db_records.append({
                    "url": url,
                    "status_code": item.get("status_code") or item.get("status-code"),
                    "title": item.get("title", ""),
                    "technologies": techs_json,
                    "ip": item.get("host", "") or item.get("a", [""])[0] if isinstance(item.get("a"), list) else item.get("host", ""),
                    "asn": str(asn_str),
                    "screenshot_path": item.get("screenshot_path"),
                    "timestamp": datetime.now(timezone.utc),
                })

            # Store in database
            if db_records:
                await self._repo.add_hosts(scan_id, db_records)

            result = ValidationResult(
                live_hosts=unique_results,
                urls=live_urls,
                count=len(live_urls),
            )

            console.print(
                f"  [bold green]✓ Validation complete:[/] "
                f"{result.count} live hosts\n"
            )
            return result

        finally:
            if input_file.exists():
                input_file.unlink()
