"""
Module 2: Port Discovery

Orchestrates Naabu for port scanning on discovered subdomains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console

from reconx.core.runner import ToolRunner
from reconx.core.security import InputValidator, FileSecurityManager
from reconx.core.utils import deduplicate_dicts, write_lines_to_file
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class PortResult:
    """Result of port scanning."""

    entries: list[dict] = field(default_factory=list)
    hosts_with_ports: list[str] = field(default_factory=list)
    count: int = 0


class PortsModule:
    """
    Port discovery using Naabu.

    Scans discovered subdomains for open ports to identify
    exposed services beyond standard HTTP/HTTPS.
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
        self, scan_id: int, subdomains: list[str]
    ) -> PortResult:
        """
        Run port scanning on all discovered subdomains.

        Args:
            scan_id: Current scan ID for database storage.
            subdomains: List of subdomains to port scan.

        Returns:
            PortResult with discovered open ports.
        """
        console.print("[bold cyan]▶ Module 2:[/] Port Discovery (Naabu)")

        if not subdomains:
            console.print("  [yellow]⚠[/] No subdomains to scan\n")
            return PortResult()

        console.print(f"  [dim]Scanning {len(subdomains)} hosts for open ports[/]")

        # Write subdomains to temp input file
        temp_dir = self._config.base_dir / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        input_file = temp_dir / f"naabu_input_{scan_id}.txt"

        try:
            write_lines_to_file(input_file, subdomains)

            args = [
                "-list", str(input_file),
                "-json",
                "-silent",
                "-p", self._config.default_ports,
            ]

            if self._config.rate_limit:
                args.extend(["-rate", str(self._config.rate_limit)])

            results = await self._runner.run(
                "naabu",
                args,
                parse_json=True,
                target="port-scan",
            )

            if not isinstance(results, list):
                console.print("  [yellow]⚠[/] No results from Naabu\n")
                return PortResult()

            # Deduplicate by host:port combination
            for item in results:
                item["_dedup_key"] = f"{item.get('host', '')}:{item.get('port', '')}"
            unique_results = deduplicate_dicts(results, "_dedup_key")

            # Prepare database records
            db_records: list[dict] = []
            hosts_with_ports: set[str] = set()

            for item in unique_results:
                host = item.get("host", "").strip()
                port = item.get("port")

                if not host or port is None:
                    continue

                port = int(port)
                InputValidator.validate_port(port)

                hosts_with_ports.add(f"{host}:{port}")
                db_records.append({
                    "host": host,
                    "port": port,
                    "service": item.get("service"),
                    "timestamp": datetime.now(timezone.utc),
                })

            # Store in database
            if db_records:
                await self._repo.add_ports(scan_id, db_records)

            result = PortResult(
                entries=unique_results,
                hosts_with_ports=sorted(hosts_with_ports),
                count=len(db_records),
            )

            console.print(
                f"  [bold green]✓ Port scan complete:[/] "
                f"{result.count} open ports on "
                f"{len(hosts_with_ports)} hosts\n"
            )
            return result

        finally:
            # Clean up temp file
            if input_file.exists():
                input_file.unlink()
