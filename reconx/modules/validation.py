"""
Module 3: Asset Validation

Orchestrates ProjectDiscovery's Httpx to probe discovered hosts and
collect status codes, titles, technologies, IPs, and ASN information.

Includes version detection to use the correct flags and guards
against the wrong ``httpx`` binary (e.g. the Python httpx CLI).
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


class HttpxBinaryError(Exception):
    """Raised when the httpx binary is missing or not the expected one."""

    pass


@dataclass
class ValidationResult:
    """Result of HTTP validation."""

    live_hosts: list[dict] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    count: int = 0


class ValidationModule:
    """
    HTTP validation using ProjectDiscovery's Httpx.

    Probes discovered hosts to determine which are alive,
    collecting rich metadata including status codes, page titles,
    technologies, and IP/ASN information.

    On first run, verifies that the ``httpx`` on PATH is
    ProjectDiscovery's build (not Python's ``httpx`` CLI) and
    detects the correct input-list flag (``-l`` vs ``-list``).
    """

    # Strings that confirm we have the ProjectDiscovery binary
    _PD_SIGNATURES = ("projectdiscovery", "pd", "httpx")

    def __init__(
        self,
        config: ReconXConfig,
        runner: ToolRunner,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._runner = runner
        self._repo = repo
        self._list_flag: str | None = None  # resolved on first run

    async def _detect_httpx(self) -> str:
        """Detect which httpx binary is installed and return the correct list flag.

        Runs ``httpx -version`` to verify this is ProjectDiscovery httpx.
        Then probes ``httpx -h`` output to determine whether ``-l`` or
        ``-list`` is the supported input-list flag.

        Returns:
            The correct list flag string (``"-l"`` or ``"-list"``).

        Raises:
            HttpxBinaryError: If httpx is missing, is the wrong binary,
                or its version/flags cannot be determined.
        """
        # ── Step 1: Verify this is ProjectDiscovery httpx ─────────
        if not self._runner.check_tool("httpx"):
            raise HttpxBinaryError(
                "httpx is not installed or not on PATH. "
                "Install it with: go install -v "
                "github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )

        try:
            version_output = await self._runner.run(
                "httpx", ["-version"], parse_json=False, target="version-check"
            )
        except Exception as exc:
            raise HttpxBinaryError(
                f"Failed to run 'httpx -version': {exc}"
            ) from exc

        version_text = version_output.strip().lower() if isinstance(version_output, str) else ""

        if not any(sig in version_text for sig in self._PD_SIGNATURES):
            raise HttpxBinaryError(
                f"The httpx binary on PATH is not ProjectDiscovery's httpx. "
                f"'httpx -version' returned: {version_output.strip()!r}\n"
                f"Install the correct one with: go install -v "
                f"github.com/projectdiscovery/httpx/cmd/httpx@latest"
            )

        console.print(f"  [dim]Detected httpx: {version_output.strip()}[/]")

        # ── Step 2: Detect the correct list flag ──────────────────
        try:
            help_output = await self._runner.run(
                "httpx", ["-h"], parse_json=False, target="flag-check"
            )
        except Exception:
            # If -h fails, default to -l (modern versions)
            return "-l"

        help_text = help_output if isinstance(help_output, str) else ""

        # Modern httpx uses -l or -list; check which appears in help
        # Check for -l as a standalone flag (not as part of -list)
        has_dash_l = False
        has_dash_list = False

        for line in help_text.splitlines():
            stripped = line.strip()
            # Look for the flag definitions in help text
            if stripped.startswith("-l,") or stripped.startswith("-l ") or "  -l," in stripped:
                has_dash_l = True
            if "-list" in stripped:
                has_dash_list = True

        if has_dash_l:
            return "-l"
        elif has_dash_list:
            return "-list"
        else:
            # Fallback: try -l (most modern versions)
            console.print(
                "  [yellow]⚠[/] Could not detect list flag from httpx help, "
                "defaulting to -l"
            )
            return "-l"

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

        Raises:
            HttpxBinaryError: If the httpx binary is wrong or missing.
        """
        console.print("[bold cyan]▶ Module 3:[/] Asset Validation (Httpx)")

        probe_list = self._build_probe_list(subdomains, ports_data)
        if not probe_list:
            console.print("  [yellow]⚠[/] No targets to validate\n")
            return ValidationResult()

        console.print(f"  [dim]Probing {len(probe_list)} targets[/]")

        # ── Detect httpx version and correct flags ────────────────
        if self._list_flag is None:
            try:
                self._list_flag = await self._detect_httpx()
            except HttpxBinaryError as exc:
                console.print(f"  [bold red]✗ httpx error:[/] {exc}\n")
                raise

        # Write targets to temp file
        temp_dir = self._config.base_dir / "tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        input_file = temp_dir / f"httpx_input_{scan_id}.txt"

        try:
            write_lines_to_file(input_file, probe_list)

            args = [
                self._list_flag, str(input_file),
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

            # ── Handle errors from httpx ──────────────────────────
            if not isinstance(results, list):
                # Check if it's an error string containing flag complaints
                if isinstance(results, str) and (
                    "flag" in results.lower()
                    or "unknown" in results.lower()
                    or "error" in results.lower()
                ):
                    console.print(
                        f"  [bold red]✗ httpx returned an error:[/]\n"
                        f"  {results.strip()[:300]}\n"
                        f"  [yellow]Hint:[/] Your httpx version may not "
                        f"support all flags used. Update with:\n"
                        f"  go install -v github.com/projectdiscovery/"
                        f"httpx/cmd/httpx@latest\n"
                    )
                else:
                    console.print("  [yellow]⚠[/] No results from Httpx\n")
                return ValidationResult()

            if len(results) == 0:
                console.print(
                    "  [yellow]⚠[/] httpx returned 0 results. "
                    "This may indicate:\n"
                    "  • All targets are unreachable\n"
                    "  • A flag incompatibility with your httpx version\n"
                    "  • The wrong httpx binary is on PATH\n"
                    "  Run 'httpx -version' to verify.\n"
                )
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

                # Handle IP extraction safely
                ip_value = ""
                a_records = item.get("a")
                if isinstance(a_records, list) and a_records:
                    ip_value = a_records[0]
                elif item.get("host"):
                    ip_value = item["host"]

                db_records.append({
                    "url": url,
                    "status_code": item.get("status_code") or item.get("status-code"),
                    "title": item.get("title", ""),
                    "technologies": techs_json,
                    "ip": ip_value,
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
