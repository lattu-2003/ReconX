"""
Module 3: Asset Validation

Orchestrates ProjectDiscovery's Httpx to probe discovered hosts and
collect status codes, titles, technologies, IPs, and ASN information.

Includes version detection to use the correct flags and guards
against the wrong ``httpx`` binary (e.g. the Python httpx CLI).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.core.runner import ToolRunner, ToolNotFoundError
from reconx.core.utils import build_url, deduplicate_dicts, write_lines_to_file
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()
logger = logging.getLogger(__name__)


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

    # Patterns that confirm we have the ProjectDiscovery binary.
    # Checked against the COMBINED stdout+stderr output of `httpx -version`.
    # PD httpx outputs formats like:
    #   "Current Version: v1.6.9"
    #   "httpx version 1.6.9"
    #   "projectdiscovery/httpx v1.6.9"
    _PD_SIGNATURES = (
        "projectdiscovery",
        "current version",
        "current:",
    )
    # Regex to match a version string like "v1.6.9" or "1.6.9"
    _VERSION_RE = re.compile(r"v?\d+\.\d+\.\d+")

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

        Uses a direct subprocess call (not runner.run) to capture BOTH
        stdout and stderr, since ProjectDiscovery httpx may write its
        version to either stream.

        Returns:
            The correct list flag string (``"-l"`` or ``"-list"``).

        Raises:
            HttpxBinaryError: If httpx is missing, is the wrong binary,
                or its version/flags cannot be determined.
        """
        # ── Step 1: Resolve the binary path ───────────────────────
        try:
            binary_path = self._runner._resolve_tool("httpx")
        except ToolNotFoundError as exc:
            raise HttpxBinaryError(str(exc)) from exc

        logger.info("[httpx-detect] Resolved binary path: %s", binary_path)
        console.print(f"  [dim]httpx binary: {binary_path}[/]")

        # ── Step 2: Run version check with full output capture ────
        cmd = [binary_path, "-version"]
        logger.info("[httpx-detect] Running: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=15
            )
        except asyncio.TimeoutError:
            raise HttpxBinaryError(
                f"'httpx -version' timed out (binary: {binary_path})"
            )
        except Exception as exc:
            raise HttpxBinaryError(
                f"Failed to run '{binary_path} -version': {exc}"
            ) from exc

        stdout_text = stdout_bytes.decode("utf-8", errors="replace").strip()
        stderr_text = stderr_bytes.decode("utf-8", errors="replace").strip()
        exit_code = proc.returncode

        # ── DEBUG LOGGING ─────────────────────────────────────────
        logger.info("[httpx-detect] Exit code: %d", exit_code)
        logger.info("[httpx-detect] Stdout: %r", stdout_text)
        logger.info("[httpx-detect] Stderr: %r", stderr_text)

        console.print(f"  [dim]httpx -version exit code: {exit_code}[/]")
        if stdout_text:
            console.print(f"  [dim]  stdout: {stdout_text[:200]}[/]")
        if stderr_text:
            console.print(f"  [dim]  stderr: {stderr_text[:200]}[/]")

        # ── Step 3: Validate this is ProjectDiscovery httpx ───────
        # Combine stdout + stderr since PD httpx can output to either
        combined = f"{stdout_text}\n{stderr_text}".lower()

        is_pd_httpx = False

        # Check known PD signatures
        for sig in self._PD_SIGNATURES:
            if sig in combined:
                is_pd_httpx = True
                break

        # Also accept if it looks like a semver version from a Go binary
        # (Python httpx outputs "httpx, version X.Y.Z" with different format)
        if not is_pd_httpx and self._VERSION_RE.search(combined):
            # PD httpx versions are like "v1.6.9", Python httpx like "0.27.0"
            version_match = self._VERSION_RE.search(combined)
            if version_match:
                version_str = version_match.group()
                # PD httpx major version is >= 1; Python httpx is 0.x
                if version_str.startswith("v") or not version_str.startswith("0."):
                    is_pd_httpx = True
                    logger.info(
                        "[httpx-detect] Accepted via version pattern: %s",
                        version_str,
                    )

        if not is_pd_httpx:
            raise HttpxBinaryError(
                f"The httpx at '{binary_path}' does not appear to be "
                f"ProjectDiscovery's httpx.\n"
                f"  Exit code: {exit_code}\n"
                f"  Stdout: {stdout_text!r}\n"
                f"  Stderr: {stderr_text!r}\n\n"
                f"Install the correct binary:\n"
                f"  go install -v github.com/projectdiscovery/httpx/"
                f"cmd/httpx@latest\n\n"
                f"Or set an explicit path in .env:\n"
                f'  RECONX_TOOL_PATHS=\'{{"httpx": "/root/go/bin/httpx"}}\''
            )

        # Show the detected version
        display_version = stdout_text or stderr_text
        console.print(f"  [green]✓ ProjectDiscovery httpx: {display_version}[/]")

        # ── Step 4: Detect the correct list flag ──────────────────
        logger.info("[httpx-detect] Running: %s -h", binary_path)

        try:
            proc = await asyncio.create_subprocess_exec(
                binary_path, "-h",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            h_stdout, h_stderr = await asyncio.wait_for(
                proc.communicate(), timeout=15
            )
        except Exception:
            logger.info("[httpx-detect] -h failed, defaulting to -l")
            return "-l"

        # PD httpx sends help to stderr
        help_text = h_stdout.decode("utf-8", errors="replace")
        help_text += "\n" + h_stderr.decode("utf-8", errors="replace")

        has_dash_l = False
        has_dash_list = False

        for line in help_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("-l,") or stripped.startswith("-l ") or "  -l," in stripped:
                has_dash_l = True
            if "-list" in stripped:
                has_dash_list = True

        if has_dash_l:
            logger.info("[httpx-detect] Detected flag: -l")
            return "-l"
        elif has_dash_list:
            logger.info("[httpx-detect] Detected flag: -list")
            return "-list"
        else:
            logger.info("[httpx-detect] Could not detect flag, defaulting to -l")
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
