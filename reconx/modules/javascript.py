"""
Module 7: JavaScript Intelligence

Analyzes JavaScript files to discover hidden API endpoints,
secrets, tokens, and internal references.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import aiohttp
from rich.console import Console

from reconx.core.security import SecretsManager
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


# ── Regex Patterns for JS Analysis ─────────────────────────────────

PATTERNS: dict[str, list[re.Pattern]] = {
    "api_endpoint": [
        re.compile(r"""['"`](/api/[a-zA-Z0-9/_\-\.]+)['"`]"""),
        re.compile(r"""['"`](/v[0-9]+/[a-zA-Z0-9/_\-\.]+)['"`]"""),
        re.compile(r"""['"`](https?://[a-zA-Z0-9.\-]+/api/[a-zA-Z0-9/_\-\.]+)['"`]"""),
    ],
    "graphql_endpoint": [
        re.compile(r"""['"`](/graphql[a-zA-Z0-9/_\-]*)['"`]"""),
        re.compile(r"""['"`](https?://[a-zA-Z0-9.\-]+/graphql[a-zA-Z0-9/_\-]*)['"`]"""),
    ],
    "internal_url": [
        re.compile(r"""(https?://[a-zA-Z0-9][\w.\-]*\.[a-zA-Z]{2,}(?:/[^\s'"`<>]*)?)"""),
    ],
    "api_key": [
        re.compile(r"""(?:api[_\-]?key|apikey)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{16,})['"`]""", re.I),
    ],
    "aws_key": [
        re.compile(r"""(AKIA[A-Z0-9]{16})"""),
        re.compile(r"""(?:aws.{0,20})?(?:secret|key).{0,20}['"`]([a-zA-Z0-9/+=]{40})['"`]""", re.I),
    ],
    "token": [
        re.compile(r"""(?:token|bearer|auth)\s*[:=]\s*['"`]([a-zA-Z0-9_\-\.]{20,})['"`]""", re.I),
        re.compile(r"""['"`](eyJ[a-zA-Z0-9_\-]*\.eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*)['"`]"""),
    ],
    "secret": [
        re.compile(r"""(?:secret|password|passwd|pwd)\s*[:=]\s*['"`]([^\s'"`]{8,})['"`]""", re.I),
        re.compile(r"""['"`](sk_live_[a-zA-Z0-9]{24,})['"`]"""),
        re.compile(r"""['"`](sk_test_[a-zA-Z0-9]{24,})['"`]"""),
    ],
    "firebase_url": [
        re.compile(r"""(https?://[a-zA-Z0-9\-]+\.firebaseio\.com[^\s'"`<>]*)"""),
        re.compile(r"""(https?://[a-zA-Z0-9\-]+\.firebaseapp\.com[^\s'"`<>]*)"""),
    ],
    "private_key": [
        re.compile(r"""-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"""),
    ],
    "hidden_route": [
        re.compile(r"""(?:path|route|href)\s*[:=]\s*['"`](/[a-zA-Z0-9/_\-]+)['"`]""", re.I),
    ],
}


@dataclass
class JSIntelResult:
    """Result of JavaScript intelligence analysis."""

    findings: list[dict] = field(default_factory=list)
    endpoints: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    files_analyzed: int = 0
    total_findings: int = 0


class JavaScriptModule:
    """
    JavaScript intelligence analysis.

    Downloads and analyzes JavaScript files to discover:
    - API endpoints and GraphQL endpoints
    - Internal URLs and hidden routes
    - API keys, tokens, and secrets
    - Firebase URLs and AWS references
    """

    # Maximum JS file size to download (5 MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    async def _download_js(
        self, session: aiohttp.ClientSession, url: str
    ) -> str | None:
        """Download a JavaScript file with size limits."""
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status != 200:
                    return None
                content_length = resp.content_length or 0
                if content_length > self.MAX_FILE_SIZE:
                    return None
                return await resp.text(errors="replace")
        except Exception:
            return None

    def _analyze_content(self, content: str, source_url: str) -> list[dict]:
        """Run all regex patterns against JS content."""
        findings: list[dict] = []
        seen_values: set[str] = set()

        for finding_type, patterns in PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(content):
                    # Get the first capturing group, or full match
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.strip()

                    # Skip duplicates and very short values
                    if not value or len(value) < 4 or value in seen_values:
                        continue
                    seen_values.add(value)

                    findings.append({
                        "finding_type": finding_type,
                        "value": value,
                        "source_url": source_url,
                    })

        return findings

    async def run(
        self, scan_id: int, js_urls: list[str]
    ) -> JSIntelResult:
        """
        Analyze JavaScript files for intelligence.

        Args:
            scan_id: Current scan ID for database storage.
            js_urls: List of JavaScript file URLs to analyze.

        Returns:
            JSIntelResult with all discovered findings.
        """
        console.print("[bold cyan]▶ Module 7:[/] JavaScript Intelligence")

        if not js_urls:
            console.print("  [yellow]⚠[/] No JavaScript files to analyze\n")
            return JSIntelResult()

        console.print(f"  [dim]Analyzing {len(js_urls)} JavaScript files[/]")

        all_findings: list[dict] = []
        endpoints: list[str] = []
        secrets: list[dict] = []
        files_analyzed = 0

        async with aiohttp.ClientSession() as session:
            for url in js_urls:
                content = await self._download_js(session, url)
                if content is None:
                    continue

                files_analyzed += 1
                findings = self._analyze_content(content, url)

                for finding in findings:
                    finding["timestamp"] = datetime.now(timezone.utc)
                    all_findings.append(finding)

                    if finding["finding_type"] in (
                        "api_endpoint", "graphql_endpoint",
                        "internal_url", "hidden_route",
                    ):
                        endpoints.append(finding["value"])
                    elif SecretsManager.should_redact(finding["finding_type"]):
                        secrets.append(finding)

        # Store findings in database
        if all_findings:
            await self._repo.add_js_findings(scan_id, all_findings)

        result = JSIntelResult(
            findings=all_findings,
            endpoints=endpoints,
            secrets=secrets,
            files_analyzed=files_analyzed,
            total_findings=len(all_findings),
        )

        # Display summary with secrets masked
        console.print(
            f"  [bold green]✓ JS analysis complete:[/] "
            f"{files_analyzed} files analyzed, "
            f"{len(endpoints)} endpoints, "
            f"{len(secrets)} secrets\n"
        )

        return result
