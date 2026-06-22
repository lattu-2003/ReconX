"""
Module 8: Endpoint Classification

Categorizes discovered URLs into functional groups to
prioritize manual testing efforts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from rich.console import Console

from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


# ── Classification Patterns ────────────────────────────────────────

CLASSIFICATION_RULES: dict[str, list[re.Pattern]] = {
    "authentication": [
        re.compile(r"/(?:login|signin|sign-in|sso|oauth|auth|cas|saml)", re.I),
        re.compile(r"/(?:register|signup|sign-up|create-account)", re.I),
        re.compile(r"/(?:forgot|reset|recover)[\-_]?(?:password)?", re.I),
        re.compile(r"/(?:logout|signout|sign-out)", re.I),
        re.compile(r"/(?:2fa|mfa|otp|verify)", re.I),
    ],
    "admin": [
        re.compile(r"/(?:admin|administrator|manage|management)", re.I),
        re.compile(r"/(?:dashboard|control[\-_]?panel|cpanel|wp-admin)", re.I),
        re.compile(r"/(?:console|portal|backoffice|back-office)", re.I),
        re.compile(r"/(?:phpmyadmin|adminer|phpinfo)", re.I),
    ],
    "api": [
        re.compile(r"/api(?:/|$)", re.I),
        re.compile(r"/v[0-9]+(?:/|$)", re.I),
        re.compile(r"/rest(?:/|$)", re.I),
        re.compile(r"/(?:swagger|openapi|api-docs|redoc)", re.I),
        re.compile(r"/(?:\.json|\.xml)$", re.I),
    ],
    "graphql": [
        re.compile(r"/graphql", re.I),
        re.compile(r"/graphiql", re.I),
        re.compile(r"/playground", re.I),
        re.compile(r"/altair", re.I),
    ],
    "upload": [
        re.compile(r"/(?:upload|file[\-_]?upload)", re.I),
        re.compile(r"/(?:media|assets|files|attachments)", re.I),
        re.compile(r"/(?:import|export)", re.I),
    ],
    "payment": [
        re.compile(r"/(?:payment|pay|checkout|billing)", re.I),
        re.compile(r"/(?:invoice|subscription|pricing|purchase)", re.I),
        re.compile(r"/(?:stripe|paypal|braintree)", re.I),
    ],
    "config": [
        re.compile(r"/(?:config|configuration|settings|preferences)", re.I),
        re.compile(r"/(?:\.env|\.git|\.svn|\.htaccess|web\.config)", re.I),
        re.compile(r"/(?:robots\.txt|sitemap\.xml|crossdomain\.xml)", re.I),
        re.compile(r"/(?:\.well-known)", re.I),
    ],
    "debug": [
        re.compile(r"/(?:debug|trace|test|status|health)", re.I),
        re.compile(r"/(?:phpinfo|server[\-_]?info|server[\-_]?status)", re.I),
        re.compile(r"/(?:elmah|errorlog|stack[\-_]?trace)", re.I),
        re.compile(r"/(?:actuator|metrics|prometheus)", re.I),
    ],
    "database": [
        re.compile(r"/(?:phpmyadmin|adminer|mongo[\-_]?express)", re.I),
        re.compile(r"/(?:kibana|elasticsearch|grafana|solr)", re.I),
        re.compile(r":[0-9]+/(?:_cat|_cluster|_nodes)", re.I),
    ],
    "devops": [
        re.compile(r"/(?:jenkins|ci|cd|pipeline|build)", re.I),
        re.compile(r"/(?:gitlab|gitea|gogs|bitbucket)", re.I),
        re.compile(r"/(?:sonar|nexus|artifactory|harbor)", re.I),
        re.compile(r"/(?:docker|kubernetes|k8s)", re.I),
    ],
}


@dataclass
class ClassificationResult:
    """Result of endpoint classification."""

    classifications: dict[str, list[str]] = field(default_factory=dict)
    total_classified: int = 0
    total_urls: int = 0


class ClassificationModule:
    """
    Endpoint classification engine.

    Categorizes all discovered URLs into functional groups:
    authentication, admin, API, GraphQL, upload, payment,
    config, debug, database, and devops. Helps prioritize
    which endpoints deserve manual testing first.
    """

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    def _classify_url(self, url: str) -> list[str]:
        """Classify a URL into zero or more categories."""
        categories: list[str] = []
        for category, patterns in CLASSIFICATION_RULES.items():
            for pattern in patterns:
                if pattern.search(url):
                    categories.append(category)
                    break
        return categories

    async def run(
        self,
        scan_id: int,
        all_urls: list[str],
    ) -> ClassificationResult:
        """
        Classify all discovered URLs.

        Args:
            scan_id: Current scan ID for database storage.
            all_urls: All URLs (crawled + historical) to classify.

        Returns:
            ClassificationResult with categorized endpoints.
        """
        console.print("[bold cyan]▶ Module 8:[/] Endpoint Classification")

        if not all_urls:
            console.print("  [yellow]⚠[/] No URLs to classify\n")
            return ClassificationResult()

        classifications: dict[str, list[str]] = {
            cat: [] for cat in CLASSIFICATION_RULES
        }
        db_records: list[dict] = []
        classified_count = 0

        for url in all_urls:
            categories = self._classify_url(url)
            for cat in categories:
                classifications[cat].append(url)
                classified_count += 1
                db_records.append({
                    "url": url,
                    "category": cat,
                    "timestamp": datetime.now(timezone.utc),
                })

        # Store in database
        if db_records:
            await self._repo.add_classifications(scan_id, db_records)

        # Remove empty categories for display
        active_classifications = {
            k: v for k, v in classifications.items() if v
        }

        result = ClassificationResult(
            classifications=active_classifications,
            total_classified=classified_count,
            total_urls=len(all_urls),
        )

        # Display summary
        if active_classifications:
            for cat, urls in sorted(
                active_classifications.items(), key=lambda x: -len(x[1])
            ):
                console.print(f"  [dim]{cat}:[/] {len(urls)} endpoints")

        console.print(
            f"\n  [bold green]✓ Classification complete:[/] "
            f"{classified_count} classified from {len(all_urls)} total\n"
        )
        return result
