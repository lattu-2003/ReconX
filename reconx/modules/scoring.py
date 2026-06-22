"""
Module 10: Risk Scoring Engine

Calculates risk scores (0-100) for each asset based on
keywords, technologies, status codes, endpoints, and secrets.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console
from rich.table import Table

from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository
from reconx.modules.intelligence import AssetProfile

console = Console()


# ── Scoring Weights ────────────────────────────────────────────────

KEYWORD_SCORES: dict[str, int] = {
    "admin": 20,
    "dev": 15,
    "development": 15,
    "staging": 20,
    "stage": 20,
    "internal": 25,
    "vpn": 25,
    "jira": 20,
    "jenkins": 20,
    "grafana": 15,
    "kibana": 15,
    "gitlab": 20,
    "sonarqube": 15,
    "nexus": 15,
    "confluence": 18,
    "test": 10,
    "debug": 15,
    "api": 10,
    "portal": 12,
    "console": 15,
    "manage": 12,
    "monitor": 12,
    "backup": 15,
    "old": 10,
    "legacy": 12,
}

TECHNOLOGY_SCORES: dict[str, int] = {
    "jenkins": 20,
    "confluence": 18,
    "grafana": 15,
    "tomcat": 15,
    "wordpress": 12,
    "graphql": 15,
    "elasticsearch": 18,
    "kibana": 15,
    "jira": 18,
    "spring": 10,
    "django": 8,
    "laravel": 8,
    "phpmyadmin": 20,
    "weblogic": 18,
    "jboss": 18,
    "adobe experience manager": 15,
    "struts": 18,
    "drupal": 12,
    "nginx": 5,
    "apache": 5,
    "iis": 8,
}

STATUS_CODE_SCORES: dict[int, int] = {
    200: 5,
    401: 15,  # Unauthorized - auth wall worth investigating
    403: 10,  # Forbidden - potential bypass
    500: 20,  # Server error - potential for exploitation
    502: 10,
    503: 8,
}


@dataclass
class ScoringResult:
    """Result of risk scoring."""

    scored_profiles: list[AssetProfile] = field(default_factory=list)
    high_value_count: int = 0
    avg_score: float = 0.0


class ScoringModule:
    """
    Risk Scoring Engine.

    Calculates a 0-100 risk score for each asset to answer:
    "Which assets deserve manual testing first?"

    Scoring factors:
    - Subdomain keywords (admin, dev, staging, etc.)
    - Detected technologies (Jenkins, Grafana, etc.)
    - HTTP status codes (401, 403, 500 are interesting)
    - Classified endpoints (auth, admin, upload, etc.)
    - JS secrets found
    - Non-standard open ports
    """

    ENDPOINT_BONUS = 5        # Per interesting endpoint, max 25
    ENDPOINT_MAX = 25
    SECRET_BONUS = 15         # Per JS secret, max 30
    SECRET_MAX = 30
    PORT_BONUS = 10           # Per non-standard port, max 20
    PORT_MAX = 20
    MAX_SCORE = 100

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    def _score_asset(self, profile: AssetProfile) -> tuple[int, list[str]]:
        """
        Calculate risk score for a single asset.

        Returns:
            Tuple of (score, list of reasons).
        """
        score = 0
        reasons: list[str] = []
        host_lower = profile.host.lower()

        # 1. Subdomain keyword scoring
        for keyword, points in KEYWORD_SCORES.items():
            if keyword in host_lower:
                score += points
                reasons.append(f"Keyword '{keyword}' detected (+{points})")

        # 2. Technology scoring
        for tech in profile.technologies:
            tech_lower = tech.lower()
            for tech_name, points in TECHNOLOGY_SCORES.items():
                if tech_name in tech_lower:
                    score += points
                    reasons.append(f"Technology '{tech}' detected (+{points})")
                    break

        # 3. Status code scoring
        if profile.status_code and profile.status_code in STATUS_CODE_SCORES:
            points = STATUS_CODE_SCORES[profile.status_code]
            score += points
            reasons.append(f"Status {profile.status_code} (+{points})")

        # 4. Interesting endpoints bonus
        endpoint_bonus = min(
            len(profile.interesting_paths) * self.ENDPOINT_BONUS,
            self.ENDPOINT_MAX,
        )
        if endpoint_bonus > 0:
            score += endpoint_bonus
            reasons.append(
                f"{len(profile.interesting_paths)} interesting endpoints "
                f"(+{endpoint_bonus})"
            )

        # 5. JS secrets bonus
        secret_bonus = min(
            profile.js_secrets_count * self.SECRET_BONUS,
            self.SECRET_MAX,
        )
        if secret_bonus > 0:
            score += secret_bonus
            reasons.append(
                f"{profile.js_secrets_count} JS secrets found (+{secret_bonus})"
            )

        # 6. Non-standard ports bonus
        standard_ports = {80, 443}
        non_standard = [p for p in profile.open_ports if p not in standard_ports]
        port_bonus = min(len(non_standard) * self.PORT_BONUS, self.PORT_MAX)
        if port_bonus > 0:
            score += port_bonus
            reasons.append(
                f"{len(non_standard)} non-standard ports (+{port_bonus})"
            )

        # Cap at MAX_SCORE
        final_score = min(score, self.MAX_SCORE)
        return final_score, reasons

    async def run(
        self,
        scan_id: int,
        profiles: list[AssetProfile],
    ) -> ScoringResult:
        """
        Score all asset profiles.

        Args:
            scan_id: Current scan ID for database updates.
            profiles: Asset profiles from the intelligence module.

        Returns:
            ScoringResult with scored profiles.
        """
        console.print("[bold cyan]▶ Module 10:[/] Risk Scoring Engine")

        if not profiles:
            console.print("  [yellow]⚠[/] No profiles to score\n")
            return ScoringResult()

        # Score each profile
        scores_update: dict[str, tuple[int, list[str]]] = {}

        for profile in profiles:
            score, reasons = self._score_asset(profile)
            profile.risk_score = score
            profile.reasons = reasons
            scores_update[profile.host] = (score, reasons)

        # Update scores in database
        if scores_update:
            await self._repo.update_risk_scores(scan_id, scores_update)

        # Sort by score descending
        profiles.sort(key=lambda p: p.risk_score, reverse=True)

        # Count high-value targets
        high_value = [p for p in profiles if p.risk_score >= 50]
        total_score = sum(p.risk_score for p in profiles)
        avg_score = total_score / len(profiles) if profiles else 0

        # Display top targets
        table = Table(title="Top Risk-Scored Assets", show_lines=False)
        table.add_column("Score", justify="right", style="bold")
        table.add_column("Host", style="cyan")
        table.add_column("Top Reason", style="dim")

        for profile in profiles[:10]:
            score_style = "bold red" if profile.risk_score >= 75 else (
                "bold yellow" if profile.risk_score >= 50 else "green"
            )
            top_reason = profile.reasons[0] if profile.reasons else "—"
            table.add_row(
                f"[{score_style}]{profile.risk_score}[/]",
                profile.host,
                top_reason,
            )

        console.print(table)

        result = ScoringResult(
            scored_profiles=profiles,
            high_value_count=len(high_value),
            avg_score=avg_score,
        )

        console.print(
            f"\n  [bold green]✓ Scoring complete:[/] "
            f"{len(high_value)} high-value targets, "
            f"avg score {avg_score:.1f}\n"
        )
        return result
