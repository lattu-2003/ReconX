"""
ReconX Dashboard Generator

Generates a standalone HTML dashboard with scan metrics,
technology breakdown, and top risk-scored assets.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console

from reconx.core.security import FileSecurityManager
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


class DashboardGenerator:
    """
    Static HTML dashboard generator.

    Creates a self-contained dashboard with summary metrics,
    technology breakdown charts, and risk-scored asset tables.
    Uses Chart.js CDN for visualizations.
    """

    def __init__(self, config: ReconXConfig, repo: ReconRepository) -> None:
        self._config = config
        self._repo = repo
        self._env = Environment(
            loader=PackageLoader("reconx", "reporting/templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate(self, scan_id: int, target: str) -> Path:
        """
        Generate the HTML dashboard.

        Args:
            scan_id: Scan ID to generate dashboard for.
            target: Target domain name.

        Returns:
            Path to the generated dashboard HTML file.
        """
        # Gather data
        summary = await self._repo.get_scan_summary(scan_id)
        severity_counts = await self._repo.get_findings_by_severity(scan_id)
        profiles = await self._repo.get_asset_profiles(scan_id)
        hosts = await self._repo.get_hosts(scan_id)

        # Aggregate technologies
        tech_counts: dict[str, int] = {}
        for host in hosts:
            try:
                techs = json.loads(host.technologies) if host.technologies else []
            except (json.JSONDecodeError, TypeError):
                techs = []
            for tech in techs:
                tech_counts[tech] = tech_counts.get(tech, 0) + 1

        # Sort by frequency
        top_techs = sorted(tech_counts.items(), key=lambda x: -x[1])[:15]

        # Parse and sort profiles by risk score
        parsed_profiles = []
        for profile in profiles:
            try:
                techs = json.loads(profile.technologies) if profile.technologies else []
            except (json.JSONDecodeError, TypeError):
                techs = []
            try:
                reasons = json.loads(profile.reasons) if profile.reasons else []
            except (json.JSONDecodeError, TypeError):
                reasons = []
            parsed_profiles.append({
                "host": profile.host,
                "technologies": techs,
                "risk_score": profile.risk_score,
                "reasons": reasons,
            })
        parsed_profiles.sort(key=lambda x: x["risk_score"], reverse=True)

        # Render template
        template = self._env.get_template("dashboard.html.j2")
        html = template.render(
            target=target,
            scan_id=scan_id,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            summary=summary,
            severity_counts=severity_counts,
            profiles=parsed_profiles[:20],
            tech_labels=json.dumps([t[0] for t in top_techs]),
            tech_values=json.dumps([t[1] for t in top_techs]),
            severity_labels=json.dumps(list(severity_counts.keys())),
            severity_values=json.dumps(list(severity_counts.values())),
        )

        output_path = self._config.reports_dir / f"{target}_dashboard.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        FileSecurityManager.secure_file(output_path)

        console.print(f"[green]✓[/] Dashboard: [link={output_path}]{output_path}[/link]")
        return output_path
