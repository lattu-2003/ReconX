"""
ReconX Report Generator

Generates HTML, JSON, and Markdown reports from scan data.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, PackageLoader, select_autoescape
from rich.console import Console

from reconx.core.security import FileSecurityManager, SecretsManager
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


class ReportGenerator:
    """
    Multi-format report generator.

    Produces HTML, JSON, and Markdown reports from scan data
    stored in the database. All outputs use XSS-safe rendering.
    """

    def __init__(self, config: ReconXConfig, repo: ReconRepository) -> None:
        self._config = config
        self._repo = repo
        self._env = Environment(
            loader=PackageLoader("reconx", "reporting/templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )

    async def generate(
        self, scan_id: int, target: str, format: str
    ) -> Path:
        """
        Generate a report in the specified format.

        Args:
            scan_id: Scan ID to report on.
            target: Target domain name.
            format: One of 'html', 'json', 'markdown'.

        Returns:
            Path to the generated report file.
        """
        # Gather all data
        data = await self._gather_data(scan_id, target)

        # Generate in requested format
        if format == "html":
            return await self._generate_html(data, target)
        elif format == "json":
            return await self._generate_json(data, target)
        elif format == "markdown":
            return await self._generate_markdown(data, target)
        else:
            raise ValueError(f"Unknown format: {format}")

    async def _gather_data(self, scan_id: int, target: str) -> dict:
        """Gather all scan data for reporting."""
        summary = await self._repo.get_scan_summary(scan_id)
        hosts = await self._repo.get_hosts(scan_id)
        findings = await self._repo.get_findings(scan_id)
        profiles = await self._repo.get_asset_profiles(scan_id)
        classifications = await self._repo.get_classifications(scan_id)
        js_findings = await self._repo.get_js_findings(scan_id)
        severity_counts = await self._repo.get_findings_by_severity(scan_id)
        subdomains = await self._repo.get_subdomains(scan_id)
        ports = await self._repo.get_ports(scan_id)
        change_events = await self._repo.get_change_events(target)

        return {
            "target": target,
            "scan_id": scan_id,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "summary": summary,
            "hosts": hosts,
            "findings": findings,
            "profiles": profiles,
            "classifications": classifications,
            "js_findings": js_findings,
            "severity_counts": severity_counts,
            "subdomains": subdomains,
            "ports": ports,
            "change_events": change_events,
        }

    async def _generate_html(self, data: dict, target: str) -> Path:
        """Generate HTML report with XSS-safe rendering."""
        template = self._env.get_template("report.html.j2")

        # Mask secrets in JS findings
        masked_js = []
        for finding in data.get("js_findings", []):
            masked = {
                "finding_type": finding.finding_type,
                "value": SecretsManager.redact_value(
                    finding.value, finding.finding_type, show_full=False
                ),
                "source_url": finding.source_url,
            }
            masked_js.append(masked)

        # Parse technologies for profiles
        parsed_profiles = []
        for profile in data.get("profiles", []):
            try:
                techs = json.loads(profile.technologies) if profile.technologies else []
            except (json.JSONDecodeError, TypeError):
                techs = []
            try:
                paths = json.loads(profile.interesting_paths) if profile.interesting_paths else []
            except (json.JSONDecodeError, TypeError):
                paths = []
            try:
                reasons = json.loads(profile.reasons) if profile.reasons else []
            except (json.JSONDecodeError, TypeError):
                reasons = []
            parsed_profiles.append({
                "host": profile.host,
                "technologies": techs,
                "interesting_paths": paths,
                "risk_score": profile.risk_score,
                "reasons": reasons,
            })

        # Sort profiles by risk score
        parsed_profiles.sort(key=lambda x: x["risk_score"], reverse=True)

        html = template.render(
            target=data["target"],
            scan_id=data["scan_id"],
            generated_at=data["generated_at"],
            summary=data["summary"],
            hosts=data["hosts"],
            findings=data["findings"],
            profiles=parsed_profiles,
            js_findings=masked_js,
            severity_counts=data["severity_counts"],
            subdomains=data["subdomains"],
            ports=data["ports"],
        )

        output_path = self._config.reports_dir / f"{target}_report.html"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")
        FileSecurityManager.secure_file(output_path)
        return output_path

    async def _generate_json(self, data: dict, target: str) -> Path:
        """Generate JSON report (machine-readable)."""
        # Serialize all ORM objects to dicts
        json_data = {
            "meta": {
                "target": data["target"],
                "scan_id": data["scan_id"],
                "generated_at": data["generated_at"],
                "framework": "ReconX",
            },
            "summary": data["summary"],
            "subdomains": [
                {"subdomain": s.subdomain, "source": s.source}
                for s in data.get("subdomains", [])
            ],
            "ports": [
                {"host": p.host, "port": p.port, "service": p.service}
                for p in data.get("ports", [])
            ],
            "hosts": [
                {
                    "url": h.url,
                    "status_code": h.status_code,
                    "title": h.title,
                    "technologies": h.technologies,
                    "ip": h.ip,
                    "asn": h.asn,
                }
                for h in data.get("hosts", [])
            ],
            "findings": [
                {
                    "template": f.template,
                    "severity": f.severity,
                    "host": f.host,
                    "url": f.url,
                    "description": f.description,
                }
                for f in data.get("findings", [])
            ],
            "js_findings": [
                {
                    "type": jf.finding_type,
                    "value": jf.value,
                    "source": jf.source_url,
                }
                for jf in data.get("js_findings", [])
            ],
            "severity_counts": data.get("severity_counts", {}),
        }

        output_path = self._config.reports_dir / f"{target}_report.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(json_data, indent=2, default=str), encoding="utf-8"
        )
        FileSecurityManager.secure_file(output_path)
        return output_path

    async def _generate_markdown(self, data: dict, target: str) -> Path:
        """Generate Markdown report (bug bounty friendly)."""
        lines: list[str] = []
        summary = data.get("summary", {})

        lines.append(f"# ReconX Report — {target}")
        lines.append(f"\n*Generated: {data['generated_at']}*\n")

        # Summary
        lines.append("## Summary\n")
        lines.append("| Metric | Count |")
        lines.append("|---|---|")
        for key, value in summary.items():
            if isinstance(value, (int, float)) and value > 0:
                lines.append(f"| {key.replace('_', ' ').title()} | {value:,} |")

        # Top Risk Assets
        profiles = data.get("profiles", [])
        if profiles:
            lines.append("\n## Top Risk Assets\n")
            lines.append("| Score | Host | Technologies |")
            lines.append("|---|---|---|")
            sorted_profiles = sorted(
                profiles, key=lambda p: p.risk_score, reverse=True
            )
            for p in sorted_profiles[:20]:
                try:
                    techs = json.loads(p.technologies) if p.technologies else []
                except (json.JSONDecodeError, TypeError):
                    techs = []
                techs_str = ", ".join(techs[:5]) if techs else "—"
                lines.append(f"| {p.risk_score} | {p.host} | {techs_str} |")

        # Findings
        findings = data.get("findings", [])
        if findings:
            lines.append("\n## Vulnerability Findings\n")
            lines.append("| Severity | Template | Host | Description |")
            lines.append("|---|---|---|---|")
            for f in sorted(findings, key=lambda x: {
                "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4
            }.get(x.severity, 5)):
                lines.append(
                    f"| {f.severity.upper()} | {f.template} | "
                    f"{f.host} | {f.description or '—'} |"
                )

        # JS Findings (masked)
        js_findings = data.get("js_findings", [])
        if js_findings:
            lines.append("\n## JavaScript Findings\n")
            lines.append("| Type | Value | Source |")
            lines.append("|---|---|---|")
            for jf in js_findings:
                masked_val = SecretsManager.redact_value(
                    jf.value, jf.finding_type, show_full=False
                )
                lines.append(
                    f"| {jf.finding_type} | `{masked_val}` | {jf.source_url} |"
                )

        # Footer
        lines.append("\n---")
        lines.append("*Generated by ReconX — Attack Surface Intelligence Framework*")

        output_path = self._config.reports_dir / f"{target}_report.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text("\n".join(lines), encoding="utf-8")
        FileSecurityManager.secure_file(output_path)
        return output_path
