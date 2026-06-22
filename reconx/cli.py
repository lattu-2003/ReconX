"""
ReconX CLI

Typer-based command-line interface with Rich formatting.
Entry point for all ReconX operations.
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from reconx import __version__
from reconx.config import ReconXConfig, ScanProfile
from reconx.engine import ScanEngine

console = Console()

# ── Main App ───────────────────────────────────────────────────────

app = typer.Typer(
    name="reconx",
    help="ReconX — Attack Surface Intelligence Framework",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# ── Scope Sub-App ──────────────────────────────────────────────────

scope_app = typer.Typer(
    name="scope",
    help="Manage scan scope (include/exclude targets).",
    no_args_is_help=True,
)
app.add_typer(scope_app, name="scope")


# ── Helper ─────────────────────────────────────────────────────────

def _run_async(coro):
    """Run an async coroutine from synchronous Typer commands."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return pool.submit(asyncio.run, coro).result()
    else:
        return asyncio.run(coro)


def _parse_targets(target: str) -> list[str]:
    """Parse a target string into a list of targets."""
    targets = []
    for t in target.split(","):
        t = t.strip()
        if t:
            targets.append(t)
    return targets


# ── Scan Commands ──────────────────────────────────────────────────

@app.command()
def quick(
    target: Annotated[str, typer.Argument(help="Target domain(s), comma-separated")],
    threads: Annotated[int, typer.Option("--threads", "-t", help="Concurrent threads")] = 50,
    rate_limit: Annotated[int, typer.Option("--rate-limit", "-r", help="Rate limit (req/s)")] = 150,
    timeout: Annotated[int, typer.Option("--timeout", help="Tool timeout (seconds)")] = 30,
) -> None:
    """
    [bold cyan]Quick scan[/] — Rapid triage with Subfinder + Httpx.

    Fast subdomain enumeration and HTTP validation.
    Use for initial assessment of a new target.
    """
    config = ReconXConfig(threads=threads, rate_limit=rate_limit, timeout=timeout)
    targets = _parse_targets(target)
    engine = ScanEngine(config)

    scan_id = _run_async(engine.run_scan(targets, ScanProfile.QUICK))
    if scan_id > 0:
        console.print(
            f"[dim]Scan ID: {scan_id} — "
            f"Run 'reconx report {target}' to generate reports[/]"
        )


@app.command()
def standard(
    target: Annotated[str, typer.Argument(help="Target domain(s), comma-separated")],
    threads: Annotated[int, typer.Option("--threads", "-t", help="Concurrent threads")] = 50,
    rate_limit: Annotated[int, typer.Option("--rate-limit", "-r", help="Rate limit (req/s)")] = 150,
    timeout: Annotated[int, typer.Option("--timeout", help="Tool timeout (seconds)")] = 30,
    ports: Annotated[str, typer.Option("--ports", "-p", help="Ports to scan")] = "80,443,8080,8443,3000,5000,9200",
) -> None:
    """
    [bold yellow]Standard scan[/] — Full bug bounty workflow.

    Runs: Subfinder → Naabu → Httpx → Katana → Nuclei
    with risk scoring and change detection.
    """
    config = ReconXConfig(
        threads=threads, rate_limit=rate_limit, timeout=timeout, default_ports=ports
    )
    targets = _parse_targets(target)
    engine = ScanEngine(config)

    scan_id = _run_async(engine.run_scan(targets, ScanProfile.STANDARD))
    if scan_id > 0:
        console.print(
            f"[dim]Scan ID: {scan_id} — "
            f"Run 'reconx report {target}' to generate reports[/]"
        )


@app.command()
def deep(
    target: Annotated[str, typer.Argument(help="Target domain(s), comma-separated")],
    threads: Annotated[int, typer.Option("--threads", "-t", help="Concurrent threads")] = 50,
    rate_limit: Annotated[int, typer.Option("--rate-limit", "-r", help="Rate limit (req/s)")] = 150,
    timeout: Annotated[int, typer.Option("--timeout", help="Tool timeout (seconds)")] = 30,
    ports: Annotated[str, typer.Option("--ports", "-p", help="Ports to scan")] = "80,443,8080,8443,3000,5000,9200",
    show_secrets: Annotated[bool, typer.Option("--show-secrets", help="Show full secret values")] = False,
) -> None:
    """
    [bold red]Deep scan[/] — Maximum attack surface discovery.

    Runs all modules: Subfinder → Naabu → Httpx → Katana →
    Gau → JS Intelligence → Risk Scoring → Nuclei.
    """
    config = ReconXConfig(
        threads=threads,
        rate_limit=rate_limit,
        timeout=timeout,
        default_ports=ports,
        show_secrets=show_secrets,
    )
    targets = _parse_targets(target)
    engine = ScanEngine(config)

    scan_id = _run_async(engine.run_scan(targets, ScanProfile.DEEP))
    if scan_id > 0:
        console.print(
            f"[dim]Scan ID: {scan_id} — "
            f"Run 'reconx report {target}' to generate reports[/]"
        )


# ── Report Command ─────────────────────────────────────────────────

@app.command()
def report(
    target: Annotated[str, typer.Argument(help="Target domain to report on")],
    format: Annotated[str, typer.Option("--format", "-f", help="Report format: html, json, markdown, all")] = "all",
) -> None:
    """
    Generate reports from the latest scan.

    Outputs HTML, JSON, and/or Markdown reports to ~/.reconx/results/reports/
    """
    async def _generate():
        from reconx.reporting.generator import ReportGenerator

        config = ReconXConfig()
        from reconx.database.engine import DatabaseManager
        from reconx.database.repository import ReconRepository

        db = DatabaseManager(config.db_url)
        await db.initialize()

        try:
            repo = ReconRepository(db.session_factory)
            scan = await repo.get_latest_scan(target)

            if scan is None:
                console.print(f"[red]✗ No scans found for {target}[/]")
                return

            generator = ReportGenerator(config, repo)
            formats = [format] if format != "all" else ["html", "json", "markdown"]

            for fmt in formats:
                output_path = await generator.generate(scan.id, target, fmt)
                console.print(
                    f"[green]✓[/] {fmt.upper()} report: [link={output_path}]{output_path}[/link]"
                )
        finally:
            await db.close()

    _run_async(_generate())


# ── Compare Command ────────────────────────────────────────────────

@app.command()
def compare(
    target: Annotated[str, typer.Argument(help="Target domain to compare scans")],
) -> None:
    """
    Compare the two most recent scans for a target.

    Shows new/removed subdomains, hosts, and findings.
    """
    async def _compare():
        config = ReconXConfig()
        from reconx.database.engine import DatabaseManager
        from reconx.database.repository import ReconRepository
        from reconx.modules.changes import ChangesModule

        db = DatabaseManager(config.db_url)
        await db.initialize()

        try:
            repo = ReconRepository(db.session_factory)
            scan = await repo.get_latest_scan(target)

            if scan is None:
                console.print(f"[red]✗ No scans found for {target}[/]")
                return

            changes = ChangesModule(config, repo)
            result = await changes.run(scan.id, target)

            if not result.has_changes:
                console.print("[green]No changes detected between scans.[/]")
        finally:
            await db.close()

    _run_async(_compare())


# ── Status Command ─────────────────────────────────────────────────

@app.command()
def status() -> None:
    """
    Check availability of all required external tools.
    """
    from reconx.core.runner import ToolRunner

    console.print(
        Panel(
            f"[bold]ReconX[/] v{__version__}\n"
            "[dim]Attack Surface Intelligence Framework[/]",
            border_style="cyan",
        )
    )

    runner = ToolRunner()
    tools = runner.check_all_tools()

    table = Table(title="Tool Status", show_lines=False)
    table.add_column("Tool", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Path", style="dim")

    import shutil

    for tool, available in sorted(tools.items()):
        if available:
            path = shutil.which(tool) or "found"
            table.add_row(tool, "[bold green]✓ Available[/]", path)
        else:
            table.add_row(tool, "[bold red]✗ Missing[/]", "not found")

    console.print(table)

    missing = [t for t, a in tools.items() if not a]
    if missing:
        console.print(
            f"\n[yellow]⚠ {len(missing)} tool(s) missing. "
            f"See DEPLOYMENT.md for installation instructions.[/]"
        )
    else:
        console.print("\n[bold green]✓ All tools available. Ready to scan![/]")


# ── Scope Commands ─────────────────────────────────────────────────

@scope_app.command("add")
def scope_add(
    target: Annotated[str, typer.Argument(help="Domain to add to scope")],
    exclude: Annotated[bool, typer.Option("--exclude", "-e", help="Add as exclusion")] = False,
) -> None:
    """Add a target to the scope."""
    async def _add():
        config = ReconXConfig()
        engine = ScanEngine(config)
        scope_type = "exclude" if exclude else "include"
        await engine.add_scope(target, scope_type)
        console.print(
            f"[green]✓[/] Added [bold]{target}[/] "
            f"as [{'red' if exclude else 'green'}]{scope_type}[/]"
        )

    _run_async(_add())


@scope_app.command("remove")
def scope_remove(
    target: Annotated[str, typer.Argument(help="Domain to remove from scope")],
) -> None:
    """Remove a target from the scope."""
    async def _remove():
        config = ReconXConfig()
        engine = ScanEngine(config)
        await engine.remove_scope(target)
        console.print(f"[green]✓[/] Removed [bold]{target}[/] from scope")

    _run_async(_remove())


@scope_app.command("show")
def scope_show() -> None:
    """Display current scope rules."""
    async def _show():
        config = ReconXConfig()
        engine = ScanEngine(config)
        scope = await engine.get_scope()

        if not scope.get("includes") and not scope.get("excludes"):
            console.print(
                "[dim]No scope rules defined. "
                "All targets will be accepted.[/]"
            )
            return

        table = Table(title="Scope Rules", show_lines=False)
        table.add_column("Type", style="bold")
        table.add_column("Target", style="cyan")

        for target in scope.get("includes", []):
            table.add_row("[green]Include[/]", target)
        for target in scope.get("excludes", []):
            table.add_row("[red]Exclude[/]", target)

        console.print(table)

    _run_async(_show())


# ── Version Callback ───────────────────────────────────────────────

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        Optional[bool],
        typer.Option("--version", "-v", help="Show version"),
    ] = None,
) -> None:
    """ReconX — Attack Surface Intelligence Framework"""
    if version:
        console.print(f"ReconX v{__version__}")
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
