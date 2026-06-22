"""
Module 4: Screenshot Collection

Manages screenshot storage and organization from Httpx captures.
Screenshots are taken during the validation phase (Module 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rich.console import Console

from reconx.core.security import FileSecurityManager
from reconx.core.utils import sanitize_filename
from reconx.config import ReconXConfig
from reconx.database.repository import ReconRepository

console = Console()


@dataclass
class ScreenshotResult:
    """Result of screenshot collection."""

    screenshot_paths: list[str] = field(default_factory=list)
    count: int = 0


class ScreenshotsModule:
    """
    Screenshot collection and organization.

    Manages the screenshot output from Httpx, organizing files
    and updating database records with screenshot paths. Useful
    for identifying admin portals, dashboards, login pages,
    staging environments, and development systems.
    """

    def __init__(
        self,
        config: ReconXConfig,
        repo: ReconRepository,
    ) -> None:
        self._config = config
        self._repo = repo

    async def run(self, scan_id: int) -> ScreenshotResult:
        """
        Organize and catalog screenshots from the latest Httpx run.

        Screenshots are already captured during validation (Module 3).
        This module catalogs them and ensures proper permissions.

        Args:
            scan_id: Current scan ID for database reference.

        Returns:
            ScreenshotResult with paths to all screenshots.
        """
        console.print("[bold cyan]▶ Module 4:[/] Screenshot Collection")

        screenshot_dir = self._config.screenshots_dir
        if not screenshot_dir.exists():
            console.print("  [yellow]⚠[/] No screenshots directory found\n")
            return ScreenshotResult()

        # Collect all screenshot files
        screenshot_files: list[str] = []
        supported_extensions = {".png", ".jpg", ".jpeg", ".webp"}

        for filepath in sorted(screenshot_dir.iterdir()):
            if filepath.is_file() and filepath.suffix.lower() in supported_extensions:
                # Secure file permissions
                FileSecurityManager.secure_file(filepath)
                screenshot_files.append(str(filepath))

        result = ScreenshotResult(
            screenshot_paths=screenshot_files,
            count=len(screenshot_files),
        )

        if result.count > 0:
            console.print(
                f"  [bold green]✓ Screenshots cataloged:[/] "
                f"{result.count} captures\n"
            )
        else:
            console.print("  [yellow]⚠[/] No screenshots found\n")

        return result
