"""
ReconX Scope Manager

Controls which domains are in-scope and out-of-scope for scanning.

Scope rules support Unix-style wildcards via :func:`fnmatch.fnmatch`:
- ``*.target.com`` matches any subdomain of ``target.com``
- ``target.com`` matches only the exact domain

Scope state is persisted in the database through :class:`ReconRepository`
and cached locally for fast in-scope checks during tool output filtering.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Protocol

from reconx.core.security import InputValidator, SecurityError

logger = logging.getLogger(__name__)


# ── Repository Protocol ──────────────────────────────────────────────────
# Decouples scope from the concrete repository implementation so this
# module can be tested and used independently of the database layer.


class ScopeRepository(Protocol):
    """Protocol for the scope-related subset of ReconRepository."""

    async def get_scope_rules(self) -> list[dict[str, str]]:
        """Return all scope rules as dicts with 'target' and 'scope_type' keys."""
        ...

    async def add_scope_rule(self, target: str, scope_type: str) -> None:
        """Persist a new scope rule."""
        ...

    async def remove_scope_rule(self, target: str) -> None:
        """Remove a scope rule by target string."""
        ...


# ── Scope Manager ─────────────────────────────────────────────────────────


class ScopeManager:
    """Manages include/exclude scope rules for reconnaissance scans.

    Include rules define what is in scope; exclude rules override them.
    If no include rules are defined, **all** domains are considered in
    scope (open scope). Once at least one include rule exists, only
    matching domains are permitted.

    Wildcards use :func:`fnmatch.fnmatch` semantics:
    - ``*.example.com`` matches ``sub.example.com`` but not ``example.com``.
    - ``example.com`` matches exactly ``example.com``.

    Exclude rules always take precedence over include rules.
    """

    def __init__(self, repo: ScopeRepository) -> None:
        """Initialise the scope manager.

        Args:
            repo: Repository providing scope rule persistence.
                Must implement the :class:`ScopeRepository` protocol.
        """
        self._repo = repo
        self._includes: list[str] = []
        self._excludes: list[str] = []

    # ── Scope Loading ─────────────────────────────────────────────────

    async def load_scope(self) -> None:
        """Load scope rules from the database into local caches.

        This should be called once at scan startup and again if rules
        are modified externally.  Handles missing/malformed records
        gracefully — invalid entries are skipped with a warning.
        """
        self._includes = []
        self._excludes = []

        try:
            rules = await self._repo.get_scope_rules()
        except Exception as exc:
            logger.warning("Failed to load scope rules: %s", exc)
            return

        if not rules or not isinstance(rules, list):
            logger.info("No scope rules found — open scope active")
            return

        for rule in rules:
            if not isinstance(rule, dict):
                logger.warning("Skipping invalid scope rule (not a dict): %r", rule)
                continue

            target = rule.get("target")
            scope_type = rule.get("scope_type")

            if not target or not isinstance(target, str):
                logger.warning("Skipping scope rule with missing/invalid target: %r", rule)
                continue
            if scope_type not in ("include", "exclude"):
                logger.warning("Skipping scope rule with invalid scope_type: %r", rule)
                continue

            if scope_type == "include":
                self._includes.append(target)
            else:
                self._excludes.append(target)

        logger.info(
            "Loaded scope: %d include rules, %d exclude rules",
            len(self._includes),
            len(self._excludes),
        )

    # ── Rule Management ───────────────────────────────────────────────

    async def add_target(
        self, target: str, scope_type: str = "include"
    ) -> None:
        """Add a scope rule and persist it to the database.

        Wildcard targets (starting with ``*.``) are stored as-is.
        Plain domain targets are validated through
        :meth:`InputValidator.validate_domain`.

        Args:
            target: Domain or wildcard pattern (e.g. ``*.target.com``).
            scope_type: Either ``"include"`` or ``"exclude"``.

        Raises:
            SecurityError: If the target fails domain validation.
            ValueError: If ``scope_type`` is not ``include``/``exclude``.
        """
        if scope_type not in ("include", "exclude"):
            raise ValueError(
                f"scope_type must be 'include' or 'exclude', got {scope_type!r}"
            )

        cleaned = target.strip().lower()

        # Validate non-wildcard targets through InputValidator
        if not cleaned.startswith("*."):
            cleaned = InputValidator.validate_domain(cleaned)

        await self._repo.add_scope_rule(cleaned, scope_type)

        # Update local cache
        if scope_type == "include":
            if cleaned not in self._includes:
                self._includes.append(cleaned)
        else:
            if cleaned not in self._excludes:
                self._excludes.append(cleaned)

        logger.info("Added scope rule: %s (%s)", cleaned, scope_type)

    async def remove_target(self, target: str) -> None:
        """Remove a scope rule from the database and local cache.

        Args:
            target: Domain or wildcard pattern to remove.
        """
        cleaned = target.strip().lower()
        await self._repo.remove_scope_rule(cleaned)

        # Update local caches
        self._includes = [t for t in self._includes if t != cleaned]
        self._excludes = [t for t in self._excludes if t != cleaned]
        logger.info("Removed scope rule: %s", cleaned)

    # ── Scope Checking ────────────────────────────────────────────────

    def is_in_scope(self, domain: str) -> bool:
        """Check whether a domain is within the current scope.

        Evaluation order:
        1. If no include rules exist, the scope is open (everything in).
        2. If the domain matches any exclude pattern → ``False``.
        3. If the domain matches any include pattern → ``True``.
        4. Otherwise → ``False``.

        Args:
            domain: Domain name to check (e.g. ``admin.target.com``).

        Returns:
            ``True`` if the domain is in scope.
        """
        normalized = domain.strip().lower()

        # Open scope: nothing defined means everything is allowed
        if not self._includes:
            # Still check excludes even in open scope
            for pattern in self._excludes:
                if fnmatch.fnmatch(normalized, pattern):
                    return False
            return True

        # Excludes override includes
        for pattern in self._excludes:
            if fnmatch.fnmatch(normalized, pattern):
                return False

        # Check includes
        for pattern in self._includes:
            if fnmatch.fnmatch(normalized, pattern):
                return True

        # Includes exist but nothing matched
        return False

    def validate_targets(self, targets: list[str]) -> list[str]:
        """Filter a list of targets to only those in scope.

        Out-of-scope targets are logged as warnings.

        Args:
            targets: List of domain strings to validate.

        Returns:
            List of in-scope targets only.
        """
        valid: list[str] = []
        for target in targets:
            if self.is_in_scope(target):
                valid.append(target)
            else:
                logger.warning(
                    "Target %r is out of scope — skipping", target
                )
        return valid

    # ── Display / Export ──────────────────────────────────────────────

    async def get_scope_display(self) -> dict[str, list[str]]:
        """Return the current scope rules for display.

        Returns:
            Dictionary with ``includes`` and ``excludes`` lists.
        """
        return {
            "includes": list(self._includes),
            "excludes": list(self._excludes),
        }

    def generate_scope_file(self, output_path: Path) -> Path:
        """Write include targets to a file for tools that support --scope.

        Some tools accept a file of in-scope domains. This method
        writes all include patterns to the given path (one per line).

        Args:
            output_path: File path to write scope entries to.

        Returns:
            The path that was written.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            "\n".join(self._includes) + "\n", encoding="utf-8"
        )
        logger.info(
            "Generated scope file with %d entries: %s",
            len(self._includes),
            output_path,
        )
        return output_path
