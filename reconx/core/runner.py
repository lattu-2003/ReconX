"""
ReconX Tool Runner

Secure asynchronous execution engine for external reconnaissance tools.

All tool invocations are:
- Allowlisted: only known tools can be executed.
- Resolved: binary paths are found via ``shutil.which()``, never by name.
- Validated: every CLI argument passes ``InputValidator.validate_argument``.
- Isolated: subprocesses receive a minimal environment (PATH, HOME only).
- Logged: every execution is recorded by the audit logger.
- Never use ``shell=True``.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
from pathlib import Path
from typing import Any

from reconx.core.security import AuditLogger, InputValidator, SecurityError
from reconx.core.utils import parse_jsonl

logger = logging.getLogger(__name__)


# ── Exceptions ────────────────────────────────────────────────────────────


class ToolNotFoundError(Exception):
    """Raised when a required external tool cannot be found on PATH."""

    pass


# ── Tool Runner ───────────────────────────────────────────────────────────


class ToolRunner:
    """Secure execution wrapper for ProjectDiscovery and related CLI tools.

    Tools are executed as async subprocesses with:
    - An allowlist gate (only ``ALLOWED_TOOLS`` may run).
    - Absolute binary resolution via ``shutil.which()``.
    - Per-argument validation to prevent shell injection.
    - A stripped-down environment to limit information leakage.
    - Configurable timeouts with proper cleanup on expiry.
    """

    ALLOWED_TOOLS: frozenset[str] = frozenset(
        {"subfinder", "naabu", "httpx", "katana", "nuclei", "gau"}
    )

    def __init__(
        self,
        audit_logger: AuditLogger | None = None,
        timeout: int = 600,
    ) -> None:
        """Initialise the tool runner.

        Args:
            audit_logger: Optional audit logger for recording executions.
            timeout: Default timeout in seconds for tool invocations.
        """
        self._audit_logger = audit_logger
        self._timeout = timeout
        self._tool_paths: dict[str, str] = {}

    # ── Binary Resolution ─────────────────────────────────────────────

    def _resolve_tool(self, tool: str) -> str:
        """Find the absolute path to a tool binary.

        Results are cached so that repeated calls to the same tool do
        not hit the filesystem.

        Args:
            tool: Tool name from :attr:`ALLOWED_TOOLS`.

        Returns:
            Absolute path to the tool binary.

        Raises:
            SecurityError: If ``tool`` is not in the allowlist.
            ToolNotFoundError: If the binary is not found on ``PATH``.
        """
        if tool not in self.ALLOWED_TOOLS:
            raise SecurityError(
                f"Tool {tool!r} is not in the allowed tools list: "
                f"{sorted(self.ALLOWED_TOOLS)}"
            )

        if tool in self._tool_paths:
            return self._tool_paths[tool]

        resolved = shutil.which(tool)
        if resolved is None:
            raise ToolNotFoundError(
                f"Tool {tool!r} not found on PATH. "
                f"Install it and ensure it is accessible."
            )

        self._tool_paths[tool] = resolved
        return resolved

    def _minimal_env(self) -> dict[str, str]:
        """Build a minimal environment for subprocess execution.

        Only essential variables are forwarded to limit information
        leakage and reduce the attack surface of child processes.

        Returns:
            Dictionary of environment variables.
        """
        env: dict[str, str] = {}
        for key in ("PATH", "HOME", "USER", "LANG", "TERM"):
            value = os.environ.get(key)
            if value is not None:
                env[key] = value

        # On Windows, SystemRoot and USERPROFILE are often required
        if os.name == "nt":
            for key in ("SystemRoot", "USERPROFILE", "APPDATA", "TEMP", "TMP"):
                value = os.environ.get(key)
                if value is not None:
                    env[key] = value

        return env

    # ── Tool Availability ─────────────────────────────────────────────

    def check_tool(self, tool: str) -> bool:
        """Check whether a single tool is available on PATH.

        Args:
            tool: Tool name to check.

        Returns:
            ``True`` if the tool binary is found, ``False`` otherwise.
        """
        if tool not in self.ALLOWED_TOOLS:
            return False
        return shutil.which(tool) is not None

    def check_all_tools(self) -> dict[str, bool]:
        """Check availability of all allowed tools.

        Returns:
            Dictionary mapping each tool name to its availability.
        """
        return {tool: self.check_tool(tool) for tool in sorted(self.ALLOWED_TOOLS)}

    # ── Execution ─────────────────────────────────────────────────────

    async def run(
        self,
        tool: str,
        args: list[str],
        parse_json: bool = True,
        timeout: int | None = None,
        target: str = "",
    ) -> list[dict[str, Any]] | str:
        """Execute an external tool and capture its output.

        Args:
            tool: Tool name (must be in :attr:`ALLOWED_TOOLS`).
            args: List of CLI arguments. Each is validated for shell
                meta-characters before use.
            parse_json: If ``True``, stdout is parsed as JSONL and a
                list of dicts is returned. Otherwise raw stdout text.
            timeout: Seconds to wait before killing the process.
                Defaults to the instance-level ``_timeout``.
            target: Target being scanned (for audit logging).

        Returns:
            Parsed JSONL list or raw stdout string.

        Raises:
            SecurityError: If the tool is not allowlisted or an argument
                contains dangerous characters.
            ToolNotFoundError: If the tool binary cannot be found.
            TimeoutError: If the process exceeds the timeout.
        """
        # 1. Resolve binary (validates allowlist internally)
        binary_path = self._resolve_tool(tool)

        # 2. Validate every argument
        validated_args: list[str] = []
        for arg in args:
            validated_args.append(InputValidator.validate_argument(arg))

        # 3. Audit log
        effective_timeout = timeout if timeout is not None else self._timeout
        args_summary = " ".join(validated_args[:6])
        if len(validated_args) > 6:
            args_summary += f" ... (+{len(validated_args) - 6} more)"

        if self._audit_logger is not None:
            self._audit_logger.log_tool_execution(
                tool=tool,
                args_summary=args_summary,
                target=target,
            )

        # 4. Create subprocess — never shell=True
        logger.debug(
            "Running %s with %d args (timeout=%ds)",
            tool,
            len(validated_args),
            effective_timeout,
        )

        proc = await asyncio.create_subprocess_exec(
            binary_path,
            *validated_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._minimal_env(),
        )

        # 5. Wait with timeout
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(), timeout=effective_timeout
            )
        except asyncio.TimeoutError:
            # Kill runaway process
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            logger.error(
                "Tool %s timed out after %ds for target %s",
                tool,
                effective_timeout,
                target,
            )
            raise TimeoutError(
                f"Tool {tool!r} timed out after {effective_timeout}s"
            )

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if proc.returncode != 0:
            logger.warning(
                "Tool %s exited with code %d. stderr: %s",
                tool,
                proc.returncode,
                stderr_text[:500],
            )

        # 6. Parse output
        if parse_json:
            return parse_jsonl(stdout_text)
        return stdout_text

    async def run_with_input_file(
        self,
        tool: str,
        args: list[str],
        input_lines: list[str],
        temp_dir: Path,
        parse_json: bool = True,
        timeout: int | None = None,
        target: str = "",
    ) -> list[dict[str, Any]] | str:
        """Execute a tool with targets provided via a temporary input file.

        Many ProjectDiscovery tools accept a ``-list <file>`` argument.
        This method writes the input lines to a secure temporary file,
        replaces the ``-list`` placeholder in ``args`` with the file
        path, runs the tool, and cleans up the temp file.

        The placeholder ``-list`` must appear in ``args`` as a bare
        flag; the file path is inserted immediately after it.

        Args:
            tool: Tool name (must be in :attr:`ALLOWED_TOOLS`).
            args: Argument list. Must contain ``-list`` as a standalone
                element; the temp-file path is appended after it.
            input_lines: Lines to write to the temporary input file.
            temp_dir: Directory for the temporary file.
            parse_json: If ``True``, parse stdout as JSONL.
            timeout: Per-invocation timeout override.
            target: Target label for audit logging.

        Returns:
            Parsed JSONL list or raw stdout string.
        """
        from reconx.core.security import FileSecurityManager

        temp_file: Path | None = None
        try:
            # 1. Create and populate the input file
            temp_file = FileSecurityManager.secure_temp_file(
                directory=temp_dir, prefix=f"reconx_{tool}_"
            )
            temp_file.write_text(
                "\n".join(input_lines) + "\n", encoding="utf-8"
            )

            # 2. Build final args: replace '-list' placeholder with file path
            final_args: list[str] = []
            for arg in args:
                final_args.append(arg)
                if arg == "-list":
                    final_args.append(str(temp_file))

            # 3. Execute
            return await self.run(
                tool=tool,
                args=final_args,
                parse_json=parse_json,
                timeout=timeout,
                target=target,
            )
        finally:
            # 4. Clean up temp file
            if temp_file is not None:
                try:
                    temp_file.unlink(missing_ok=True)
                except OSError:
                    pass
