"""
ReconX Security Module

Centralized security primitives for input validation, file permissions,
secrets management, and tamper-evident audit logging.

All user-supplied inputs (domains, ports, paths, URLs, CLI arguments)
MUST pass through InputValidator before use. Subprocess arguments are
validated to reject shell meta-characters, preventing injection attacks.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


# ── Exceptions ────────────────────────────────────────────────────────────


class SecurityError(Exception):
    """Raised when a security violation is detected."""

    pass


# ── Input Validation ──────────────────────────────────────────────────────


class InputValidator:
    """Validates and sanitizes all external inputs before they reach tools.

    Every domain, port, path, URL, and CLI argument flows through this
    class to ensure no shell injection, path traversal, or malformed
    data reaches subprocess calls.
    """

    ALLOWED_DOMAIN_PATTERN: re.Pattern[str] = re.compile(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$"
    )
    ALLOWED_PORT_RANGE: range = range(1, 65536)
    SHELL_DANGEROUS_CHARS: frozenset[str] = frozenset(
        ';&|`$(){}[]!#~\\\n\r'
    )

    @staticmethod
    def validate_domain(domain: str) -> str:
        """Validate and clean a domain name.

        Strips whitespace, converts to lowercase, checks against the
        allowed domain pattern, and rejects any shell meta-characters.

        Args:
            domain: Raw domain string from user input.

        Returns:
            Cleaned, validated domain string.

        Raises:
            SecurityError: If the domain is empty, too long, contains
                dangerous characters, or does not match the allowed pattern.
        """
        cleaned = domain.strip().lower()
        if not cleaned:
            raise SecurityError("Domain cannot be empty")
        if len(cleaned) > 255:
            raise SecurityError(
                f"Domain exceeds maximum length of 255: {cleaned!r}"
            )
        # Check for shell-dangerous characters
        dangerous_found = InputValidator.SHELL_DANGEROUS_CHARS.intersection(cleaned)
        if dangerous_found:
            raise SecurityError(
                f"Domain contains dangerous characters: {dangerous_found}"
            )
        if not InputValidator.ALLOWED_DOMAIN_PATTERN.match(cleaned):
            raise SecurityError(
                f"Domain does not match allowed pattern: {cleaned!r}"
            )
        return cleaned

    @staticmethod
    def validate_port(port: int) -> int:
        """Validate a network port number.

        Args:
            port: Port number to validate.

        Returns:
            The validated port number.

        Raises:
            SecurityError: If the port is outside the range 1-65535.
        """
        if not isinstance(port, int):
            raise SecurityError(f"Port must be an integer, got {type(port).__name__}")
        if port not in InputValidator.ALLOWED_PORT_RANGE:
            raise SecurityError(
                f"Port {port} is outside the allowed range (1-65535)"
            )
        return port

    @staticmethod
    def sanitize_path(path: str, base_dir: Path) -> Path:
        """Resolve and validate a path against a base directory.

        Prevents path traversal attacks by ensuring the resolved path
        is a child of ``base_dir``.

        Args:
            path: Raw path string from user input.
            base_dir: The trusted base directory; the result must live
                inside this directory.

        Returns:
            The resolved, validated :class:`~pathlib.Path`.

        Raises:
            SecurityError: If the resolved path escapes ``base_dir``.
        """
        resolved = Path(path).resolve()
        base_resolved = base_dir.resolve()
        if not resolved.is_relative_to(base_resolved):
            raise SecurityError(
                f"Path traversal detected: {path!r} escapes base directory "
                f"{base_resolved}"
            )
        return resolved

    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and clean a URL.

        Only ``http`` and ``https`` schemes are permitted. The network
        location component is checked for shell meta-characters.

        Args:
            url: Raw URL string.

        Returns:
            The cleaned URL string.

        Raises:
            SecurityError: If the scheme is not http/https or the netloc
                contains dangerous characters.
        """
        cleaned = url.strip()
        if not cleaned:
            raise SecurityError("URL cannot be empty")
        parsed = urlparse(cleaned)
        if parsed.scheme not in ("http", "https"):
            raise SecurityError(
                f"URL scheme must be http or https, got {parsed.scheme!r}"
            )
        if not parsed.netloc:
            raise SecurityError(f"URL has no network location: {cleaned!r}")
        dangerous_found = InputValidator.SHELL_DANGEROUS_CHARS.intersection(
            parsed.netloc
        )
        if dangerous_found:
            raise SecurityError(
                f"URL netloc contains dangerous characters: {dangerous_found}"
            )
        return cleaned

    @staticmethod
    def validate_argument(arg: str) -> str:
        """Validate a single CLI argument for shell meta-characters.

        All arguments passed to subprocess calls must go through this
        method to prevent injection.

        Args:
            arg: Raw CLI argument string.

        Returns:
            The validated argument string.

        Raises:
            SecurityError: If the argument contains shell-dangerous characters.
        """
        dangerous_found = InputValidator.SHELL_DANGEROUS_CHARS.intersection(arg)
        if dangerous_found:
            raise SecurityError(
                f"Argument contains dangerous characters {dangerous_found}: {arg!r}"
            )
        return arg


# ── File Security ─────────────────────────────────────────────────────────


class FileSecurityManager:
    """Manages file and directory permissions and secure temporary files.

    On POSIX systems, directories default to 0o700 and files to 0o600.
    On Windows, permission calls are silently skipped since NTFS uses a
    different ACL model.
    """

    @staticmethod
    def secure_directory(path: Path, mode: int = 0o700) -> None:
        """Create a directory with secure permissions.

        Creates parent directories as needed. On POSIX, sets the
        directory mode to ``mode`` (default: owner-only rwx).

        Args:
            path: Directory path to create.
            mode: POSIX permission bits (ignored on Windows).
        """
        path.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            os.chmod(path, mode)

    @staticmethod
    def secure_file(path: Path, mode: int = 0o600) -> None:
        """Set secure permissions on an existing file.

        On POSIX, sets the file mode to ``mode`` (default: owner-only rw).
        On Windows, this is a no-op.

        Args:
            path: File path whose permissions should be tightened.
            mode: POSIX permission bits (ignored on Windows).
        """
        if os.name == "posix":
            os.chmod(path, mode)

    @staticmethod
    def validate_output_path(path: Path, base_dir: Path) -> Path:
        """Validate an output path against a base directory.

        Prevents writing files outside of the sanctioned output tree.

        Args:
            path: Proposed output path.
            base_dir: Trusted base directory.

        Returns:
            The resolved output path.

        Raises:
            SecurityError: If the resolved path escapes ``base_dir``.
        """
        resolved = path.resolve()
        base_resolved = base_dir.resolve()
        if not resolved.is_relative_to(base_resolved):
            raise SecurityError(
                f"Output path traversal detected: {path} escapes {base_resolved}"
            )
        return resolved

    @staticmethod
    def secure_temp_file(directory: Path, prefix: str = "reconx_") -> Path:
        """Create a secure temporary file.

        Uses :func:`tempfile.mkstemp` to atomically create a file that is
        not vulnerable to symlink races.

        Args:
            directory: Directory in which to create the temp file.
            prefix: Filename prefix for identification and cleanup.

        Returns:
            Path to the newly created temporary file.
        """
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=prefix, dir=str(directory))
        os.close(fd)
        result = Path(tmp_path)
        FileSecurityManager.secure_file(result)
        return result

    @staticmethod
    def cleanup_temp_files(directory: Path, prefix: str = "reconx_") -> None:
        """Remove all temporary files with the given prefix.

        Silently ignores files that have already been deleted.

        Args:
            directory: Directory to scan.
            prefix: Only files whose name starts with ``prefix`` are removed.
        """
        if not directory.exists():
            return
        for entry in directory.iterdir():
            if entry.is_file() and entry.name.startswith(prefix):
                try:
                    entry.unlink()
                except OSError:
                    pass  # Best-effort cleanup


# ── Secrets Management ────────────────────────────────────────────────────


class SecretsManager:
    """Handles masking and redaction of sensitive values in output.

    Any finding whose type matches a known sensitive category is
    automatically masked when displayed to prevent accidental credential
    leakage in logs, reports, and terminal output.
    """

    SENSITIVE_TYPES: frozenset[str] = frozenset(
        {
            "api_key",
            "token",
            "secret",
            "password",
            "aws_key",
            "firebase_url",
            "private_key",
        }
    )

    @staticmethod
    def mask_secret(value: str, visible_chars: int = 4) -> str:
        """Return a partially masked version of a secret value.

        The first ``visible_chars`` characters remain visible; the rest
        are replaced with asterisks.

        Args:
            value: The raw secret value.
            visible_chars: Number of leading characters to keep visible.

        Returns:
            Masked string, e.g. ``"sk_l****"``.
        """
        if len(value) <= visible_chars:
            return "*" * len(value)
        return value[:visible_chars] + "*" * (len(value) - visible_chars)

    @classmethod
    def should_redact(cls, finding_type: str) -> bool:
        """Check whether a finding type requires redaction.

        Args:
            finding_type: The category/type label of the finding.

        Returns:
            ``True`` if the type is in :attr:`SENSITIVE_TYPES`.
        """
        return finding_type.lower() in cls.SENSITIVE_TYPES

    @classmethod
    def redact_value(
        cls, value: str, finding_type: str, show_full: bool = False
    ) -> str:
        """Conditionally redact a value based on its finding type.

        Args:
            value: The raw value to potentially redact.
            finding_type: The category/type label of the finding.
            show_full: If ``True``, bypass redaction entirely.

        Returns:
            The original value, or a masked version if redaction applies.
        """
        if show_full:
            return value
        if cls.should_redact(finding_type):
            return cls.mask_secret(value)
        return value


# ── Audit Logging ─────────────────────────────────────────────────────────


class AuditLogger:
    """Tamper-evident, append-only audit log.

    Each entry is chained via SHA-256 hashes: the hash of entry *N*
    includes the hash of entry *N-1*, so any deletion or modification
    of earlier entries is detectable.

    The log file is written as newline-delimited JSON (JSONL).
    """

    def __init__(self, log_path: Path) -> None:
        """Initialise the audit logger.

        Args:
            log_path: File path for the append-only JSONL audit log.
        """
        self._log_path = log_path
        self._last_hash: str = "0" * 64

    # ── Internal ──────────────────────────────────────────────────────

    def _write_entry(self, entry: dict) -> None:
        """Compute a chained hash, timestamp, and append the entry.

        The hash covers the previous entry's hash concatenated with the
        JSON-serialised payload, ensuring tamper evidence.

        Args:
            entry: Dictionary payload to log.
        """
        entry["timestamp"] = datetime.now(timezone.utc).isoformat()
        entry["previous_hash"] = self._last_hash

        # Compute chained hash
        payload = json.dumps(entry, sort_keys=True)
        chain_input = self._last_hash + payload
        entry_hash = hashlib.sha256(chain_input.encode("utf-8")).hexdigest()
        entry["hash"] = entry_hash
        self._last_hash = entry_hash

        # Append to log file
        self._log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")

        # Secure the log file after writing
        FileSecurityManager.secure_file(self._log_path)

    # ── Public API ────────────────────────────────────────────────────

    def log_scan_start(self, target: str, profile: str) -> None:
        """Record the start of a scan.

        Args:
            target: The root target domain.
            profile: The scan profile name (quick/standard/deep).
        """
        self._write_entry(
            {
                "event": "scan_start",
                "target": target,
                "profile": profile,
            }
        )

    def log_tool_execution(
        self, tool: str, args_summary: str, target: str
    ) -> None:
        """Record a tool invocation.

        Args:
            tool: Tool binary name (e.g. ``subfinder``).
            args_summary: Human-readable summary of the arguments.
            target: The target being scanned.
        """
        self._write_entry(
            {
                "event": "tool_execution",
                "tool": tool,
                "args_summary": args_summary,
                "target": target,
            }
        )

    def log_scope_violation(self, domain: str, reason: str) -> None:
        """Record an out-of-scope access attempt.

        Args:
            domain: The domain that was rejected.
            reason: Why the domain was considered out of scope.
        """
        self._write_entry(
            {
                "event": "scope_violation",
                "domain": domain,
                "reason": reason,
            }
        )

    def log_scan_complete(self, scan_id: int, findings_count: int) -> None:
        """Record the completion of a scan.

        Args:
            scan_id: Database primary key of the completed scan.
            findings_count: Total number of findings produced.
        """
        self._write_entry(
            {
                "event": "scan_complete",
                "scan_id": scan_id,
                "findings_count": findings_count,
            }
        )

    def log_security_event(self, event_type: str, detail: str) -> None:
        """Record a generic security event.

        Args:
            event_type: Short label (e.g. ``"invalid_input"``).
            detail: Human-readable description of what happened.
        """
        self._write_entry(
            {
                "event": "security_event",
                "event_type": event_type,
                "detail": detail,
            }
        )
