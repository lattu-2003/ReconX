"""
ReconX Smoke Tests

Validates that the package installs correctly, all imports resolve,
the CLI entry point starts, and core components initialize without errors.

These tests should pass on any supported platform (Kali, Parrot, Ubuntu)
with Python 3.12+ inside a virtual environment.

Run with:
    python -m pytest tests/ -v
"""

import subprocess
import sys


class TestPackageImports:
    """Error 7: Verify all key modules import without errors."""

    def test_import_reconx(self):
        """Root package imports successfully."""
        import reconx
        assert hasattr(reconx, "__version__")

    def test_import_config(self):
        """Config module with Pydantic settings imports."""
        from reconx.config import ReconXConfig, ScanProfile, PROFILE_MODULES
        assert ScanProfile.QUICK is not None
        assert ScanProfile.STANDARD is not None
        assert ScanProfile.DEEP is not None

    def test_import_database_models(self):
        """All 13 ORM models import and have __tablename__."""
        from reconx.database.models import (
            Base, Scan, Scope, Subdomain, Port, Host, URL,
            HistoricalURL, JSFile, JSFinding, EndpointClassification,
            AssetProfile, Finding, ChangeEvent,
        )
        assert len(Base.metadata.tables) == 13

    def test_import_database_engine(self):
        """Database engine and manager import."""
        from reconx.database.engine import (
            DatabaseManager, get_engine, get_session_factory, init_db,
        )
        assert DatabaseManager is not None

    def test_import_database_repository(self):
        """Repository data access layer imports."""
        from reconx.database.repository import ReconRepository
        assert ReconRepository is not None

    def test_import_security(self):
        """Security module imports with all classes."""
        from reconx.core.security import (
            SecurityError, InputValidator, FileSecurityManager,
            SecretsManager, AuditLogger,
        )
        assert InputValidator is not None
        assert SecretsManager.SENSITIVE_TYPES is not None

    def test_import_runner(self):
        """Tool runner imports with allowlist."""
        from reconx.core.runner import ToolRunner, ToolNotFoundError
        assert "subfinder" in ToolRunner.ALLOWED_TOOLS
        assert "nuclei" in ToolRunner.ALLOWED_TOOLS

    def test_import_scope(self):
        """Scope manager imports."""
        from reconx.core.scope import ScopeManager
        assert ScopeManager is not None

    def test_import_all_modules(self):
        """All 12 scanning modules import."""
        from reconx.modules.discovery import DiscoveryModule
        from reconx.modules.ports import PortsModule
        from reconx.modules.validation import ValidationModule
        from reconx.modules.screenshots import ScreenshotsModule
        from reconx.modules.crawling import CrawlingModule
        from reconx.modules.historical import HistoricalModule
        from reconx.modules.javascript import JavaScriptModule
        from reconx.modules.classification import ClassificationModule
        from reconx.modules.intelligence import IntelligenceModule
        from reconx.modules.scoring import ScoringModule
        from reconx.modules.vulnerability import VulnerabilityModule
        from reconx.modules.changes import ChangesModule
        assert DiscoveryModule is not None
        assert ChangesModule is not None

    def test_import_reporting(self):
        """Report and dashboard generators import."""
        from reconx.reporting.generator import ReportGenerator
        from reconx.reporting.dashboard import DashboardGenerator
        assert ReportGenerator is not None
        assert DashboardGenerator is not None

    def test_import_engine(self):
        """Scan orchestrator imports."""
        from reconx.engine import ScanEngine
        assert ScanEngine is not None

    def test_import_cli(self):
        """CLI app imports."""
        from reconx.cli import app
        assert app is not None


class TestCLIStartup:
    """Error 4 & 6: Verify CLI entry point starts and responds."""

    def test_reconx_help(self):
        """reconx --help exits 0 and shows usage text."""
        result = subprocess.run(
            [sys.executable, "-m", "reconx.cli", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert "reconx" in result.stdout.lower() or "attack" in result.stdout.lower()

    def test_reconx_version(self):
        """reconx --version shows version string."""
        result = subprocess.run(
            [sys.executable, "-m", "reconx.cli", "--version"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Version check failed: {result.stderr}"


class TestCoreComponents:
    """Error 7: Verify core components work as an integrated stack."""

    def test_config_defaults(self):
        """ReconXConfig creates with valid defaults."""
        from reconx.config import ReconXConfig
        config = ReconXConfig()
        assert config.threads > 0
        assert config.rate_limit > 0
        assert config.timeout > 0

    def test_profile_modules(self):
        """Each scan profile has the expected module set."""
        from reconx.config import ScanProfile, PROFILE_MODULES
        quick = PROFILE_MODULES[ScanProfile.QUICK]
        standard = PROFILE_MODULES[ScanProfile.STANDARD]
        deep = PROFILE_MODULES[ScanProfile.DEEP]

        assert "discovery" in quick
        assert "validation" in quick
        assert len(standard) > len(quick)
        assert len(deep) >= len(standard)

    def test_input_validator_domain(self):
        """InputValidator accepts valid domains."""
        from reconx.core.security import InputValidator
        assert InputValidator.validate_domain("example.com") == "example.com"
        assert InputValidator.validate_domain("sub.example.com") == "sub.example.com"

    def test_input_validator_rejects_injection(self):
        """InputValidator rejects shell injection attempts."""
        from reconx.core.security import InputValidator, SecurityError
        import pytest
        with pytest.raises(SecurityError):
            InputValidator.validate_domain("example.com; rm -rf /")

    def test_input_validator_port(self):
        """InputValidator accepts valid ports, rejects invalid."""
        from reconx.core.security import InputValidator, SecurityError
        import pytest
        assert InputValidator.validate_port(443) == 443
        assert InputValidator.validate_port(8080) == 8080
        with pytest.raises(SecurityError):
            InputValidator.validate_port(0)
        with pytest.raises(SecurityError):
            InputValidator.validate_port(70000)

    def test_secrets_masking(self):
        """SecretsManager correctly masks sensitive values."""
        from reconx.core.security import SecretsManager
        masked = SecretsManager.mask_secret("super_secret_key_12345", visible_chars=4)
        assert masked.startswith("supe")
        assert "****" in masked
        assert masked != "super_secret_key_12345"

    def test_secrets_redaction(self):
        """SecretsManager redacts sensitive finding types."""
        from reconx.core.security import SecretsManager
        assert SecretsManager.should_redact("api_key") is True
        assert SecretsManager.should_redact("token") is True
        assert SecretsManager.should_redact("api_endpoint") is False

    def test_tool_runner_allowlist(self):
        """ToolRunner rejects tools not in the allowlist."""
        from reconx.core.runner import ToolRunner, ToolNotFoundError
        import pytest
        runner = ToolRunner()
        with pytest.raises((ToolNotFoundError, Exception)):
            runner._resolve_tool("curl")
        with pytest.raises((ToolNotFoundError, Exception)):
            runner._resolve_tool("bash")

    def test_sqlalchemy_models_metadata(self):
        """All 13 tables are registered in SQLAlchemy metadata."""
        from reconx.database.models import Base
        table_names = set(Base.metadata.tables.keys())
        expected = {
            "scans", "scope", "subdomains", "ports", "hosts",
            "urls", "historical_urls", "js_files", "js_findings",
            "endpoint_classifications", "asset_profiles", "findings",
            "change_events",
        }
        assert expected == table_names

    def test_classification_patterns(self):
        """Classification module categorizes URLs correctly."""
        from reconx.modules.classification import ClassificationModule
        module = ClassificationModule.__new__(ClassificationModule)
        cats = module._classify_url("https://example.com/admin/dashboard")
        assert "admin" in cats

    def test_scoring_weights_exist(self):
        """Scoring module has keyword and technology weights."""
        from reconx.modules.scoring import KEYWORD_SCORES, TECHNOLOGY_SCORES
        assert len(KEYWORD_SCORES) > 10
        assert len(TECHNOLOGY_SCORES) > 10
        assert "admin" in KEYWORD_SCORES
        assert "jenkins" in TECHNOLOGY_SCORES
