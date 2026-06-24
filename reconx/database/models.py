"""SQLAlchemy 2.0 ORM models for the ReconX database.

Defines all tables used by the Attack Surface Intelligence Framework,
including scans, scope rules, discovered assets, findings, and change events.
Uses DeclarativeBase with Mapped[] type annotations per SQLAlchemy 2.0 conventions.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base class for all ReconX ORM models."""

    pass


class Scan(Base):
    """Represents a reconnaissance scan execution.

    Tracks the lifecycle of a scan from creation through completion,
    including its target, type, and timing information.
    """

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(512))
    scan_type: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), default="pending")
    started_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
    finished_at: Mapped[Optional[datetime]] = mapped_column(default=None)


class Scope(Base):
    """Defines an inclusion or exclusion rule for scan targeting.

    Scope rules determine which targets are in-scope (should be scanned)
    or out-of-scope (should be excluded).
    """

    __tablename__ = "scope"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(512))
    scope_type: Mapped[str] = mapped_column(String(16))  # 'include' or 'exclude'
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class Subdomain(Base):
    """A subdomain discovered during enumeration.

    Links back to the scan that discovered it and records the discovery source
    (e.g., 'subfinder', 'amass', 'crt.sh').
    """

    __tablename__ = "subdomains"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    root_domain: Mapped[str] = mapped_column(String(512))
    subdomain: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class Port(Base):
    """An open port discovered during port scanning.

    Records the host, port number, and optionally identified service name.
    """

    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    host: Mapped[str] = mapped_column(String(512))
    port: Mapped[int] = mapped_column()
    service: Mapped[Optional[str]] = mapped_column(String(128), default=None)
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class Host(Base):
    """A live host discovered during HTTP probing.

    Contains detailed information including HTTP response data,
    detected technologies, IP/ASN info, and optional screenshot path.
    """

    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    url: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[Optional[int]] = mapped_column(default=None)
    title: Mapped[Optional[str]] = mapped_column(String(1024), default=None)
    technologies: Mapped[Optional[str]] = mapped_column(Text, default=None)  # JSON
    ip: Mapped[Optional[str]] = mapped_column(String(45), default=None)
    asn: Mapped[Optional[str]] = mapped_column(String(64), default=None)
    screenshot_path: Mapped[Optional[str]] = mapped_column(
        String(1024), default=None
    )
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class URL(Base):
    """A URL discovered through crawling or fuzzing.

    Associates a discovered URL with the host it belongs to and the
    discovery source tool.
    """

    __tablename__ = "urls"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    host: Mapped[str] = mapped_column(String(512))
    url: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class HistoricalURL(Base):
    """A URL discovered from historical/archived sources.

    Captures URLs found via Wayback Machine, CommonCrawl, or similar
    historical data sources.
    """

    __tablename__ = "historical_urls"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    url: Mapped[str] = mapped_column(String(2048))
    source: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class JSFile(Base):
    """A JavaScript file discovered on a target host.

    Used as input for JS analysis to extract endpoints, secrets, and
    other findings from client-side code.
    """

    __tablename__ = "js_files"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    url: Mapped[str] = mapped_column(String(2048))
    host: Mapped[str] = mapped_column(String(512))
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class JSFinding(Base):
    """A finding extracted from JavaScript analysis.

    Categorizes findings by type (e.g., 'api_key', 'endpoint', 'secret')
    and records the value and the JS source URL where it was found.
    """

    __tablename__ = "js_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    finding_type: Mapped[str] = mapped_column(String(128))
    value: Mapped[str] = mapped_column(Text)
    source_url: Mapped[str] = mapped_column(String(2048))
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class EndpointClassification(Base):
    """Classification of a discovered endpoint by category.

    Categories might include 'api', 'admin', 'login', 'upload', etc.
    Used by the asset profiling and prioritization pipeline.
    """

    __tablename__ = "endpoint_classifications"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    url: Mapped[str] = mapped_column(String(2048))
    category: Mapped[str] = mapped_column(String(128))
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class AssetProfile(Base):
    """Aggregated profile for a discovered asset/host.

    Combines technology detection, interesting paths, and computed
    risk scoring with explanatory reasons.
    """

    __tablename__ = "asset_profiles"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    host: Mapped[str] = mapped_column(String(512))
    technologies: Mapped[Optional[str]] = mapped_column(Text, default=None)  # JSON
    interesting_paths: Mapped[Optional[str]] = mapped_column(
        Text, default=None
    )  # JSON
    risk_score: Mapped[int] = mapped_column(default=0)
    reasons: Mapped[Optional[str]] = mapped_column(Text, default=None)  # JSON
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class Finding(Base):
    """A vulnerability or security finding from scanning tools.

    Records findings from tools like Nuclei, with severity levels,
    template identifiers, and affected hosts/URLs.
    """

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"))
    template: Mapped[str] = mapped_column(String(256))
    severity: Mapped[str] = mapped_column(String(32))
    host: Mapped[str] = mapped_column(String(512))
    url: Mapped[Optional[str]] = mapped_column(String(2048), default=None)
    description: Mapped[Optional[str]] = mapped_column(Text, default=None)
    timestamp: Mapped[datetime] = mapped_column(default=datetime.utcnow)


class ChangeEvent(Base):
    """Records a detected change in the attack surface.

    Used by the monitoring/diffing pipeline to track new subdomains,
    changed ports, new technologies, etc., over time.
    """

    __tablename__ = "change_events"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(512))
    event_type: Mapped[str] = mapped_column(String(128))
    detail: Mapped[str] = mapped_column(Text)
    detected_at: Mapped[datetime] = mapped_column(default=datetime.utcnow)
