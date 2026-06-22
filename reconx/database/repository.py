"""Data access layer for ReconX.

Provides :class:`ReconRepository`, the single entry-point for all
database reads and writes.  Every method uses the SQLAlchemy 2.0
``select()`` / ``execute()`` API — **no** legacy ``session.query()`` calls.
"""

import json
from datetime import datetime
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .models import (
    AssetProfile,
    ChangeEvent,
    EndpointClassification,
    Finding,
    HistoricalURL,
    Host,
    JSFile,
    JSFinding,
    Port,
    Scan,
    Scope,
    Subdomain,
    URL,
)


class ReconRepository:
    """Async data-access layer for all ReconX entities.

    Wraps an ``async_sessionmaker`` and exposes high-level CRUD
    operations for every model defined in :mod:`.models`.

    Args:
        session_factory: An ``async_sessionmaker[AsyncSession]`` that
            produces database sessions.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    async def create_scan(self, target: str, scan_type: str) -> Scan:
        """Create and persist a new scan record.

        Args:
            target: The target domain or host.
            scan_type: Scan category (e.g. ``'full'``, ``'subdomain'``).

        Returns:
            The newly created :class:`Scan` instance with its generated id.
        """
        scan = Scan(target=target, scan_type=scan_type)
        async with self._session_factory() as session:
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            return scan

    async def update_scan_status(
        self,
        scan_id: int,
        status: str,
        finished_at: Optional[datetime] = None,
    ) -> None:
        """Update the status (and optionally finish time) of a scan.

        Args:
            scan_id: Primary key of the scan to update.
            status: New status value (e.g. ``'running'``, ``'completed'``).
            finished_at: Optional completion timestamp.
        """
        async with self._session_factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is not None:
                scan.status = status
                if finished_at is not None:
                    scan.finished_at = finished_at
                await session.commit()

    async def get_latest_scan(self, target: str) -> Scan | None:
        """Return the most recent scan for a given target.

        Args:
            target: The target domain or host.

        Returns:
            The latest :class:`Scan` or ``None`` if no scans exist.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scan)
                .where(Scan.target == target)
                .order_by(Scan.started_at.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()

    async def get_previous_scan(
        self, target: str, before_scan_id: int
    ) -> Scan | None:
        """Return the scan immediately preceding *before_scan_id* for a target.

        Useful for diffing consecutive scan results.

        Args:
            target: The target domain or host.
            before_scan_id: The scan id whose predecessor is requested.

        Returns:
            The previous :class:`Scan` or ``None``.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scan)
                .where(Scan.target == target, Scan.id < before_scan_id)
                .order_by(Scan.id.desc())
                .limit(1)
            )
            return result.scalar_one_or_none()

    # ------------------------------------------------------------------
    # Subdomains
    # ------------------------------------------------------------------

    async def add_subdomains(
        self, scan_id: int, subdomains: list[dict]
    ) -> None:
        """Bulk-insert subdomain records.

        Args:
            scan_id: The owning scan's id.
            subdomains: List of dicts with keys matching
                :class:`Subdomain` columns (excluding ``id`` and ``scan_id``).
        """
        async with self._session_factory() as session:
            objects = [Subdomain(scan_id=scan_id, **sd) for sd in subdomains]
            session.add_all(objects)
            await session.commit()

    async def get_subdomains(self, scan_id: int) -> list[Subdomain]:
        """Return all subdomains discovered in a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`Subdomain` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Subdomain).where(Subdomain.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Ports
    # ------------------------------------------------------------------

    async def add_ports(self, scan_id: int, ports: list[dict]) -> None:
        """Bulk-insert port records.

        Args:
            scan_id: The owning scan's id.
            ports: List of dicts with keys matching :class:`Port` columns.
        """
        async with self._session_factory() as session:
            objects = [Port(scan_id=scan_id, **p) for p in ports]
            session.add_all(objects)
            await session.commit()

    async def get_ports(self, scan_id: int) -> list[Port]:
        """Return all ports discovered in a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`Port` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Port).where(Port.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Hosts
    # ------------------------------------------------------------------

    async def add_hosts(self, scan_id: int, hosts: list[dict]) -> None:
        """Bulk-insert host records.

        Args:
            scan_id: The owning scan's id.
            hosts: List of dicts with keys matching :class:`Host` columns.
        """
        async with self._session_factory() as session:
            objects = [Host(scan_id=scan_id, **h) for h in hosts]
            session.add_all(objects)
            await session.commit()

    async def get_hosts(self, scan_id: int) -> list[Host]:
        """Return all hosts discovered in a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`Host` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Host).where(Host.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # URLs
    # ------------------------------------------------------------------

    async def add_urls(self, scan_id: int, urls: list[dict]) -> None:
        """Bulk-insert URL records.

        Args:
            scan_id: The owning scan's id.
            urls: List of dicts with keys matching :class:`URL` columns.
        """
        async with self._session_factory() as session:
            objects = [URL(scan_id=scan_id, **u) for u in urls]
            session.add_all(objects)
            await session.commit()

    async def get_urls(self, scan_id: int) -> list[URL]:
        """Return all URLs discovered in a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`URL` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(URL).where(URL.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Historical URLs
    # ------------------------------------------------------------------

    async def add_historical_urls(
        self, scan_id: int, urls: list[dict]
    ) -> None:
        """Bulk-insert historical URL records.

        Args:
            scan_id: The owning scan's id.
            urls: List of dicts with keys matching :class:`HistoricalURL` columns.
        """
        async with self._session_factory() as session:
            objects = [HistoricalURL(scan_id=scan_id, **u) for u in urls]
            session.add_all(objects)
            await session.commit()

    # ------------------------------------------------------------------
    # JS Files
    # ------------------------------------------------------------------

    async def add_js_files(self, scan_id: int, files: list[dict]) -> None:
        """Bulk-insert JavaScript file records.

        Args:
            scan_id: The owning scan's id.
            files: List of dicts with keys matching :class:`JSFile` columns.
        """
        async with self._session_factory() as session:
            objects = [JSFile(scan_id=scan_id, **f) for f in files]
            session.add_all(objects)
            await session.commit()

    # ------------------------------------------------------------------
    # JS Findings
    # ------------------------------------------------------------------

    async def add_js_findings(
        self, scan_id: int, findings: list[dict]
    ) -> None:
        """Bulk-insert JS analysis findings.

        Args:
            scan_id: The owning scan's id.
            findings: List of dicts with keys matching :class:`JSFinding` columns.
        """
        async with self._session_factory() as session:
            objects = [JSFinding(scan_id=scan_id, **f) for f in findings]
            session.add_all(objects)
            await session.commit()

    async def get_js_findings(self, scan_id: int) -> list[JSFinding]:
        """Return all JS findings for a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`JSFinding` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(JSFinding).where(JSFinding.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Endpoint Classifications
    # ------------------------------------------------------------------

    async def add_classifications(
        self, scan_id: int, classifications: list[dict]
    ) -> None:
        """Bulk-insert endpoint classification records.

        Args:
            scan_id: The owning scan's id.
            classifications: List of dicts with keys matching
                :class:`EndpointClassification` columns.
        """
        async with self._session_factory() as session:
            objects = [
                EndpointClassification(scan_id=scan_id, **c)
                for c in classifications
            ]
            session.add_all(objects)
            await session.commit()

    async def get_classifications(
        self, scan_id: int
    ) -> list[EndpointClassification]:
        """Return all endpoint classifications for a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`EndpointClassification` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(EndpointClassification).where(
                    EndpointClassification.scan_id == scan_id
                )
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Asset Profiles
    # ------------------------------------------------------------------

    async def add_asset_profiles(
        self, scan_id: int, profiles: list[dict]
    ) -> None:
        """Bulk-insert asset profile records.

        Args:
            scan_id: The owning scan's id.
            profiles: List of dicts with keys matching
                :class:`AssetProfile` columns.
        """
        async with self._session_factory() as session:
            objects = [AssetProfile(scan_id=scan_id, **p) for p in profiles]
            session.add_all(objects)
            await session.commit()

    async def update_risk_scores(
        self,
        scan_id: int,
        scores: dict[str, tuple[int, list[str]]],
    ) -> None:
        """Update risk scores and reasons for asset profiles by host.

        Args:
            scan_id: The owning scan's id.
            scores: Mapping of ``host -> (risk_score, [reason, ...])``.
        """
        async with self._session_factory() as session:
            for host, (score, reasons) in scores.items():
                result = await session.execute(
                    select(AssetProfile).where(
                        AssetProfile.scan_id == scan_id,
                        AssetProfile.host == host,
                    )
                )
                profile = result.scalar_one_or_none()
                if profile is not None:
                    profile.risk_score = score
                    profile.reasons = json.dumps(reasons)
            await session.commit()

    async def get_asset_profiles(self, scan_id: int) -> list[AssetProfile]:
        """Return all asset profiles for a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`AssetProfile` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(AssetProfile).where(AssetProfile.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    async def add_findings(
        self, scan_id: int, findings: list[dict]
    ) -> None:
        """Bulk-insert vulnerability/security findings.

        Args:
            scan_id: The owning scan's id.
            findings: List of dicts with keys matching :class:`Finding` columns.
        """
        async with self._session_factory() as session:
            objects = [Finding(scan_id=scan_id, **f) for f in findings]
            session.add_all(objects)
            await session.commit()

    async def get_findings(self, scan_id: int) -> list[Finding]:
        """Return all findings for a scan.

        Args:
            scan_id: The scan to query.

        Returns:
            List of :class:`Finding` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Finding).where(Finding.scan_id == scan_id)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Change Events
    # ------------------------------------------------------------------

    async def add_change_events(self, events: list[dict]) -> None:
        """Bulk-insert change detection events.

        Args:
            events: List of dicts with keys matching
                :class:`ChangeEvent` columns.
        """
        async with self._session_factory() as session:
            objects = [ChangeEvent(**e) for e in events]
            session.add_all(objects)
            await session.commit()

    async def get_change_events(self, target: str) -> list[ChangeEvent]:
        """Return all change events for a target.

        Args:
            target: The target domain or host.

        Returns:
            List of :class:`ChangeEvent` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(ChangeEvent).where(ChangeEvent.target == target)
            )
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Scope
    # ------------------------------------------------------------------

    async def add_scope(self, target: str, scope_type: str) -> None:
        """Add a scope inclusion or exclusion rule.

        Args:
            target: The target domain/host/IP pattern.
            scope_type: Either ``'include'`` or ``'exclude'``.
        """
        async with self._session_factory() as session:
            scope = Scope(target=target, scope_type=scope_type)
            session.add(scope)
            await session.commit()

    async def remove_scope(self, target: str) -> None:
        """Remove all scope rules matching a target.

        Args:
            target: The target whose scope rules should be deleted.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Scope).where(Scope.target == target)
            )
            for scope in result.scalars().all():
                await session.delete(scope)
            await session.commit()

    async def get_scope(self) -> list[Scope]:
        """Return all scope rules.

        Returns:
            List of :class:`Scope` instances.
        """
        async with self._session_factory() as session:
            result = await session.execute(select(Scope))
            return list(result.scalars().all())

    # ------------------------------------------------------------------
    # Aggregation / Summaries
    # ------------------------------------------------------------------

    async def get_scan_summary(self, scan_id: int) -> dict:
        """Return counts of every entity type associated with a scan.

        Args:
            scan_id: The scan to summarise.

        Returns:
            Dict mapping entity names to their row counts, e.g.
            ``{"subdomains": 42, "ports": 17, ...}``.
        """
        entity_map: dict[str, type] = {
            "subdomains": Subdomain,
            "ports": Port,
            "hosts": Host,
            "urls": URL,
            "historical_urls": HistoricalURL,
            "js_files": JSFile,
            "js_findings": JSFinding,
            "endpoint_classifications": EndpointClassification,
            "asset_profiles": AssetProfile,
            "findings": Finding,
        }

        summary: dict[str, int] = {}
        async with self._session_factory() as session:
            for name, model in entity_map.items():
                result = await session.execute(
                    select(func.count(model.id)).where(
                        model.scan_id == scan_id
                    )
                )
                summary[name] = result.scalar_one()
        return summary

    async def get_findings_by_severity(
        self, scan_id: int
    ) -> dict[str, int]:
        """Return finding counts grouped by severity level.

        Args:
            scan_id: The scan to query.

        Returns:
            Dict mapping severity strings to counts, e.g.
            ``{"critical": 2, "high": 5, "medium": 12}``.
        """
        async with self._session_factory() as session:
            result = await session.execute(
                select(Finding.severity, func.count(Finding.id))
                .where(Finding.scan_id == scan_id)
                .group_by(Finding.severity)
            )
            return dict(result.all())
