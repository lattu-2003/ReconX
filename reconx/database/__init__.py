"""ReconX database package.

Public API:
    - :class:`Base` — SQLAlchemy declarative base for all models.
    - :class:`DatabaseManager` — async engine / session lifecycle manager.
    - :class:`ReconRepository` — data-access layer for all entity types.
    - :func:`init_db` — one-shot helper to create all tables.
"""

from .engine import DatabaseManager, get_engine, get_session_factory, init_db
from .models import (
    AssetProfile,
    Base,
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
from .repository import ReconRepository

__all__ = [
    # Engine / session
    "Base",
    "DatabaseManager",
    "get_engine",
    "get_session_factory",
    "init_db",
    # Repository
    "ReconRepository",
    # Models
    "AssetProfile",
    "ChangeEvent",
    "EndpointClassification",
    "Finding",
    "HistoricalURL",
    "Host",
    "JSFile",
    "JSFinding",
    "Port",
    "Scan",
    "Scope",
    "Subdomain",
    "URL",
]
