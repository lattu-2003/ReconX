"""Async SQLAlchemy engine and session management for ReconX.

Provides factory functions for creating async engines and session makers,
plus a DatabaseManager class that bundles engine lifecycle management
with a convenient async context-manager for obtaining sessions.
"""

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from .models import Base


def get_engine(db_url: str) -> AsyncEngine:
    """Create an async SQLAlchemy engine.

    Args:
        db_url: Database connection URL (e.g. 'sqlite+aiosqlite:///reconx.db').

    Returns:
        Configured AsyncEngine instance.
    """
    return create_async_engine(db_url, echo=False)


def get_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    """Create a session factory bound to the given engine.

    Sessions produced by this factory will have ``expire_on_commit=False``
    so that attributes remain accessible after commit without requiring
    a refresh.

    Args:
        engine: The async engine to bind sessions to.

    Returns:
        An async_sessionmaker configured for the engine.
    """
    return async_sessionmaker(engine, expire_on_commit=False)


async def init_db(db_url: str) -> None:
    """Initialize the database by creating all tables.

    Connects to the database at *db_url*, runs
    ``Base.metadata.create_all`` synchronously inside the async connection,
    then disposes of the engine.

    Args:
        db_url: Database connection URL.
    """
    engine = create_async_engine(db_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


class DatabaseManager:
    """Manages the async database engine and session lifecycle.

    Accepts a database URL at construction time and lazily creates the
    engine and session factory when :meth:`initialize` is called.

    Usage::

        db = DatabaseManager("sqlite+aiosqlite:///reconx.db")
        await db.initialize()

        async with db.get_session() as session:
            result = await session.execute(select(Scan))

        await db.close()
    """

    def __init__(self, db_url: str) -> None:
        """Initialise with a database URL.

        The engine is **not** created until :meth:`initialize` is called.

        Args:
            db_url: Database connection URL.
        """
        self._db_url = db_url
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

    async def initialize(self) -> None:
        """Create the engine, session factory, and ensure all tables exist.

        This must be called before any sessions are requested.
        """
        self._engine = get_engine(self._db_url)
        self._session_factory = get_session_factory(self._engine)

        # Create tables if they don't already exist
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    @property
    def session_factory(self) -> async_sessionmaker[AsyncSession]:
        """Return the session factory for direct use by repositories.

        Raises:
            RuntimeError: If :meth:`initialize` has not been called yet.
        """
        if self._session_factory is None:
            raise RuntimeError(
                "DatabaseManager has not been initialized. "
                "Call 'await db.initialize()' first."
            )
        return self._session_factory

    @asynccontextmanager
    async def get_session(self) -> AsyncIterator[AsyncSession]:
        """Yield an async session, committing on success or rolling back on error.

        Raises:
            RuntimeError: If :meth:`initialize` has not been called yet.

        Yields:
            An ``AsyncSession`` ready for use.
        """
        if self._session_factory is None:
            raise RuntimeError(
                "DatabaseManager has not been initialized. "
                "Call 'await db.initialize()' first."
            )

        async with self._session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    async def close(self) -> None:
        """Dispose of the engine and release all connection resources."""
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._session_factory = None
