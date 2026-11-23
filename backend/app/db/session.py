from __future__ import annotations

import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings

_engine: AsyncEngine | None = None
_maker: async_sessionmaker[AsyncSession] | None = None


def build_engine(settings: Settings) -> AsyncEngine:
    connect_args: dict[str, object] = {}
    if settings.db_ssl_ca_file:
        ctx = ssl.create_default_context(cafile=settings.db_ssl_ca_file)  # vérifie chaîne + nom d'hôte
        connect_args["ssl"] = ctx
    return create_async_engine(
        settings.database_url, pool_size=10, max_overflow=5, pool_pre_ping=True, connect_args=connect_args
    )


def init_db(settings: Settings) -> None:
    global _engine, _maker
    _engine = build_engine(settings)
    _maker = async_sessionmaker(_engine, expire_on_commit=False)


async def close_db() -> None:
    global _engine, _maker
    if _engine is not None:
        await _engine.dispose()
    _engine = _maker = None


async def get_session() -> AsyncIterator[AsyncSession]:
    if _maker is None:
        raise RuntimeError("DB non initialisée")
    async with _maker() as session:
        yield session


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Session indépendante du cycle de requête (flux SSE de longue durée)."""
    if _maker is None:
        raise RuntimeError("DB non initialisée")
    async with _maker() as session:
        yield session
