"""Alembic : s'exécute avec le rôle PROPRIÉTAIRE (lasthop_owner), jamais le rôle applicatif."""

import asyncio
import os
from pathlib import Path
from urllib.parse import quote

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base

target_metadata = Base.metadata


def _url() -> str:
    pw_file = os.environ.get("LASTHOP_DB_OWNER_PASSWORD_FILE")
    pw = Path(pw_file).read_text().strip() if pw_file else os.environ.get("LASTHOP_DB_OWNER_PASSWORD", "")
    user = os.environ.get("LASTHOP_DB_OWNER_USER", "lasthop_owner")
    host = os.environ.get("LASTHOP_DB_HOST", "postgres")
    port = os.environ.get("LASTHOP_DB_PORT", "5432")
    name = os.environ.get("LASTHOP_DB_NAME", "lasthop")
    return f"postgresql+asyncpg://{user}:{quote(pw, safe='')}@{host}:{port}/{name}"


def _do_run(connection) -> None:  # type: ignore[no-untyped-def]
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def _run() -> None:
    engine = create_async_engine(_url())
    async with engine.connect() as conn:
        await conn.run_sync(_do_run)
    await engine.dispose()


asyncio.run(_run())
