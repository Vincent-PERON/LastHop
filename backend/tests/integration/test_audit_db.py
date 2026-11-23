"""Immuabilité et intégrité de l'audit log, moindre privilège des rôles SQL."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app.db import session as dbsession
from app.security.audit import record, verify_chain

pytestmark = pytest.mark.usefixtures("app")


async def _insert(s, action: str) -> None:  # type: ignore[no-untyped-def]
    await record(s, None, action, actor_type="system", details={"n": 1, "password": "hunter2"})
    await s.commit()


async def test_chain_is_valid_and_secrets_never_stored() -> None:
    async for s in dbsession.get_session():
        for i in range(3):
            await _insert(s, f"test.chain{i}")
        assert await verify_chain(s) is None
        row = (
            await s.execute(text("SELECT details::text, prev_hash, row_hash FROM audit_log ORDER BY id DESC LIMIT 1"))
        ).one()
        assert "hunter2" not in row[0] and row[1] != row[2]


async def test_app_role_cannot_update_delete_truncate() -> None:
    async for s in dbsession.get_session():
        await _insert(s, "test.immutable")
        for stmt in ("UPDATE audit_log SET action='x'", "DELETE FROM audit_log", "TRUNCATE audit_log"):
            with pytest.raises((ProgrammingError, DBAPIError)):
                await s.execute(text(stmt))
            await s.rollback()


async def test_even_owner_is_blocked_by_triggers_and_tamper_is_detected(owner_engine) -> None:  # type: ignore[no-untyped-def]
    async for s in dbsession.get_session():
        await _insert(s, "test.tamper")
    async with owner_engine.connect() as c:
        with pytest.raises((ProgrammingError, DBAPIError)):
            await c.execute(text("UPDATE audit_log SET action='forged' WHERE id=(SELECT max(id) FROM audit_log)"))
        await c.rollback()
        # Un attaquant propriétaire qui désactive les triggers est détecté par la chaîne (transaction annulée ensuite).
        await c.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_no_mutation"))
        await c.execute(text("UPDATE audit_log SET action='forged' WHERE id=(SELECT max(id) FROM audit_log)"))
        broken = (await c.execute(text("SELECT audit_verify()"))).scalar_one()
        assert broken is not None
        await c.rollback()


async def test_app_role_has_no_ddl_or_superuser_rights() -> None:
    async for s in dbsession.get_session():
        with pytest.raises((ProgrammingError, DBAPIError)):
            await s.execute(text("CREATE TABLE evil(x int)"))
        await s.rollback()
        with pytest.raises((ProgrammingError, DBAPIError)):
            await s.execute(text("DROP TABLE users"))
        await s.rollback()
        sup = (await s.execute(text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user"))).scalar_one()
        assert sup is False
