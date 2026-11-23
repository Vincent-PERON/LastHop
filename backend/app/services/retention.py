"""Purge des données anciennes (rétention). Le journal d'audit n'est JAMAIS purgé par l'application."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.security.audit import record
from app.services.settings_store import get_value

BATCH = 10_000
JOB_RETENTION_DAYS = 30

_STATEMENTS = {
    "endpoint_history": (
        "DELETE FROM endpoint_history WHERE id IN (SELECT id FROM endpoint_history WHERE ts < :c LIMIT :n)"
    ),
    "endpoints": "DELETE FROM endpoints WHERE id IN (SELECT id FROM endpoints WHERE last_seen < :c LIMIT :n)",
}


async def purge(db: AsyncSession) -> dict[str, int]:
    days = int(await get_value(db, "retention_days"))
    cutoff = datetime.now(UTC) - timedelta(days=days)
    totals: dict[str, int] = {}
    for name, sql in _STATEMENTS.items():  # par lots : transactions courtes même sur de gros volumes
        total = 0
        while True:
            n = int((await db.execute(text(sql), {"c": cutoff, "n": BATCH})).rowcount)  # type: ignore[attr-defined]
            await db.commit()
            total += n
            if n < BATCH:
                break
        totals[name] = total
    # Anciennes versions de configuration : on conserve TOUJOURS la dernière de chaque type par équipement, et tout
    # contenu encore référencé par une ligne « identique » récente.
    bdays = int(await get_value(db, "backup_retention_days"))
    bcut = datetime.now(UTC) - timedelta(days=bdays)
    await db.execute(text("DELETE FROM config_backups WHERE status = 'unchanged' AND created_at < :c"), {"c": bcut})
    cfg_res = await db.execute(
        text(
            "DELETE FROM config_backups b WHERE b.created_at < :c AND b.status = 'success' "
            "AND NOT EXISTS (SELECT 1 FROM config_backups r WHERE r.same_as_id = b.id) "
            "AND b.id NOT IN (SELECT DISTINCT ON (device_id, kind) id FROM config_backups "
            "WHERE status = 'success' ORDER BY device_id, kind, created_at DESC)"
        ),
        {"c": bcut},
    )
    totals["config_backups"] = int(cfg_res.rowcount)  # type: ignore[attr-defined]
    runs_res = await db.execute(text("DELETE FROM backup_runs WHERE started_at < :c"), {"c": bcut})
    totals["backup_runs"] = int(runs_res.rowcount)  # type: ignore[attr-defined]
    jobs_res = await db.execute(
        text("DELETE FROM jobs WHERE created_at < :c AND status IN ('done','failed')"),
        {"c": datetime.now(UTC) - timedelta(days=JOB_RETENTION_DAYS)},
    )
    totals["jobs"] = int(jobs_res.rowcount)  # type: ignore[attr-defined]
    await record(db, None, "retention.purge", actor_type="system", details={"retention_days": days, **totals})
    await db.commit()
    return totals
