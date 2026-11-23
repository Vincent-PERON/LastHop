"""Planification périodique de la collecte de topologie (appelée par Celery beat)."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, Job
from app.services.settings_store import all_values

MAX_PER_SWEEP = 200
INFLIGHT_WINDOW = timedelta(minutes=30)


async def create_due_topology_jobs(db: AsyncSession) -> list[uuid.UUID]:
    cfg = await all_values(db)
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=int(cfg["topology_interval_s"]))
    due = (
        (
            await db.execute(
                select(Device)
                .where(
                    Device.enabled.is_(True), (Device.last_topology_at.is_(None)) | (Device.last_topology_at < cutoff)
                )
                .order_by(Device.last_topology_at.asc().nulls_first())
                .limit(MAX_PER_SWEEP)
            )
        )
        .scalars()
        .all()
    )
    inflight = {
        j.params.get("device_id")
        for j in (
            await db.execute(
                select(Job).where(
                    Job.kind == "topology",
                    Job.status.in_(("pending", "running")),
                    Job.created_at > now - INFLIGHT_WINDOW,
                )
            )
        ).scalars()
    }
    ids: list[uuid.UUID] = []
    for d in due:
        if str(d.id) in inflight:
            continue
        job = Job(kind="topology", requested_by=None, params={"device_id": str(d.id)})
        db.add(job)
        await db.flush()
        ids.append(job.id)
    await db.commit()
    return ids


async def create_due_learning_jobs(db: AsyncSession) -> list[uuid.UUID]:
    """Un job de learning par équipement dont la dernière collecte dépasse SON intervalle (poll_interval_s)."""
    now = datetime.now(UTC)
    devices = (
        (
            await db.execute(
                select(Device)
                .where(Device.enabled.is_(True), (Device.is_l2.is_(True)) | (Device.is_l3.is_(True)))
                .order_by(Device.last_learning_at.asc().nulls_first())
            )
        )
        .scalars()
        .all()
    )
    inflight = {
        j.params.get("device_id")
        for j in (
            await db.execute(
                select(Job).where(
                    Job.kind == "learning",
                    Job.status.in_(("pending", "running")),
                    Job.created_at > now - INFLIGHT_WINDOW,
                )
            )
        ).scalars()
    }
    ids: list[uuid.UUID] = []
    for d in devices:
        if len(ids) >= MAX_PER_SWEEP or str(d.id) in inflight:
            continue
        if d.last_learning_at is not None and d.last_learning_at > now - timedelta(seconds=d.poll_interval_s):
            continue
        job = Job(kind="learning", requested_by=None, params={"device_id": str(d.id)})
        db.add(job)
        await db.flush()
        ids.append(job.id)
    await db.commit()
    return ids


async def create_due_backup_jobs(db: AsyncSession) -> list[uuid.UUID]:
    """Sauvegardes planifiées : équipements `backup_enabled` dont la dernière tentative dépasse `backup_interval_s`."""
    cfg = await all_values(db)
    now = datetime.now(UTC)
    cutoff = now - timedelta(seconds=int(cfg["backup_interval_s"]))
    due = (
        (
            await db.execute(
                select(Device)
                .where(
                    Device.enabled.is_(True),
                    Device.backup_enabled.is_(True),
                    (Device.last_backup_at.is_(None)) | (Device.last_backup_at < cutoff),
                )
                .order_by(Device.last_backup_at.asc().nulls_first())
                .limit(MAX_PER_SWEEP)
            )
        )
        .scalars()
        .all()
    )
    inflight = {
        j.params.get("device_id")
        for j in (
            await db.execute(
                select(Job).where(
                    Job.kind == "backup", Job.status.in_(("pending", "running")), Job.created_at > now - INFLIGHT_WINDOW
                )
            )
        ).scalars()
    }
    ids: list[uuid.UUID] = []
    for d in due:
        if str(d.id) in inflight:
            continue
        job = Job(kind="backup", requested_by=None, params={"device_id": str(d.id), "trigger": "scheduled"})
        db.add(job)
        await db.flush()
        ids.append(job.id)
    await db.commit()
    return ids
