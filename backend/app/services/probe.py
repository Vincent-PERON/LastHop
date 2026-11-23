"""Exécution des jobs SNMP (côté worker) : test de connectivité et découverte par plage CIDR."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Device, Job, SnmpCredentialRow
from app.drivers.base import DeviceIdentity
from app.drivers.registry import detect_driver, get_driver
from app.redis_util import StreamPublisher
from app.security.crypto import KeyRing
from app.security.targets import TargetNotAllowed, check_address, expand_hosts, parse_discovery_cidr
from app.services.credentials_store import to_snmp_credential
from app.services.learning import persist_learning
from app.services.settings_store import all_values
from app.services.topology import persist_snapshot
from app.snmp import oids
from app.snmp.client import SnmpClient, SnmpError, SnmpTarget

log = logging.getLogger("lasthop.probe")

V2C_DISABLED = "V2C_DISABLED"
TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
INTERNAL = "INTERNAL_ERROR"


async def identify_target(target: SnmpTarget) -> DeviceIdentity:
    async with SnmpClient(target) as client:
        oid = (await client.get(oids.SYS_OBJECT_ID)).get(oids.SYS_OBJECT_ID)
        driver = detect_driver(str(oid or ""))()
        return await driver.identify(client)


async def _run_device_test(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    cfg = await all_values(db)
    dev = (await db.execute(select(Device).where(Device.id == uuid.UUID(params["device_id"])))).scalar_one()
    cred = (await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == dev.credential_id))).scalar_one()
    if cred.version == "v2c" and not cfg["snmp_v2c_enabled"]:
        raise SnmpError(V2C_DISABLED)
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        raise SnmpError(TARGET_NOT_ALLOWED) from None
    target = SnmpTarget(
        host=str(dev.mgmt_ip),
        port=dev.snmp_port,
        timeout_s=dev.timeout_ms / 1000,
        retries=dev.retries,
        credential=to_snmp_credential(keyring, cred),
        context_name=dev.snmp_context,
    )
    started = time.monotonic()
    try:
        ident = await identify_target(target)
    except SnmpError as exc:
        await db.execute(update(Device).where(Device.id == dev.id).values(last_poll_status=exc.code))
        raise
    await db.execute(
        update(Device)
        .where(Device.id == dev.id)
        .values(
            sys_name=ident.sys_name,
            sys_descr=ident.sys_descr,
            sys_object_id=ident.sys_object_id,
            vendor=ident.vendor,
            model=ident.model,
            driver=ident.driver,
            last_identified_at=datetime.now(UTC),
            last_poll_status="ok",
        )
    )
    return {"ok": True, "latency_ms": round((time.monotonic() - started) * 1000), **asdict(ident)}


async def _run_topology(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    cfg = await all_values(db)
    dev = (await db.execute(select(Device).where(Device.id == uuid.UUID(params["device_id"])))).scalar_one()
    cred = (await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == dev.credential_id))).scalar_one()
    if cred.version == "v2c" and not cfg["snmp_v2c_enabled"]:
        raise SnmpError(V2C_DISABLED)
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        raise SnmpError(TARGET_NOT_ALLOWED) from None
    target = SnmpTarget(
        host=str(dev.mgmt_ip),
        port=dev.snmp_port,
        timeout_s=dev.timeout_ms / 1000,
        retries=dev.retries,
        credential=to_snmp_credential(keyring, cred),
        context_name=dev.snmp_context,
    )
    try:
        async with SnmpClient(target) as client:
            driver_cls = get_driver(dev.driver)
            if dev.driver == "generic":  # équipement jamais identifié : détection par sysObjectID
                oid = (await client.get(oids.SYS_OBJECT_ID)).get(oids.SYS_OBJECT_ID)
                driver_cls = detect_driver(str(oid or ""))
                dev.driver, dev.vendor = driver_cls.name, driver_cls.vendor  # mémorisé : plus de détection ensuite
            snap = await driver_cls().collect_topology(
                client, min_tagged_vlans=int(cfg["trunk_min_tagged_vlans"]), max_repetitions=dev.max_repetitions
            )
    except SnmpError as exc:
        await db.execute(update(Device).where(Device.id == dev.id).values(last_topology_status=exc.code))
        raise
    stats = await persist_snapshot(db, dev, snap)
    return {"ok": True, "driver": driver_cls.name, **stats}


async def _run_learning(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    cfg = await all_values(db)
    dev = (await db.execute(select(Device).where(Device.id == uuid.UUID(params["device_id"])))).scalar_one()
    cred = (await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == dev.credential_id))).scalar_one()
    if cred.version == "v2c" and not cfg["snmp_v2c_enabled"]:
        raise SnmpError(V2C_DISABLED)
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        raise SnmpError(TARGET_NOT_ALLOWED) from None
    if dev.last_topology_at is None:  # ports et rôles (uplink/accès) nécessaires à la jointure
        await _run_topology(db, keyring, params)
    target = SnmpTarget(
        host=str(dev.mgmt_ip),
        port=dev.snmp_port,
        timeout_s=dev.timeout_ms / 1000,
        retries=dev.retries,
        credential=to_snmp_credential(keyring, cred),
        context_name=dev.snmp_context,
    )
    arp = fdb = None
    try:
        async with SnmpClient(target) as client:
            driver_cls = get_driver(dev.driver)
            if dev.driver == "generic":
                oid = (await client.get(oids.SYS_OBJECT_ID)).get(oids.SYS_OBJECT_ID)
                driver_cls = detect_driver(str(oid or ""))
                dev.driver, dev.vendor = driver_cls.name, driver_cls.vendor  # mémorisé : plus de détection ensuite
            driver = driver_cls()
            if dev.is_l3:
                arp = await driver.collect_arp(client, dev.max_repetitions)
        if dev.is_l2:
            fdb = await driver.collect_fdb(target, dev.max_repetitions, int(cfg["snmp_max_concurrency"]))
    except SnmpError as exc:
        # un échec ne modifie AUCUN endpoint : une collecte incomplète ne doit pas faire « disparaître » des postes
        await db.execute(update(Device).where(Device.id == dev.id).values(last_learning_status=exc.code))
        raise
    stats = await persist_learning(db, dev, arp, fdb)
    dev.last_learning_at, dev.last_learning_status = datetime.now(UTC), "ok"
    return {"ok": True, "driver": driver_cls.name, **stats}


async def _run_hostkey(db: AsyncSession, params: dict[str, Any]) -> dict[str, Any]:
    """Lit la clé d'hôte SSH SANS s'authentifier ; l'approbation reste un acte humain distinct."""
    from app.services.backup_messages import human
    from app.services.ssh_backup import BackupError, fetch_host_key

    cfg = await all_values(db)
    dev = (await db.execute(select(Device).where(Device.id == uuid.UUID(params["device_id"])))).scalar_one()
    try:
        check_address(str(dev.mgmt_ip), cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        what, advice = human("TARGET_NOT_ALLOWED")
        return {"error_code": "TARGET_NOT_ALLOWED", "message": what, "advice": advice}
    try:
        pub, fp, algo = await fetch_host_key(str(dev.mgmt_ip), dev.ssh_port, dev.ssh_allow_legacy)
    except BackupError as exc:
        what, advice = human(exc.code)
        return {"error_code": exc.code, "message": what, "advice": advice}
    return {"fingerprint": fp, "algo": algo, "public_key": pub, "host": str(dev.mgmt_ip), "port": dev.ssh_port}


async def _run_realtime_job(db: AsyncSession, keyring: KeyRing, job: Job, redis: Redis | None) -> dict[str, Any]:
    from app.security.audit import record
    from app.services.realtime import MESSAGES, run_realtime

    async def silent(_: str, __: dict[str, Any]) -> None:
        return None

    publish = StreamPublisher(redis, job.id) if redis is not None else silent
    try:
        result = await run_realtime(db, keyring, job.params, publish)
    except Exception:
        await publish("failed", {"ok": False, "error_code": INTERNAL, "message": MESSAGES["INTERNAL_ERROR"]})
        await publish("done", {"ok": False, "error_code": INTERNAL})
        raise
    await record(  # trace « résultat » (qui a cherché quoi est déjà dans l'audit de la requête)
        db,
        None,
        "realtime.result",
        actor_type="system",
        target_type="job",
        target_id=str(job.id),
        details={
            "query": job.params.get("value"),
            "ok": bool(result.get("ok")),
            "error_code": result.get("error_code"),
        },
    )
    return result


async def _run_discovery(db: AsyncSession, keyring: KeyRing, params: dict[str, Any]) -> dict[str, Any]:
    cfg = await all_values(db)
    cred = (
        await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == uuid.UUID(params["credential_id"])))
    ).scalar_one()
    if cred.version == "v2c" and not cfg["snmp_v2c_enabled"]:
        raise SnmpError(V2C_DISABLED)
    try:  # revérifié côté worker : défense en profondeur (la liste blanche a pu changer depuis la requête)
        net = parse_discovery_cidr(params["cidr"], cfg["snmp_allowed_cidrs"])
    except TargetNotAllowed:
        raise SnmpError(TARGET_NOT_ALLOWED) from None
    credential = to_snmp_credential(keyring, cred)
    known = {str(ip) for ip in (await db.execute(select(Device.mgmt_ip))).scalars()}
    hosts = expand_hosts(net)
    sem = asyncio.Semaphore(int(cfg["snmp_max_concurrency"]))
    port = int(params.get("port", 161))

    async def probe(ip: str) -> dict[str, Any] | None:
        async with sem:
            try:
                ident = await identify_target(
                    SnmpTarget(host=ip, port=port, timeout_s=1.5, retries=0, credential=credential)
                )
            except (SnmpError, OSError):
                return None
            return {"ip": ip, "already_registered": ip in known, **asdict(ident)}

    found = [r for r in await asyncio.gather(*(probe(h) for h in hosts)) if r]
    return {"scanned": len(hosts), "found": len(found), "hosts": found}


async def process_job(db: AsyncSession, keyring: KeyRing, job_id: uuid.UUID, redis: Redis | None = None) -> None:
    job = (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
    if job is None or job.status != "pending":
        return  # idempotent : un job déjà pris/terminé n'est jamais rejoué
    job.status, job.started_at = "running", datetime.now(UTC)
    await db.commit()
    result: dict[str, Any] | None = None
    error: str | None = None
    try:
        if job.kind == "device_test":
            result = await _run_device_test(db, keyring, job.params)
        elif job.kind == "topology":
            result = await _run_topology(db, keyring, job.params)
        elif job.kind == "realtime":
            result = await _run_realtime_job(db, keyring, job, redis)
            error = result.get(
                "error_code"
            )  # un échec « métier » (MAC expirée…) marque le job « failed » mais garde le détail
        elif job.kind == "backup":
            from app.services.ssh_backup import run_backup

            result = await run_backup(db, keyring, job.params)
            error = result.get("error_code")
        elif job.kind == "ssh_hostkey":
            result = await _run_hostkey(db, job.params)
            error = result.get("error_code")
        elif job.kind == "oui_update":
            from app.services.oui import update_oui

            result = {"entries": await update_oui(db)}
        elif job.kind == "learning":
            result = await _run_learning(db, keyring, job.params)
        elif job.kind == "discovery":
            result = await _run_discovery(db, keyring, job.params)
        else:
            error = INTERNAL
    except SnmpError as exc:
        error = exc.code
    except Exception:  # noqa: BLE001 - détail en logs serveur uniquement (jamais de secret dans la trace)
        log.exception("job_failed", extra={"job_id": str(job_id), "kind": job.kind})
        error = INTERNAL
    await db.execute(
        update(Job)
        .where(Job.id == job_id)
        .values(status="failed" if error else "done", result=result, error_code=error, finished_at=datetime.now(UTC))
    )
    await db.commit()
