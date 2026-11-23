"""Profils SSH (sauvegarde des configurations) et approbation des empreintes (clés d'hôte) des équipements."""

from __future__ import annotations

import hmac
import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.db.models import Device, Job, SshCredentialRow
from app.deps import DbSession, require
from app.security.audit import record
from app.security.crypto import keyring_from_settings
from app.security.rbac import Perm, Principal
from app.services.jobs import create_and_dispatch
from app.services.ssh_backup import seal_secret, unseal_secret

router = APIRouter(prefix="/api/v1", tags=["ssh"])
Admin = Annotated[Principal, Depends(require(Perm.credentials_write))]
Writer = Annotated[Principal, Depends(require(Perm.inventory_write))]
NAME = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .\-()]+$")]
USER = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[\w.\-@]+$")]
HOSTKEY_JOB_TTL = timedelta(minutes=15)


class SshIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME
    username: USER
    auth_type: Literal["password", "key"] = "password"
    password: SecretStr | None = Field(default=None, min_length=1, max_length=256)
    private_key: SecretStr | None = Field(default=None, min_length=40, max_length=20000)  # PEM / OpenSSH
    passphrase: SecretStr | None = Field(default=None, max_length=256)

    @model_validator(mode="after")
    def _shape(self) -> SshIn:
        if self.auth_type == "password" and (not self.password or self.private_key):
            raise ValueError("mot de passe requis (et pas de clé privée)")
        if self.auth_type == "key" and (not self.private_key or self.password):
            raise ValueError("clé privée requise (et pas de mot de passe)")
        return self


class SshUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME | None = None
    username: USER | None = None
    password: SecretStr | None = Field(default=None, min_length=1, max_length=256)
    private_key: SecretStr | None = Field(default=None, min_length=40, max_length=20000)
    passphrase: SecretStr | None = Field(default=None, max_length=256)


def _view(c: SshCredentialRow, used: int = 0) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "name": c.name,
        "username": c.username,
        "auth_type": c.auth_type,
        "key_id": c.key_id,
        "secrets_stored": True,
        "devices_using": used,
        "updated_at": c.updated_at.isoformat(),
    }


def _keyring(request: Request):  # type: ignore[no-untyped-def]
    s = request.app.state.settings
    return keyring_from_settings(s.master_keys, s.master_key_active)


def _check_private_key(pem: str, passphrase: str | None) -> None:
    try:
        asyncssh.import_private_key(pem, passphrase or None)
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError):
        raise HTTPException(422, "Clé privée illisible ou passphrase incorrecte") from None


@router.get("/ssh-credentials")
async def list_ssh(db: DbSession, _: Admin) -> list[dict[str, Any]]:
    counts = dict(
        (await db.execute(select(Device.ssh_credential_id, func.count()).group_by(Device.ssh_credential_id))).all()
    )
    rows = (await db.execute(select(SshCredentialRow).order_by(SshCredentialRow.name))).scalars()
    return [_view(c, counts.get(c.id, 0)) for c in rows]


@router.post("/ssh-credentials", status_code=201)
async def create_ssh(body: SshIn, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    secrets: dict[str, str]
    if body.auth_type == "password":
        secrets = {"password": body.password.get_secret_value()}  # type: ignore[union-attr]
    else:
        pem = body.private_key.get_secret_value()  # type: ignore[union-attr]
        pp = body.passphrase.get_secret_value() if body.passphrase else None
        _check_private_key(pem, pp)  # refuse une clé invalide dès la création (message clair)
        secrets = {"private_key": pem, **({"passphrase": pp} if pp else {})}
    cid = uuid.uuid4()
    blob, kid = seal_secret(_keyring(request), cid, secrets)
    row = SshCredentialRow(
        id=cid,
        name=body.name,
        username=body.username,
        auth_type=body.auth_type,
        secret_blob=blob,
        key_id=kid,
        created_by=p.user_id,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Ce nom existe déjà") from None
    await record(
        db,
        request,
        "ssh_credential.create",
        principal=p,
        target_type="ssh_credential",
        target_id=str(cid),
        details={"name": body.name, "username": body.username, "auth_type": body.auth_type},
    )  # jamais de secret
    await db.commit()
    return _view(row)


@router.put("/ssh-credentials/{cred_id}")
async def update_ssh(cred_id: uuid.UUID, body: SshUpdate, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    row = (await db.execute(select(SshCredentialRow).where(SshCredentialRow.id == cred_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Introuvable")
    ring = _keyring(request)
    secrets = unseal_secret(ring, row)
    changed: list[str] = []
    if body.password:
        if row.auth_type != "password":
            raise HTTPException(422, "Ce profil utilise une clé")
        secrets["password"] = body.password.get_secret_value()
        changed.append("password")
    if body.private_key:
        if row.auth_type != "key":
            raise HTTPException(422, "Ce profil utilise un mot de passe")
        pp = body.passphrase.get_secret_value() if body.passphrase else None
        _check_private_key(body.private_key.get_secret_value(), pp)
        secrets = {"private_key": body.private_key.get_secret_value(), **({"passphrase": pp} if pp else {})}
        changed.append("private_key")
    for f in ("name", "username"):
        v = getattr(body, f)
        if v is not None and getattr(row, f) != v:
            setattr(row, f, v)
            changed.append(f)
    if "password" in changed or "private_key" in changed:
        row.secret_blob, row.key_id = seal_secret(ring, row.id, secrets)
    row.updated_at = datetime.now(UTC)
    try:
        await record(
            db,
            request,
            "ssh_credential.update",
            principal=p,
            target_type="ssh_credential",
            target_id=str(row.id),
            details={"changed_fields": changed},
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Ce nom existe déjà") from None
    return _view(row)


@router.delete("/ssh-credentials/{cred_id}", status_code=204)
async def delete_ssh(cred_id: uuid.UUID, request: Request, db: DbSession, p: Admin) -> None:
    row = (await db.execute(select(SshCredentialRow).where(SshCredentialRow.id == cred_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Introuvable")
    await db.delete(row)  # les équipements concernés perdent leur profil (SET NULL) : la sauvegarde l'expliquera
    await record(
        db,
        request,
        "ssh_credential.delete",
        principal=p,
        target_type="ssh_credential",
        target_id=str(cred_id),
        details={"name": row.name},
    )
    await db.commit()


# ------------------------------------ empreinte (clé d'hôte) : jamais de confiance automatique


class TrustIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: uuid.UUID
    fingerprint: Annotated[str, Field(min_length=10, max_length=100)]  # ressaisie volontaire : confirmation humaine


@router.post("/devices/{device_id}/ssh/hostkey", status_code=202)
async def fetch_hostkey(device_id: uuid.UUID, request: Request, db: DbSession, p: Writer) -> dict[str, str]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    if d is None:
        raise HTTPException(404, "Introuvable")
    job = await create_and_dispatch(request, db, p, "ssh_hostkey", {"device_id": str(d.id)})
    await record(
        db,
        request,
        "device.ssh_hostkey_fetch",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"job_id": str(job.id)},
    )
    await db.commit()
    return {"job_id": str(job.id)}


@router.post("/devices/{device_id}/ssh/trust")
async def trust_hostkey(
    device_id: uuid.UUID, body: TrustIn, request: Request, db: DbSession, p: Writer
) -> dict[str, Any]:
    d = (await db.execute(select(Device).where(Device.id == device_id))).scalar_one_or_none()
    job = (await db.execute(select(Job).where(Job.id == body.job_id, Job.kind == "ssh_hostkey"))).scalar_one_or_none()
    if (
        d is None
        or job is None
        or job.status != "done"
        or not job.result
        or job.params.get("device_id") != str(device_id)
        or datetime.now(UTC) - job.created_at > HOSTKEY_JOB_TTL
        or job.requested_by != p.user_id
    ):
        raise HTTPException(404, "Vérification introuvable, expirée ou non terminée : relancez-la")
    # L'administrateur doit RESAISIR l'empreinte lue sur l'équipement : on n'approuve pas à l'aveugle
    if not hmac.compare_digest(body.fingerprint.strip(), str(job.result["fingerprint"])):
        await record(
            db,
            request,
            "device.ssh_trust",
            principal=p,
            outcome="denied",
            target_type="device",
            target_id=str(d.id),
            details={"reason": "fingerprint_mismatch"},
        )
        await db.commit()
        raise HTTPException(422, "L'empreinte saisie ne correspond pas à celle reçue de l'équipement")
    previous = None
    if d.ssh_host_key:
        try:
            previous = asyncssh.import_public_key(d.ssh_host_key).get_fingerprint("sha256")
        except (asyncssh.KeyImportError, ValueError):
            previous = "illisible"
    d.ssh_host_key = job.result["public_key"]
    await record(
        db,
        request,
        "device.ssh_trust",
        principal=p,
        target_type="device",
        target_id=str(d.id),
        details={"fingerprint": job.result["fingerprint"], "replaced": previous},
    )
    await db.commit()
    return {"trusted": job.result["fingerprint"], "replaced": previous}
