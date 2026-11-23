"""Profils d'identifiants SNMP. Les secrets sont chiffrés (AES-GCM) et ne sont JAMAIS renvoyés par l'API."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.db.models import Device, SnmpCredentialRow
from app.deps import DbSession, require
from app.security.audit import record
from app.security.crypto import keyring_from_settings
from app.security.rbac import Perm, Principal
from app.services.credentials_store import seal, unseal
from app.services.settings_store import get_value

router = APIRouter(prefix="/api/v1/credentials", tags=["credentials"])
Admin = Annotated[Principal, Depends(require(Perm.credentials_write))]

NAME = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .\-()]+$")]
KEY = Annotated[SecretStr, Field(min_length=8, max_length=128)]  # 8 = minimum RFC 3414
AuthProto = Literal["sha224", "sha256", "sha384", "sha512", "sha1"]
PrivProto = Literal["aes128", "aes192", "aes256"]
WEAK_COMMUNITIES = {"public", "private", "community", "snmp", "cisco", "admin"}


class CredentialIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: NAME
    version: Literal["v2c", "v3"] = "v3"
    # v2c
    community: SecretStr | None = Field(default=None, min_length=6, max_length=64)
    # v3 : uniquement authPriv (authNoPriv/noAuth ne sont pas proposés)
    v3_username: Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[\w.\-@]+$")] | None = None
    auth_proto: AuthProto = "sha256"
    priv_proto: PrivProto = "aes128"
    auth_key: KEY | None = None
    priv_key: KEY | None = None
    allow_legacy_algos: bool = False  # nécessaire pour SHA-1 : équipement ne supportant pas mieux

    @model_validator(mode="after")
    def _shape(self) -> CredentialIn:
        if self.version == "v2c":
            if not self.community or self.community.get_secret_value().lower() in WEAK_COMMUNITIES:
                raise ValueError("community absente ou triviale")
            if self.v3_username or self.auth_key or self.priv_key:
                raise ValueError("champs v3 interdits en v2c")
        else:
            if not (self.v3_username and self.auth_key and self.priv_key) or self.community:
                raise ValueError("v3 : utilisateur, clé d'authentification et clé de chiffrement requis")
        if self.auth_proto == "sha1" and not self.allow_legacy_algos:
            raise ValueError("SHA-1 exige allow_legacy_algos=true")
        return self


class CredentialUpdate(BaseModel):
    """Mise à jour partielle : un secret omis est conservé. La version ne peut pas changer."""

    model_config = ConfigDict(extra="forbid")
    name: NAME | None = None
    community: SecretStr | None = Field(default=None, min_length=6, max_length=64)
    v3_username: Annotated[str, Field(min_length=1, max_length=32, pattern=r"^[\w.\-@]+$")] | None = None
    auth_proto: AuthProto | None = None
    priv_proto: PrivProto | None = None
    auth_key: KEY | None = None
    priv_key: KEY | None = None
    allow_legacy_algos: bool | None = None


def _view(c: SnmpCredentialRow, in_use: int = 0) -> dict[str, Any]:
    return {
        "id": str(c.id),
        "name": c.name,
        "version": c.version,
        "v3_username": c.v3_username,
        "auth_proto": c.auth_proto,
        "priv_proto": c.priv_proto,
        "allow_legacy_algos": c.allow_legacy_algos,
        "key_id": c.key_id,
        "secrets_stored": True,  # indicateur seulement : la valeur n'est jamais exposée
        "devices_using": in_use,
        "updated_at": c.updated_at.isoformat(),
    }


async def _require_v2c_enabled(db: Any) -> None:
    if not await get_value(db, "snmp_v2c_enabled"):
        raise HTTPException(409, "SNMP v2c est désactivé globalement")


@router.get("")
async def list_credentials(db: DbSession, _: Admin) -> list[dict[str, Any]]:
    counts = dict((await db.execute(select(Device.credential_id, func.count()).group_by(Device.credential_id))).all())
    rows = (await db.execute(select(SnmpCredentialRow).order_by(SnmpCredentialRow.name))).scalars()
    return [_view(c, counts.get(c.id, 0)) for c in rows]


@router.post("", status_code=201)
async def create_credential(body: CredentialIn, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    if body.version == "v2c":
        await _require_v2c_enabled(db)
    keyring = _keyring(request)
    cid = uuid.uuid4()
    secrets = (
        {"community": body.community.get_secret_value()}  # type: ignore[union-attr]
        if body.version == "v2c"
        else {"auth_key": body.auth_key.get_secret_value(), "priv_key": body.priv_key.get_secret_value()}  # type: ignore[union-attr]
    )
    blob, kid = seal(keyring, cid, secrets)
    row = SnmpCredentialRow(
        id=cid,
        name=body.name,
        version=body.version,
        secret_blob=blob,
        key_id=kid,
        created_by=p.user_id,
        v3_username=body.v3_username if body.version == "v3" else None,
        auth_proto=body.auth_proto if body.version == "v3" else None,
        priv_proto=body.priv_proto if body.version == "v3" else None,
        allow_legacy_algos=body.allow_legacy_algos,
    )
    db.add(row)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Ce nom existe déjà") from None
    await record(  # l'audit ne contient jamais de secret : seulement les métadonnées
        db,
        request,
        "credential.create",
        principal=p,
        target_type="snmp_credential",
        target_id=str(cid),
        details={
            "name": body.name,
            "version": body.version,
            "auth_proto": row.auth_proto,
            "priv_proto": row.priv_proto,
            "legacy": body.allow_legacy_algos,
        },
    )
    await db.commit()
    return _view(row)


@router.put("/{cred_id}")
async def update_credential(
    cred_id: uuid.UUID, body: CredentialUpdate, request: Request, db: DbSession, p: Admin
) -> dict[str, Any]:
    row = (await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == cred_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Introuvable")
    if row.version == "v2c" and (body.v3_username or body.auth_key or body.priv_key):
        raise HTTPException(422, "Champs v3 interdits pour un profil v2c")
    if row.version == "v3" and body.community:
        raise HTTPException(422, "community interdite pour un profil v3")
    if row.version == "v2c" and body.community:
        await _require_v2c_enabled(db)
    keyring = _keyring(request)
    secrets = unseal(keyring, row)
    changed: list[str] = []
    if body.community:
        if body.community.get_secret_value().lower() in WEAK_COMMUNITIES:
            raise HTTPException(422, "community triviale")
        secrets["community"] = body.community.get_secret_value()
        changed.append("community")
    if body.auth_key:
        secrets["auth_key"] = body.auth_key.get_secret_value()
        changed.append("auth_key")
    if body.priv_key:
        secrets["priv_key"] = body.priv_key.get_secret_value()
        changed.append("priv_key")
    for f in ("name", "v3_username", "auth_proto", "priv_proto", "allow_legacy_algos"):
        v = getattr(body, f)
        if v is not None and getattr(row, f) != v:
            setattr(row, f, v)
            changed.append(f)
    if row.auth_proto == "sha1" and not row.allow_legacy_algos:
        raise HTTPException(422, "SHA-1 exige allow_legacy_algos=true")
    if any(c in changed for c in ("community", "auth_key", "priv_key")):
        row.secret_blob, row.key_id = seal(keyring, row.id, secrets)
    row.updated_at = datetime.now(UTC)
    try:
        await record(
            db,
            request,
            "credential.update",
            principal=p,
            target_type="snmp_credential",
            target_id=str(row.id),
            details={"changed_fields": changed},
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Ce nom existe déjà") from None
    return _view(row)


@router.delete("/{cred_id}", status_code=204)
async def delete_credential(cred_id: uuid.UUID, request: Request, db: DbSession, p: Admin) -> None:
    row = (await db.execute(select(SnmpCredentialRow).where(SnmpCredentialRow.id == cred_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Introuvable")
    try:
        await db.delete(row)
        await record(
            db,
            request,
            "credential.delete",
            principal=p,
            target_type="snmp_credential",
            target_id=str(cred_id),
            details={"name": row.name},
        )
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(409, "Profil utilisé par des équipements") from None


def _keyring(request: Request):  # type: ignore[no-untyped-def]
    s = request.app.state.settings
    return keyring_from_settings(s.master_keys, s.master_key_active)
