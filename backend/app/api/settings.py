"""Paramètres d'administration (ex. désactivation globale de SNMP v2c). Liste blanche stricte de clés."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, TypeAdapter, ValidationError
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.models import AppSetting
from app.deps import DbSession, require
from app.security.audit import record
from app.security.rbac import Perm, Principal
from app.services.settings_store import SCHEMA, all_values

router = APIRouter(prefix="/api/v1/settings", tags=["settings"])


class SettingBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: Any


@router.get("")
async def get_settings_(
    db: DbSession, _: Annotated[Principal, Depends(require(Perm.settings_write))]
) -> dict[str, Any]:
    return await all_values(db)


@router.put("/{key}")
async def put_setting(
    key: str,
    body: SettingBody,
    request: Request,
    db: DbSession,
    principal: Annotated[Principal, Depends(require(Perm.settings_write))],
) -> dict[str, Any]:
    if key not in SCHEMA:
        raise HTTPException(404, "Paramètre inconnu")
    try:
        value = TypeAdapter(SCHEMA[key][0]).validate_python(body.value, strict=True)
    except ValidationError:
        raise HTTPException(422, "Valeur invalide") from None
    await db.execute(
        pg_insert(AppSetting)
        .values(key=key, value=value, updated_by=str(principal.user_id))
        .on_conflict_do_update(index_elements=["key"], set_={"value": value, "updated_by": str(principal.user_id)})
    )
    await record(
        db,
        request,
        "settings.update",
        principal=principal,
        target_type="setting",
        target_id=key,
        details={"value": value},
    )
    await db.commit()
    return {key: value}
