from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select

from app.db.models import ApiToken, Role
from app.deps import DbSession, require
from app.security import tokens as tok
from app.security.audit import record
from app.security.rbac import ROLE_PERMS, TOKEN_SCOPES, Perm, Principal

router = APIRouter(prefix="/api/v1/tokens", tags=["tokens"])
# Gestion des tokens : super admin uniquement (un token d'API ne peut jamais porter cette permission).
SuperAdmin = Annotated[Principal, Depends(require(Perm.tokens_manage))]
MAX_LIFETIME_DAYS = 365


class TokenCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .@()\-]+$")]
    scopes: Annotated[list[str], Field(min_length=1, max_length=len(TOKEN_SCOPES))]
    expires_in_days: Annotated[int, Field(ge=1, le=MAX_LIFETIME_DAYS)] = 90

    @field_validator("scopes")
    @classmethod
    def _known(cls, v: list[str]) -> list[str]:
        if set(v) - set(TOKEN_SCOPES):
            raise ValueError("portée inconnue")
        return sorted(set(v))


def _view(t: ApiToken) -> dict[str, object]:
    return {
        "id": str(t.id),
        "name": t.name,
        "prefix": t.prefix,
        "scopes": t.scopes,
        "expires_at": t.expires_at.isoformat(),
        "revoked_at": t.revoked_at.isoformat() if t.revoked_at else None,
        "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
        "user_id": str(t.user_id),
    }


@router.post("", status_code=201)
async def create_token(body: TokenCreate, request: Request, principal: SuperAdmin, db: DbSession) -> dict[str, object]:
    if principal.kind != "user":
        raise HTTPException(403, "Un token d'API ne peut pas créer de token")
    # Un utilisateur ne peut pas déléguer une portée que son rôle n'autorise pas.
    for s in body.scopes:
        if not TOKEN_SCOPES[s] <= ROLE_PERMS[principal.role]:
            raise HTTPException(403, "Portée non autorisée pour votre rôle")
    plain, prefix, h = tok.generate_token()
    t = ApiToken(
        user_id=principal.user_id,
        name=body.name,
        prefix=prefix,
        token_hash=h,
        scopes=body.scopes,
        expires_at=datetime.now(UTC) + timedelta(days=body.expires_in_days),
    )
    db.add(t)
    await db.flush()
    await record(
        db,
        request,
        "token.create",
        principal=principal,
        target_type="api_token",
        target_id=str(t.id),
        details={"name": body.name, "scopes": body.scopes, "expires_in_days": body.expires_in_days},
    )
    await db.commit()
    return {**_view(t), "token": plain}  # seule occurrence du secret en clair


@router.get("")
async def list_tokens(
    principal: SuperAdmin, db: DbSession, all: Annotated[bool, Query()] = False
) -> list[dict[str, object]]:
    q = select(ApiToken).order_by(ApiToken.created_at.desc()).limit(500)
    if not (all and principal.role == Role.admin):
        q = q.where(ApiToken.user_id == principal.user_id)
    return [_view(t) for t in (await db.execute(q)).scalars()]


@router.delete("/{token_id}", status_code=204)
async def revoke_token(token_id: uuid.UUID, request: Request, principal: SuperAdmin, db: DbSession) -> None:
    if principal.kind != "user":
        raise HTTPException(403, "Révocation réservée aux sessions")
    t = (await db.execute(select(ApiToken).where(ApiToken.id == token_id))).scalar_one_or_none()
    # Même réponse pour « inexistant » et « appartient à un autre » (pas d'énumération), sauf admin.
    if t is None or (t.user_id != principal.user_id and principal.role != Role.admin):
        raise HTTPException(404, "Introuvable")
    if t.revoked_at is None:
        t.revoked_at = datetime.now(UTC)
        await record(db, request, "token.revoke", principal=principal, target_type="api_token", target_id=str(t.id))
        await db.commit()
