"""TOTP optionnel du compte super admin local : activation, connexion en deux étapes, codes de secours."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.api.auth import (
    _deny,
    _keyring,
    _require_origin,
    open_local_session,
    register_failure,
)
from app.db.models import LOCAL_ISSUER, User
from app.deps import CurrentPrincipal, DbSession
from app.security import totp
from app.security.audit import record
from app.security.passwords import is_locked, verify_password
from app.security.ratelimit import ip_limiter
from app.services import totp_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth-totp"])
Code = Annotated[str, Field(min_length=6, max_length=16, pattern=r"^[0-9A-Za-z -]+$")]
Password = Annotated[str, Field(min_length=1, max_length=1024)]


class TotpStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge: Annotated[str, Field(min_length=20, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")]
    code: Code


@router.post("/local/totp", dependencies=[Depends(ip_limiter("login", 20, 60))])
async def local_totp_login(body: TotpStep, request: Request, db: DbSession) -> JSONResponse:
    """2e étape de la connexion locale : code TOTP (ou code de secours) + défi obtenu après le mot de passe."""
    _require_origin(request)
    redis = request.app.state.redis
    user_id = await totp_service.challenge_user(redis, body.challenge)
    if user_id is None:
        raise await _deny(db, request, "totp_challenge_invalid", provider="local")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    now = datetime.now(UTC)
    if user is None or not user.is_active or not user.totp_enabled or is_locked(user.locked_until, now):
        raise await _deny(db, request, "locked_or_disabled", provider="local", label=user.sub if user else None)
    kind = await totp_service.verify_second_factor(db, _keyring(request), user, body.code)
    if kind is None:
        register_failure(user, now)  # compte dans le verrouillage progressif, comme un mot de passe erroné
        raise await _deny(db, request, "totp_bad_code", provider="local", label=user.sub)
    await totp_service.close_challenge(redis, body.challenge)  # défi à usage unique
    if kind == "recovery":
        await record(
            db,
            request,
            "auth.totp_recovery_used",
            actor_type="user",
            actor_label=user.sub,
            target_type="user",
            target_id=str(user.id),
            details={"remaining": len(user.totp_recovery)},
        )
    return await open_local_session(db, request, user, now, second_factor=kind)


# ---------------------------------------------------------------- gestion (session ouverte, compte local)
async def _local_user(db: DbSession, p: Any) -> User:
    if p.kind != "user":
        raise HTTPException(403, "Réservé aux sessions")
    user = (await db.execute(select(User).where(User.id == p.user_id))).scalar_one()
    if user.issuer != LOCAL_ISSUER:
        raise HTTPException(
            400, "Le TOTP ne concerne que le compte local ; les autres comptes dépendent de leur fournisseur"
        )
    return user


async def _reauth(db: DbSession, request: Request, p: Any, user: User, password: str) -> None:
    if not await verify_password(user.password_hash, password):
        await record(
            db, request, "auth.totp_reauth", principal=p, outcome="failure", details={"reason": "bad_password"}
        )
        await db.commit()
        raise HTTPException(403, "Mot de passe incorrect")


class PasswordOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: Password


class CodeOnly(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: Code


class PasswordAndCode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: Password
    code: Code


def _new_recovery(user: User) -> list[str]:
    codes = totp.new_recovery_codes()
    user.totp_recovery = [totp.hash_recovery(c) for c in codes]
    return [totp.format_recovery(c) for c in codes]  # affichés UNE seule fois


@router.post("/totp/setup", dependencies=[Depends(ip_limiter("totp", 10, 300))])
async def totp_setup(body: PasswordOnly, request: Request, p: CurrentPrincipal, db: DbSession) -> dict[str, Any]:
    """Étape 1 : génère un secret (inactif jusqu'à confirmation par un code). Mot de passe exigé."""
    user = await _local_user(db, p)
    await _reauth(db, request, p, user, body.password)
    if user.totp_enabled:
        raise HTTPException(409, "Le TOTP est déjà activé : désactivez-le d'abord pour en changer")
    secret = totp.new_secret()
    totp_service.seal(_keyring(request), user, secret)
    user.totp_last_step = None
    await record(db, request, "auth.totp_setup", principal=p)
    await db.commit()
    uri = totp.provisioning_uri(secret, user.sub)
    return {"secret": secret, "uri": uri, "qr": totp.qr_data_uri(uri)}


@router.post("/totp/enable", dependencies=[Depends(ip_limiter("totp", 10, 300))])
async def totp_enable(body: CodeOnly, request: Request, p: CurrentPrincipal, db: DbSession) -> dict[str, Any]:
    """Étape 2 : un code valide prouve la configuration ; active le TOTP et fournit les codes de secours."""
    user = await _local_user(db, p)
    if user.totp_enabled or user.totp_secret_blob is None:
        raise HTTPException(409, "Lancez d'abord la configuration")
    step = totp.verify(totp_service.unseal(_keyring(request), user), body.code, None)
    if step is None:
        await record(db, request, "auth.totp_enable", principal=p, outcome="failure", details={"reason": "bad_code"})
        await db.commit()
        raise HTTPException(422, "Code incorrect : vérifiez l'heure de votre appareil et réessayez")
    user.totp_enabled, user.totp_last_step = True, step
    codes = _new_recovery(user)
    await record(db, request, "auth.totp_enable", principal=p)
    await db.commit()
    return {"enabled": True, "recovery_codes": codes}


@router.post("/totp/disable", dependencies=[Depends(ip_limiter("totp", 10, 300))])
async def totp_disable(body: PasswordAndCode, request: Request, p: CurrentPrincipal, db: DbSession) -> dict[str, Any]:
    user = await _local_user(db, p)
    if not user.totp_enabled:
        raise HTTPException(409, "Le TOTP n'est pas activé")
    await _reauth(db, request, p, user, body.password)
    if await totp_service.verify_second_factor(db, _keyring(request), user, body.code) is None:
        await record(db, request, "auth.totp_disable", principal=p, outcome="failure", details={"reason": "bad_code"})
        await db.commit()
        raise HTTPException(403, "Code incorrect")
    user.totp_enabled, user.totp_secret_blob, user.totp_key_id = False, None, None
    user.totp_last_step, user.totp_recovery = None, []
    await record(db, request, "auth.totp_disable", principal=p)
    await db.commit()
    return {"enabled": False}


@router.post("/totp/recovery-codes", dependencies=[Depends(ip_limiter("totp", 10, 300))])
async def totp_regenerate(
    body: PasswordAndCode, request: Request, p: CurrentPrincipal, db: DbSession
) -> dict[str, Any]:
    """Nouveaux codes de secours (les anciens sont invalidés)."""
    user = await _local_user(db, p)
    if not user.totp_enabled:
        raise HTTPException(409, "Le TOTP n'est pas activé")
    await _reauth(db, request, p, user, body.password)
    if await totp_service.verify_second_factor(db, _keyring(request), user, body.code) is None:
        await record(
            db, request, "auth.totp_recovery_regenerate", principal=p, outcome="failure", details={"reason": "bad_code"}
        )
        await db.commit()
        raise HTTPException(403, "Code incorrect")
    codes = _new_recovery(user)
    await record(db, request, "auth.totp_recovery_regenerate", principal=p)
    await db.commit()
    return {"recovery_codes": codes}
