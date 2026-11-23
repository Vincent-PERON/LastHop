"""TOTP du compte local : défi de connexion en deux étapes (Redis), vérification atomique (anti-rejeu, codes de secours
à usage unique), enregistrement chiffré du secret."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import UTC, datetime

from redis.asyncio import Redis
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import LOCAL_ISSUER, User
from app.security import totp
from app.security.crypto import KeyRing

CHALLENGE_TTL = 300  # 5 minutes pour saisir le code après le mot de passe
CHALLENGE_MAX_TRIES = 5


def _aad(user_id: uuid.UUID) -> str:
    return f"users_totp:{user_id}"


def seal(ring: KeyRing, user: User, secret_b32: str) -> None:
    user.totp_secret_blob = ring.encrypt(secret_b32.encode(), _aad(user.id))
    user.totp_key_id = ring.active_kid


def unseal(ring: KeyRing, user: User) -> str:
    if user.totp_secret_blob is None:
        raise ValueError("pas de secret TOTP")
    return ring.decrypt(user.totp_secret_blob, _aad(user.id)).decode()


# --- défi (étape intermédiaire entre mot de passe valide et session)
def _ckey(token: str) -> str:
    return "totpc:" + hashlib.sha256(token.encode()).hexdigest()


async def create_challenge(redis: Redis, user_id: uuid.UUID) -> str:
    token = secrets.token_urlsafe(32)
    await redis.set(_ckey(token), str(user_id), ex=CHALLENGE_TTL)
    return token


async def challenge_user(redis: Redis, token: str) -> uuid.UUID | None:
    """Identifiant du compte du défi, ou None (inconnu, expiré, ou trop d'essais). Compte l'essai."""
    key = _ckey(token)
    raw = await redis.get(key)
    if raw is None:
        return None
    tries = await redis.incr(key + ":t")
    await redis.expire(key + ":t", CHALLENGE_TTL)
    if tries > CHALLENGE_MAX_TRIES:
        await redis.delete(key, key + ":t")
        return None
    return uuid.UUID(raw.decode() if isinstance(raw, bytes) else raw)


async def close_challenge(redis: Redis, token: str) -> None:
    key = _ckey(token)
    await redis.delete(key, key + ":t")


# --- second facteur
async def verify_second_factor(
    db: AsyncSession, ring: KeyRing, user: User, code: str, now: float | None = None
) -> str | None:
    """Retourne « totp » ou « recovery » si le code est valable (et le consomme), sinon None.

    TOTP : le pas accepté est enregistré par UPDATE conditionnel (deux requêtes simultanées : une seule passe).
    Secours : le code est retiré de la liste sous verrou de ligne (usage unique)."""
    if totp.looks_like_recovery(code):
        row = (await db.execute(select(User).where(User.id == user.id).with_for_update())).scalar_one()
        wanted = totp.hash_recovery(code)
        stored = list(row.totp_recovery or [])
        hit = next((h for h in stored if hmac.compare_digest(h, wanted)), None)
        if hit is None:
            return None
        row.totp_recovery = [h for h in stored if h != hit]
        user.totp_recovery = row.totp_recovery
        return "recovery"
    step = totp.verify(unseal(ring, user), code, user.totp_last_step, now)
    if step is None:
        return None
    res = await db.execute(
        update(User)
        .where(User.id == user.id, or_(User.totp_last_step.is_(None), User.totp_last_step < step))
        .values(totp_last_step=step)
    )
    if not res.rowcount:  # type: ignore[attr-defined]
        return None  # rejeu concurrent
    user.totp_last_step = step
    return "totp"


async def disable_totp(db: AsyncSession, username: str) -> bool:
    """Secours (CLI) : retire le TOTP d'un compte local (appareil perdu, plus de codes de secours)."""
    res = await db.execute(
        update(User)
        .where(User.issuer == LOCAL_ISSUER, User.sub == username)
        .values(totp_enabled=False, totp_secret_blob=None, totp_key_id=None, totp_last_step=None, totp_recovery=[])
    )
    return bool(res.rowcount)  # type: ignore[attr-defined]


def utcnow() -> datetime:
    return datetime.now(UTC)
