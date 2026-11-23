"""Compte super admin local : création au premier démarrage et réinitialisation (CLI)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert

from app.config import Settings
from app.db.models import LOCAL_ISSUER, Role, User
from app.db.session import session_scope
from app.security.passwords import PasswordPolicyError, hash_password, validate_new_password

log = logging.getLogger("lasthop.auth")


async def ensure_local_admin(s: Settings) -> bool:
    """Crée le compte local s'il n'en existe aucun et qu'un mot de passe initial est fourni (Docker secret).
    Le changement du mot de passe est imposé à la première connexion. Retourne True si un compte a été créé."""
    if not s.local_admin_password:
        return False
    async with session_scope() as db:
        if (await db.execute(select(User.id).where(User.issuer == LOCAL_ISSUER).limit(1))).first() is not None:
            return False
        try:
            validate_new_password(s.local_admin_password, s.local_admin_username)
        except PasswordPolicyError as exc:
            log.error("local_admin_bootstrap_refused", extra={"reason": str(exc)})
            return False
        res = await db.execute(
            insert(User)
            .values(
                issuer=LOCAL_ISSUER,
                sub=s.local_admin_username,
                display_name="Super admin local",
                role=Role.admin,
                password_hash=await hash_password(s.local_admin_password),
                must_change_password=s.local_admin_must_change,
            )
            .on_conflict_do_nothing(index_elements=["issuer", "sub"])
        )
        await db.commit()
        created = bool(res.rowcount)  # type: ignore[attr-defined]
    if created:
        log.warning("local_admin_created", extra={"username": s.local_admin_username})
    return created


async def reset_local_password(username: str, new_password: str) -> bool:
    """Réinitialisation de secours (CLI, accès au serveur requis) : déverrouille, impose un nouveau changement et
    invalide toutes les sessions du compte. Retourne False si le compte n'existe pas."""
    validate_new_password(new_password, username)
    async with session_scope() as db:
        res = await db.execute(
            update(User)
            .where(User.issuer == LOCAL_ISSUER, User.sub == username)
            .values(
                password_hash=await hash_password(new_password),
                must_change_password=True,
                failed_login_count=0,
                locked_until=None,
                is_active=True,
                password_changed_at=datetime.now(UTC),
            )
        )
        await db.commit()
        return bool(res.rowcount)  # type: ignore[attr-defined]
