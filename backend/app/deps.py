"""Dépendances FastAPI : authentification (session cookie OU token Bearer), CSRF, RBAC."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ApiToken, User
from app.db.session import get_session
from app.security import tokens as tok
from app.security.audit import record
from app.security.ratelimit import hit
from app.security.rbac import ROLE_PERMS, Perm, Principal, token_permissions
from app.security.sessions import COOKIE_NAME, SessionStore, session_hash

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DbSession = Annotated[AsyncSession, Depends(get_session)]

PASSWORD_CHANGE_ALLOWED = {"/api/v1/auth/me", "/api/v1/auth/logout", "/api/v1/auth/password"}

UNAUTH = HTTPException(401, "Authentification requise", headers={"WWW-Authenticate": "Bearer"})


def _check_origin_and_csrf(request: Request, csrf_expected: str) -> None:
    import secrets as _s

    origin = request.headers.get("origin")
    if origin is None or origin.rstrip("/") != request.app.state.settings.frontend_origin:
        raise HTTPException(403, "Origine refusée")
    sent = request.headers.get("x-csrf-token", "")
    if not _s.compare_digest(sent, csrf_expected):
        raise HTTPException(403, "Jeton CSRF invalide")


async def get_principal(request: Request, db: DbSession) -> Principal:
    app = request.app
    auth = request.headers.get("authorization")
    ip = request.client.host if request.client else "unknown"

    # --- Token d'API (Bearer) : pas de cookie, donc pas de CSRF
    if auth and auth.lower().startswith("bearer "):
        ok, retry = await hit(app.state.redis, f"tokauth:{ip}", 60, 60)
        if not ok:
            raise HTTPException(429, "Trop de requêtes", headers={"Retry-After": str(retry)})
        parsed = tok.parse_token(auth[7:].strip())
        if parsed is None:
            raise UNAUTH
        prefix, secret = parsed
        row = (
            await db.execute(
                select(ApiToken, User).join(User, User.id == ApiToken.user_id).where(ApiToken.prefix == prefix)
            )
        ).first()
        now = datetime.now(UTC)
        if row is None or not tok.verify_secret(secret, row[0].token_hash):
            raise UNAUTH
        t, u = row
        if t.revoked_at is not None or t.expires_at <= now or not u.is_active:
            raise UNAUTH
        await db.execute(update(ApiToken).where(ApiToken.id == t.id).values(last_used_at=now))
        await db.commit()
        return Principal(
            kind="token",
            user_id=u.id,
            label=f"{u.email or u.sub} (token {t.prefix})",
            role=u.role,
            permissions=token_permissions(list(t.scopes), u.role),
            token_id=t.id,
            scopes=list(t.scopes),
        )

    # --- Session cookie
    sid = request.cookies.get(COOKIE_NAME)
    if not sid:
        raise UNAUTH
    store: SessionStore = app.state.sessions
    data = await store.get(sid)
    if data is None:
        raise UNAUTH
    user = (await db.execute(select(User).where(User.id == data.user_id))).scalar_one_or_none()
    if user is None or not user.is_active:
        await store.destroy(sid)
        raise UNAUTH
    # Changement de mot de passe : toutes les sessions ouvertes avant sont invalides
    if user.password_changed_at is not None and data.created < user.password_changed_at.timestamp():
        await store.destroy(sid)
        raise UNAUTH
    if request.method not in SAFE_METHODS:
        _check_origin_and_csrf(request, data.csrf)
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_ALLOWED:
        # Mot de passe initial/réinitialisé : rien d'autre n'est accessible tant qu'il n'a pas été changé
        raise HTTPException(
            403, "Changement de mot de passe requis", headers={"X-Error-Code": "PASSWORD_CHANGE_REQUIRED"}
        )
    source = "local" if user.issuer == "local" else ("ldap" if user.issuer.startswith("ldap:") else "oidc")
    return Principal(
        kind="user",
        user_id=user.id,
        label=user.email or user.sub,
        role=user.role,
        permissions=ROLE_PERMS[user.role],
        session_hash=session_hash(sid),
        csrf=data.csrf,
        auth_source=source,
        must_change_password=user.must_change_password,
    )


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]


def require(perm: Perm) -> Callable[..., Coroutine[Any, Any, Principal]]:
    async def dep(request: Request, principal: CurrentPrincipal, db: DbSession) -> Principal:
        if perm not in principal.permissions:
            await record(
                db,
                request,
                "authz.denied",
                principal=principal,
                outcome="denied",
                details={"required": perm.value, "path": request.url.path, "method": request.method},
            )
            await db.commit()
            raise HTTPException(403, "Accès refusé")
        return principal

    return dep


async def still_authenticated(request: Request, principal: Principal) -> bool:
    """Revalide en cours de flux (SSE) : session expirée/déconnectée, utilisateur désactivé, token révoqué/expiré."""
    from app.db.session import session_scope

    async with session_scope() as db:
        user = (await db.execute(select(User).where(User.id == principal.user_id))).scalar_one_or_none()
        if user is None or not user.is_active:
            return False
        if principal.kind == "token":
            t = (await db.execute(select(ApiToken).where(ApiToken.id == principal.token_id))).scalar_one_or_none()
            return t is not None and t.revoked_at is None and t.expires_at > datetime.now(UTC)
    sid = request.cookies.get(COOKIE_NAME)
    if not sid:
        return False
    return await request.app.state.sessions.get(sid) is not None
