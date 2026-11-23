"""Authentification OIDC côté serveur (BFF) : /login, /callback, /me, /logout."""

from __future__ import annotations

import json
import logging
import secrets
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from app.db.models import User
from app.deps import CurrentPrincipal, DbSession
from app.security.audit import record
from app.security.oidc import OIDCError, new_pkce
from app.security.ratelimit import ip_limiter
from app.security.rbac import role_from_groups
from app.security.sessions import COOKIE_NAME, LOGIN_COOKIE

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
log = logging.getLogger("lasthop.auth")


def _safe_next(value: str | None) -> str:
    """Anti open-redirect : uniquement un chemin relatif interne."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return "/"
    return value[:512]


def _cookie(response: Response, name: str, value: str, max_age: int) -> None:
    # Préfixe __Host- : Secure, Path=/, pas de Domain. HttpOnly + SameSite=Lax (nécessaire au retour de l'IdP).
    response.set_cookie(name, value, max_age=max_age, secure=True, httponly=True, samesite="lax", path="/")


@router.get("/login", dependencies=[Depends(ip_limiter("login", 20, 60))])
async def login(request: Request, next: str | None = Query(default=None, max_length=512)) -> RedirectResponse:
    oidc, redis = request.app.state.oidc, request.app.state.redis
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    await redis.set(f"oidc:{state}", json.dumps({"n": nonce, "v": verifier, "next": _safe_next(next)}), ex=600)
    resp = RedirectResponse(await oidc.authorization_url(state, nonce, challenge), status_code=302)
    _cookie(resp, LOGIN_COOKIE, state, 600)  # lie le flux au navigateur initiateur (anti login-CSRF)
    return resp


@router.get("/callback", dependencies=[Depends(ip_limiter("callback", 30, 60))])
async def callback(
    request: Request,
    db: DbSession,
    code: str | None = Query(default=None, max_length=2048),
    state: str | None = Query(default=None, max_length=128),
    error: str | None = Query(default=None, max_length=128),
) -> Response:
    app = request.app
    s = app.state.settings
    redis = app.state.redis
    bound = request.cookies.get(LOGIN_COOKIE)

    async def deny(reason: str, label: str | None = None, status: int = 401) -> HTTPException:
        await record(
            db,
            request,
            "auth.login",
            actor_type="anonymous",
            actor_label=label,
            outcome="failure",
            details={"reason": reason},
        )
        await db.commit()
        return HTTPException(status, "Authentification refusée")

    if error or not code or not state or not bound or not secrets.compare_digest(bound, state):
        raise await deny("invalid_request")
    raw = await redis.getdel(f"oidc:{state}")  # usage unique
    if raw is None:
        raise await deny("unknown_state")
    flow: dict[str, Any] = json.loads(raw)

    try:
        id_token = await app.state.oidc.exchange_code(code, flow["v"])
        claims = await app.state.oidc.verify_id_token(id_token, flow["n"])
    except (OIDCError, Exception) as exc:  # noqa: BLE001 - tout échec = refus, détail uniquement dans les logs
        log.warning("oidc_failure", extra={"error": type(exc).__name__})
        raise await deny("token_validation_failed") from None

    groups = claims.get(s.oidc_groups_claim) or []
    role = role_from_groups(
        [g for g in groups if isinstance(g, str)] if isinstance(groups, list) else [],
        s.oidc_admin_groups,
        s.oidc_operator_groups,
        s.oidc_viewer_groups,
    )
    label = claims.get("email") or claims["sub"]
    if role is None:
        raise await deny("no_mapped_group", label=str(label), status=403)  # refus par défaut

    iss = claims["iss"].rstrip("/")
    user = (await db.execute(select(User).where(User.issuer == iss, User.sub == claims["sub"]))).scalar_one_or_none()
    if user is None:
        user = User(issuer=iss, sub=claims["sub"], role=role)
        db.add(user)
    if not user.is_active and user.id is not None:
        raise await deny("user_disabled", label=str(label), status=403)
    user.role = role  # le rôle est toujours recalculé depuis l'IdP
    user.email = str(claims.get("email"))[:320] if claims.get("email") else None
    user.display_name = str(claims.get("name"))[:255] if claims.get("name") else None
    user.last_login_at = datetime.now(UTC)
    await db.flush()

    sid, _ = await app.state.sessions.create(user.id)
    await record(
        db,
        request,
        "auth.login",
        actor_type="user",
        actor_label=str(label),
        target_type="user",
        target_id=str(user.id),
        details={"role": role.value},
    )
    await db.commit()

    resp = RedirectResponse(s.frontend_origin + _safe_next(flow.get("next")), status_code=302)
    _cookie(resp, COOKIE_NAME, sid, s.session_absolute_seconds)
    resp.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return resp


@router.get("/me")
async def me(principal: CurrentPrincipal) -> dict[str, Any]:
    return {
        "user_id": str(principal.user_id),
        "label": principal.label,
        "role": principal.role.value,
        "permissions": sorted(p.value for p in principal.permissions),
        "csrf_token": principal.csrf,  # None pour un token d'API
    }


@router.post("/logout")
async def logout(request: Request, response: Response, principal: CurrentPrincipal, db: DbSession) -> dict[str, Any]:
    if principal.kind != "user":
        raise HTTPException(400, "Logout réservé aux sessions")
    sid = request.cookies.get(COOKIE_NAME)
    if sid:
        await request.app.state.sessions.destroy(sid)
    await record(db, request, "auth.logout", principal=principal)
    await db.commit()
    response.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="lax")
    return {"status": "logged_out"}
