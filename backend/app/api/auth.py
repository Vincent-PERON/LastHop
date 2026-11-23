"""Authentification : compte super admin local, OIDC (Keycloak, Entra ID, Google Workspace…) et LDAP direct.

Session côté serveur (BFF) : cookie `__Host-` HttpOnly, jeton CSRF, aucune donnée d'authentification dans le navigateur
hors ce cookie. Les connexions POST (local, LDAP) exigent l'en-tête Origin de l'application (anti login-CSRF)."""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.db.models import LOCAL_ISSUER, AuthProvider, Role, User
from app.deps import CurrentPrincipal, DbSession
from app.security import ldap_auth
from app.security.audit import record
from app.security.crypto import KeyRing, keyring_from_settings
from app.security.oidc import OIDCError, OidcParams, check_identity_policy, extract_groups, new_pkce
from app.security.passwords import (
    PasswordPolicyError,
    hash_password,
    is_locked,
    lock_duration,
    validate_new_password,
    verify_password,
)
from app.security.ratelimit import hit, ip_limiter
from app.security.sessions import COOKIE_NAME, LOGIN_COOKIE
from app.services import totp_service
from app.services.auth_providers import LdapConfig, open_secret, resolve_role

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
log = logging.getLogger("lasthop.auth")
GENERIC_DENIAL = "Authentification refusée"
LDAP_FAILURES_PER_15MIN = 10


def _safe_next(value: str | None) -> str:
    """Anti open-redirect : uniquement un chemin relatif interne."""
    if not value or not value.startswith("/") or value.startswith("//") or "\\" in value or "\n" in value:
        return "/"
    return value[:512]


def _cookie(response: Response, name: str, value: str, max_age: int) -> None:
    # Préfixe __Host- : Secure, Path=/, pas de Domain. HttpOnly + SameSite=Lax (nécessaire au retour de l'IdP).
    response.set_cookie(name, value, max_age=max_age, secure=True, httponly=True, samesite="lax", path="/")


def _keyring(request: Request) -> KeyRing:
    s = request.app.state.settings
    return keyring_from_settings(s.master_keys, s.master_key_active)


def _require_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is None or origin.rstrip("/") != request.app.state.settings.frontend_origin:
        raise HTTPException(403, "Origine refusée")


async def _deny(
    db: DbSession,
    request: Request,
    reason: str,
    *,
    provider: str | None = None,
    label: str | None = None,
    status: int = 401,
) -> HTTPException:
    await record(
        db,
        request,
        "auth.login",
        actor_type="anonymous",
        actor_label=label,
        outcome="failure",
        details={"reason": reason, **({"provider": provider} if provider else {})},
    )
    await db.commit()
    return HTTPException(status, GENERIC_DENIAL)


async def _provider(db: DbSession, provider_id: str, kind: str) -> AuthProvider:
    try:
        pid = uuid.UUID(provider_id)
    except ValueError:
        raise HTTPException(404, "Introuvable") from None
    row = (await db.execute(select(AuthProvider).where(AuthProvider.id == pid))).scalar_one_or_none()
    if row is None or row.kind != kind or not row.enabled:
        raise HTTPException(404, "Introuvable")  # un fournisseur désactivé n'existe pas pour l'extérieur
    return row


async def _login_federated(
    db: DbSession,
    request: Request,
    provider: AuthProvider,
    *,
    issuer: str,
    sub: str,
    groups: list[str],
    email: str | None,
    name: str | None,
    label: str,
) -> tuple[str, Role]:
    """Crée/met à jour l'utilisateur fédéré (rôle recalculé à chaque connexion, jamais admin) et ouvre la session."""
    role = resolve_role(provider.role_map, provider.default_role, groups)
    if role is None:
        raise await _deny(db, request, "no_mapped_group", provider=provider.name, label=label, status=403)
    user = (await db.execute(select(User).where(User.issuer == issuer, User.sub == sub))).scalar_one_or_none()
    if user is not None and not user.is_active:
        raise await _deny(db, request, "user_disabled", provider=provider.name, label=label, status=403)
    if user is None:
        user = User(issuer=issuer, sub=sub, role=role)
        db.add(user)
    user.role = role
    user.email = email[:320] if email else None
    user.display_name = name[:255] if name else None
    user.last_login_at = datetime.now(UTC)
    await db.flush()
    sid, _ = await request.app.state.sessions.create(user.id)
    await record(
        db,
        request,
        "auth.login",
        actor_type="user",
        actor_label=label,
        target_type="user",
        target_id=str(user.id),
        details={"role": role.value, "provider": provider.name},
    )
    await db.commit()
    return sid, role


# ---------------------------------------------------------------- fournisseurs affichés sur la page de connexion
@router.get("/providers", dependencies=[Depends(ip_limiter("providers", 60, 60))])
async def public_providers(db: DbSession) -> dict[str, Any]:
    rows = (
        (await db.execute(select(AuthProvider).where(AuthProvider.enabled.is_(True)).order_by(AuthProvider.name)))
        .scalars()
        .all()
    )
    return {
        "local": True,
        "providers": [{"id": str(r.id), "name": r.name, "kind": r.kind, "preset": r.preset} for r in rows],
    }


# ---------------------------------------------------------------- compte local
class LocalLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")]
    password: Annotated[str, Field(min_length=1, max_length=1024)]


@router.post("/local/login", dependencies=[Depends(ip_limiter("login", 20, 60))])
async def local_login(body: LocalLogin, request: Request, db: DbSession) -> JSONResponse:
    _require_origin(request)
    username = body.username.strip().lower()
    user = (
        await db.execute(select(User).where(User.issuer == LOCAL_ISSUER, User.sub == username))
    ).scalar_one_or_none()
    now = datetime.now(UTC)
    locked = user is not None and is_locked(user.locked_until, now)
    # Une vérification est toujours faite (hash factice si le compte n'existe pas) : temps de réponse constant.
    valid = await verify_password(user.password_hash if user and user.is_active and not locked else None, body.password)
    if user is None or not user.is_active or locked or not valid:
        if user is not None and user.is_active and not locked:
            register_failure(user, now)
        reason = "locked" if locked else "bad_credentials"
        raise await _deny(db, request, reason, provider="local", label=username)

    if user.totp_enabled:
        # Mot de passe correct mais second facteur requis : aucun cookie de session, seulement un défi à usage limité
        challenge = await totp_service.create_challenge(request.app.state.redis, user.id)
        await record(
            db,
            request,
            "auth.login_password",
            actor_type="anonymous",
            actor_label=username,
            details={"provider": "local", "totp": "required"},
        )
        await db.commit()
        return JSONResponse({"status": "totp_required", "challenge": challenge})
    return await open_local_session(db, request, user, now)


def register_failure(user: User, now: datetime) -> None:
    """Échec d'authentification du compte local (mot de passe OU second facteur) : compteur et verrouillage."""
    user.failed_login_count += 1
    delay = lock_duration(user.failed_login_count)
    if delay is not None:
        user.locked_until = now + delay


async def open_local_session(
    db: DbSession, request: Request, user: User, now: datetime, *, second_factor: str | None = None
) -> JSONResponse:
    user.failed_login_count, user.locked_until, user.last_login_at = 0, None, now
    sid, _ = await request.app.state.sessions.create(user.id)
    await record(
        db,
        request,
        "auth.login",
        actor_type="user",
        actor_label=user.sub,
        target_type="user",
        target_id=str(user.id),
        details={
            "role": user.role.value,
            "provider": "local",
            **({"second_factor": second_factor} if second_factor else {}),
        },
    )
    await db.commit()
    resp = JSONResponse({"status": "ok", "must_change_password": user.must_change_password})
    _cookie(resp, COOKIE_NAME, sid, request.app.state.settings.session_absolute_seconds)
    return resp


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: Annotated[str, Field(min_length=1, max_length=1024)]
    new_password: Annotated[str, Field(min_length=1, max_length=1024)]


@router.post("/password", dependencies=[Depends(ip_limiter("pwchange", 10, 300))])
async def change_password(body: PasswordChange, request: Request, p: CurrentPrincipal, db: DbSession) -> JSONResponse:
    if p.kind != "user":
        raise HTTPException(403, "Réservé aux sessions")
    user = (await db.execute(select(User).where(User.id == p.user_id))).scalar_one()
    if user.issuer != LOCAL_ISSUER or user.password_hash is None:
        raise HTTPException(400, "Le mot de passe de ce compte est géré par son fournisseur d'identité")
    if not await verify_password(user.password_hash, body.current_password):
        await record(
            db, request, "auth.password_change", principal=p, outcome="failure", details={"reason": "bad_current"}
        )
        await db.commit()
        raise HTTPException(403, "Mot de passe actuel incorrect")
    try:
        validate_new_password(body.new_password, user.sub)
    except PasswordPolicyError as exc:
        raise HTTPException(422, str(exc)) from None
    if body.new_password == body.current_password:
        raise HTTPException(422, "Le nouveau mot de passe doit être différent de l'ancien.")
    user.password_hash = await hash_password(body.new_password)
    user.must_change_password = False
    user.failed_login_count, user.locked_until = 0, None
    user.password_changed_at = datetime.now(UTC)  # invalide toutes les sessions antérieures de ce compte
    await record(db, request, "auth.password_change", principal=p)
    await db.commit()
    store = request.app.state.sessions
    old = request.cookies.get(COOKIE_NAME)
    if old:
        await store.destroy(old)
    sid, data = await store.create(user.id)
    resp = JSONResponse({"status": "ok", "csrf_token": data.csrf})
    _cookie(resp, COOKIE_NAME, sid, request.app.state.settings.session_absolute_seconds)
    return resp


# ---------------------------------------------------------------- LDAP direct
class LdapLogin(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._@-]+$")]
    password: Annotated[str, Field(min_length=1, max_length=512)]


@router.post("/ldap/{provider_id}/login", dependencies=[Depends(ip_limiter("login", 20, 60))])
async def ldap_login(provider_id: str, body: LdapLogin, request: Request, db: DbSession) -> JSONResponse:
    _require_origin(request)
    provider = await _provider(db, provider_id, "ldap")
    username = body.username.strip()
    redis = request.app.state.redis
    bucket = f"ldapfail:{provider.id}:{username.lower()}"
    if (
        int(await redis.get(f"rl:{bucket}") or 0) >= LDAP_FAILURES_PER_15MIN
    ):  # protège aussi l'annuaire (verrouillage AD)
        raise HTTPException(429, "Trop de tentatives, réessayez plus tard", headers={"Retry-After": "900"})
    cfg = LdapConfig.model_validate(provider.config)
    try:
        bind_pw = open_secret(_keyring(request), provider)
        ident = await asyncio.to_thread(ldap_auth.authenticate, cfg, bind_pw, username, body.password)
    except ldap_auth.LdapError as exc:
        if exc.code in ("bad_credentials", "not_found", "ambiguous", "invalid_input"):
            await hit(redis, bucket, LDAP_FAILURES_PER_15MIN, 900)
        log.warning("ldap_login_failed", extra={"code": exc.code, "provider": provider.name})
        raise await _deny(db, request, f"ldap_{exc.code}", provider=provider.name, label=username) from None
    except Exception as exc:  # noqa: BLE001 - tout échec = refus, détail uniquement dans les logs
        log.warning("ldap_login_error", extra={"error": type(exc).__name__, "provider": provider.name})
        raise await _deny(db, request, "ldap_error", provider=provider.name, label=username) from None
    sid, role = await _login_federated(
        db,
        request,
        provider,
        issuer=f"ldap:{provider.id}",
        sub=ident.uid,
        groups=ident.groups,
        email=ident.email,
        name=ident.display_name,
        label=ident.email or username,
    )
    resp = JSONResponse({"status": "ok", "role": role.value})
    _cookie(resp, COOKIE_NAME, sid, request.app.state.settings.session_absolute_seconds)
    return resp


# ---------------------------------------------------------------- OIDC
def oidc_client_for(request: Request, provider: AuthProvider) -> tuple[Any, OidcParams]:
    s = request.app.state.settings
    cfg = provider.config
    secret = open_secret(_keyring(request), provider) or ""
    params = OidcParams(
        issuer=cfg["issuer"],
        client_id=cfg["client_id"],
        client_secret=secret,
        redirect_uri=s.frontend_origin + "/api/v1/auth/oidc/callback",
        env=s.env,
        scopes=cfg.get("scopes", "openid profile email"),
        groups_claim=cfg.get("groups_claim", "groups"),
        allowed_domains=tuple(cfg.get("allowed_domains", [])),
        require_email_verified=bool(cfg.get("require_email_verified", False)),
        required_acr=cfg.get("required_acr"),
        preset=provider.preset,
    )
    return request.app.state.oidc.get(str(provider.id), params), params


@router.get("/oidc/{provider_id}/login", dependencies=[Depends(ip_limiter("login", 20, 60))])
async def oidc_login(
    provider_id: str, request: Request, db: DbSession, next: str | None = Query(default=None, max_length=512)
) -> RedirectResponse:
    provider = await _provider(db, provider_id, "oidc")
    client, _ = oidc_client_for(request, provider)
    redis = request.app.state.redis
    state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    verifier, challenge = new_pkce()
    await redis.set(
        f"oidc:{state}",
        json.dumps({"p": str(provider.id), "n": nonce, "v": verifier, "next": _safe_next(next)}),
        ex=600,
    )
    try:
        url = await client.authorization_url(state, nonce, challenge)
    except Exception as exc:  # noqa: BLE001 - IdP injoignable / configuration invalide
        log.warning("oidc_discovery_failed", extra={"error": type(exc).__name__, "provider": provider.name})
        raise HTTPException(502, "Fournisseur d'identité indisponible") from None
    resp = RedirectResponse(url, status_code=302)
    _cookie(resp, LOGIN_COOKIE, state, 600)  # lie le flux au navigateur initiateur (anti login-CSRF)
    return resp


@router.get("/oidc/callback", dependencies=[Depends(ip_limiter("callback", 30, 60))])
async def oidc_callback(
    request: Request,
    db: DbSession,
    code: str | None = Query(default=None, max_length=2048),
    state: str | None = Query(default=None, max_length=128),
    error: str | None = Query(default=None, max_length=128),
) -> Response:
    app = request.app
    s = app.state.settings
    bound = request.cookies.get(LOGIN_COOKIE)
    if error or not code or not state or not bound or not secrets.compare_digest(bound, state):
        raise await _deny(db, request, "invalid_request")
    raw = await app.state.redis.getdel(f"oidc:{state}")  # usage unique
    if raw is None:
        raise await _deny(db, request, "unknown_state")
    flow: dict[str, Any] = json.loads(raw)
    try:
        provider = await _provider(db, flow["p"], "oidc")
    except HTTPException:
        raise await _deny(db, request, "provider_unavailable") from None

    client, params = oidc_client_for(request, provider)
    try:
        id_token = await client.exchange_code(code, flow["v"])
        claims = await client.verify_id_token(id_token, flow["n"])
        check_identity_policy(params, claims)
    except (OIDCError, Exception) as exc:  # noqa: BLE001 - tout échec = refus, détail uniquement dans les logs
        log.warning("oidc_failure", extra={"error": type(exc).__name__, "provider": provider.name})
        raise await _deny(db, request, "token_validation_failed", provider=provider.name) from None

    email = str(claims["email"]) if claims.get("email") else None
    sid, _ = await _login_federated(
        db,
        request,
        provider,
        issuer=claims["iss"].rstrip("/"),
        sub=str(claims["sub"]),
        groups=extract_groups(claims, params.groups_claim),
        email=email,
        name=str(claims["name"]) if claims.get("name") else None,
        label=email or str(claims["sub"]),
    )
    resp = RedirectResponse(s.frontend_origin + _safe_next(flow.get("next")), status_code=302)
    _cookie(resp, COOKIE_NAME, sid, s.session_absolute_seconds)
    resp.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
    return resp


# ---------------------------------------------------------------- session
@router.get("/me")
async def me(principal: CurrentPrincipal) -> dict[str, Any]:
    return {
        "user_id": str(principal.user_id),
        "label": principal.label,
        "role": principal.role.value,
        "permissions": sorted(p.value for p in principal.permissions),
        "csrf_token": principal.csrf,  # None pour un token d'API
        "auth_source": principal.auth_source,
        "must_change_password": principal.must_change_password,
        "totp_enabled": principal.totp_enabled,
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
