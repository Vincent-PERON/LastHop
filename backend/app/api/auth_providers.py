"""Gestion des fournisseurs d'identité (OIDC : Keycloak, Entra ID, Google Workspace ; LDAP direct) — super admin local.

Les secrets (client_secret, mot de passe du compte de service) sont chiffrés (AES-GCM) et ne sont JAMAIS renvoyés."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select

from app.api.auth import oidc_client_for
from app.db.models import AuthProvider
from app.deps import DbSession, require
from app.security import ldap_auth
from app.security.audit import record
from app.security.crypto import keyring_from_settings
from app.security.ratelimit import ip_limiter
from app.security.rbac import Perm, Principal
from app.services.auth_providers import (
    LdapConfig,
    ProviderConfigError,
    open_secret,
    seal_secret,
    validate_config,
    validate_role_map,
)

log = logging.getLogger("lasthop.auth")
router = APIRouter(prefix="/api/v1/auth-providers", tags=["auth-providers"])
Admin = Annotated[Principal, Depends(require(Perm.auth_manage))]
NAME = Annotated[str, Field(min_length=1, max_length=100, pattern=r"^[\w .@()\-]+$")]


class ProviderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["oidc", "ldap"]
    preset: Annotated[str, Field(max_length=16)]
    name: NAME
    enabled: bool = False
    config: dict[str, Any]
    secret: Annotated[str | None, Field(min_length=1, max_length=4096)] = None  # client_secret OIDC / mot de passe LDAP
    role_map: dict[str, str] = {}
    default_role: Literal["viewer", "operator"] | None = None


class ProviderUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preset: Annotated[str | None, Field(max_length=16)] = None
    name: NAME | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None
    secret: Annotated[str | None, Field(min_length=1, max_length=4096)] = None  # absent = secret inchangé
    clear_secret: bool = False
    role_map: dict[str, str] | None = None
    default_role: Literal["viewer", "operator"] | None = None
    clear_default_role: bool = False


def _view(request: Request, p: AuthProvider) -> dict[str, Any]:
    origin = request.app.state.settings.frontend_origin
    return {
        "id": str(p.id),
        "kind": p.kind,
        "preset": p.preset,
        "name": p.name,
        "enabled": p.enabled,
        "config": p.config,
        "has_secret": p.secret_blob is not None,  # le secret lui-même n'est jamais renvoyé
        "role_map": p.role_map,
        "default_role": p.default_role,
        "redirect_uri": origin + "/api/v1/auth/oidc/callback" if p.kind == "oidc" else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _validate(
    request: Request, kind: str, preset: str, config: dict[str, Any], role_map: dict[str, str]
) -> tuple[dict[str, Any], dict[str, str]]:
    try:
        return (
            validate_config(kind, preset, config, env=request.app.state.settings.env),
            validate_role_map(role_map),
        )
    except ProviderConfigError as exc:
        raise HTTPException(422, str(exc)) from None
    except (ValidationError, ValueError):
        raise HTTPException(422, "Configuration invalide") from None


def _check_enable(p: AuthProvider) -> None:
    if not p.enabled:
        return
    if p.kind == "oidc" and p.secret_blob is None:
        raise HTTPException(422, "Un client_secret est requis pour activer ce fournisseur")
    if not p.role_map and not p.default_role:
        raise HTTPException(
            422,
            "Définissez une correspondance de groupe ou un rôle par défaut : sinon personne ne pourrait se connecter",
        )


@router.get("")
async def list_providers(request: Request, db: DbSession, _: Admin) -> list[dict[str, Any]]:
    rows = (await db.execute(select(AuthProvider).order_by(AuthProvider.name))).scalars()
    return [_view(request, r) for r in rows]


@router.post("", status_code=201)
async def create_provider(body: ProviderIn, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    config, role_map = _validate(request, body.kind, body.preset, body.config, body.role_map)
    if (await db.execute(select(AuthProvider.id).where(AuthProvider.name == body.name))).first():
        raise HTTPException(409, "Ce nom est déjà utilisé")
    row = AuthProvider(
        id=uuid.uuid4(),
        kind=body.kind,
        preset=body.preset,
        name=body.name,
        enabled=body.enabled,
        config=config,
        role_map=role_map,
        default_role=body.default_role,
        created_by=p.user_id,
        updated_at=datetime.now(UTC),
    )
    s = request.app.state.settings
    if body.secret:
        row.secret_blob, row.key_id = seal_secret(
            keyring_from_settings(s.master_keys, s.master_key_active), row.id, body.secret
        )
    _check_enable(row)
    db.add(row)
    await record(
        db,
        request,
        "auth_provider.create",
        principal=p,
        target_type="auth_provider",
        target_id=str(row.id),
        details={
            "name": row.name,
            "kind": row.kind,
            "preset": row.preset,
            "enabled": row.enabled,
            "insecure": bool(config.get("insecure")),
        },
    )
    await db.commit()
    return _view(request, row)


async def _get(db: DbSession, provider_id: uuid.UUID) -> AuthProvider:
    row = (await db.execute(select(AuthProvider).where(AuthProvider.id == provider_id))).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "Introuvable")
    return row


@router.put("/{provider_id}")
async def update_provider(
    provider_id: uuid.UUID, body: ProviderUpdate, request: Request, db: DbSession, p: Admin
) -> dict[str, Any]:
    row = await _get(db, provider_id)
    s = request.app.state.settings
    changed: list[str] = []
    if body.name is not None and body.name != row.name:
        if (await db.execute(select(AuthProvider.id).where(AuthProvider.name == body.name))).first():
            raise HTTPException(409, "Ce nom est déjà utilisé")
        row.name = body.name
        changed.append("name")
    preset = body.preset or row.preset
    config, role_map = _validate(
        request,
        row.kind,
        preset,
        body.config if body.config is not None else row.config,
        body.role_map if body.role_map is not None else row.role_map,
    )
    if body.preset is not None:
        row.preset = preset
        changed.append("preset")
    if body.config is not None:
        row.config = config
        changed.append("config")
    if body.role_map is not None:
        row.role_map = role_map
        changed.append("role_map")
    if body.default_role is not None:
        row.default_role = body.default_role
        changed.append("default_role")
    if body.clear_default_role:
        row.default_role = None
        changed.append("default_role")
    if body.secret:
        row.secret_blob, row.key_id = seal_secret(
            keyring_from_settings(s.master_keys, s.master_key_active), row.id, body.secret
        )
        changed.append("secret")
    elif body.clear_secret:
        row.secret_blob, row.key_id = None, None
        changed.append("secret")
    if body.enabled is not None and body.enabled != row.enabled:
        row.enabled = body.enabled
        changed.append("enabled")
    _check_enable(row)
    row.updated_at = datetime.now(UTC)
    request.app.state.oidc.forget(str(row.id))  # le client OIDC (découverte, JWKS) est reconstruit au prochain usage
    await record(
        db,
        request,
        "auth_provider.update",
        principal=p,
        target_type="auth_provider",
        target_id=str(row.id),
        details={"name": row.name, "changed": changed, "enabled": row.enabled},
    )
    await db.commit()
    return _view(request, row)


@router.delete("/{provider_id}", status_code=204)
async def delete_provider(provider_id: uuid.UUID, request: Request, db: DbSession, p: Admin) -> None:
    row = await _get(db, provider_id)
    await db.delete(row)
    request.app.state.oidc.forget(str(row.id))
    await record(
        db,
        request,
        "auth_provider.delete",
        principal=p,
        target_type="auth_provider",
        target_id=str(row.id),
        details={"name": row.name},
    )
    await db.commit()


@router.post("/{provider_id}/test", dependencies=[Depends(ip_limiter("authtest", 20, 60))])
async def test_provider(provider_id: uuid.UUID, request: Request, db: DbSession, p: Admin) -> dict[str, Any]:
    """Contrôle sans connexion d'utilisateur : découverte + clés (OIDC) ; connexion, TLS et compte de service (LDAP)."""
    row = await _get(db, provider_id)
    ok, message = True, ""
    try:
        if row.kind == "oidc":
            client, _ = oidc_client_for(request, row)
            issuer = await client.check()
            message = f"Découverte OIDC réussie ({issuer}) ; clés de signature récupérées."
        else:
            s = request.app.state.settings
            secret = open_secret(keyring_from_settings(s.master_keys, s.master_key_active), row)
            message = await asyncio.to_thread(ldap_auth.check_connection, LdapConfig.model_validate(row.config), secret)
    except ldap_auth.LdapError as exc:
        ok, message = (
            False,
            {
                "unreachable": "Annuaire injoignable, ou négociation TLS impossible (certificat/nom non reconnu ?).",
                "bad_credentials": "Compte de service refusé par l'annuaire (DN ou mot de passe).",
            }.get(exc.code, "Échec de la connexion."),
        )
    except Exception as exc:  # noqa: BLE001 - message générique ; le détail reste dans le journal serveur
        ok, message = False, "Échec : fournisseur injoignable ou réponse invalide (voir les journaux du serveur)."
        log.warning("provider_test_failed", extra={"error": type(exc).__name__, "provider": row.name})
    await record(
        db,
        request,
        "auth_provider.test",
        principal=p,
        target_type="auth_provider",
        target_id=str(row.id),
        outcome="success" if ok else "failure",
        details={"name": row.name},
    )
    await db.commit()
    return {"ok": ok, "message": message}
