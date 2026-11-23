"""Client OIDC (Authorization Code + PKCE) pour Keycloak / Entra ID. Aucune gestion de mot de passe ici."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any
from urllib.parse import urlencode

import httpx
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet

from app.config import Settings

ALLOWED_ALGS = ["RS256", "PS256", "ES256"]  # liste blanche explicite : jamais "none" ni HS*


class OIDCError(Exception):
    """Erreur d'authentification ; le message n'est jamais renvoyé tel quel à l'utilisateur."""


def new_pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


class OIDCClient:
    def __init__(self, settings: Settings, http: httpx.AsyncClient) -> None:
        self.s, self.http = settings, http
        self._disco: dict[str, Any] | None = None
        self._disco_at = 0.0
        self._jwks: KeySet | None = None
        self._jwks_at = 0.0

    async def discovery(self) -> dict[str, Any]:
        if self._disco is None or time.time() - self._disco_at > 3600:
            url = self.s.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            r = await self.http.get(url)
            r.raise_for_status()
            d = r.json()
            if d.get("issuer", "").rstrip("/") != self.s.oidc_issuer.rstrip("/"):
                raise OIDCError("issuer de découverte incohérent")
            if self.s.env == "prod":
                for k in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                    if not str(d.get(k, "")).startswith("https://"):
                        raise OIDCError(f"{k} non HTTPS")
            self._disco, self._disco_at = d, time.time()
        return self._disco

    async def _keyset(self, force: bool = False) -> KeySet:
        if force or self._jwks is None or time.time() - self._jwks_at > 3600:
            r = await self.http.get((await self.discovery())["jwks_uri"])
            r.raise_for_status()
            self._jwks, self._jwks_at = KeySet.import_key_set(r.json()), time.time()
        return self._jwks

    async def authorization_url(self, state: str, nonce: str, challenge: str) -> str:
        q = {
            "response_type": "code",
            "client_id": self.s.oidc_client_id,
            "redirect_uri": self.s.oidc_redirect_uri,
            "scope": self.s.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        endpoint = str((await self.discovery())["authorization_endpoint"])
        return endpoint + "?" + urlencode(q)

    async def exchange_code(self, code: str, verifier: str) -> str:
        """Retourne l'id_token brut."""
        d = await self.discovery()
        r = await self.http.post(
            d["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.s.oidc_redirect_uri,
                "client_id": self.s.oidc_client_id,
                "client_secret": self.s.oidc_client_secret,
                "code_verifier": verifier,
            },
        )
        if r.status_code != 200:
            raise OIDCError("échange de code refusé")
        id_token: object = r.json().get("id_token")
        if not isinstance(id_token, str):
            raise OIDCError("id_token absent")
        return id_token

    async def verify_id_token(self, id_token: str, nonce: str) -> dict[str, Any]:
        for attempt in (0, 1):  # 2e essai avec rechargement JWKS (rotation de clés de l'IdP)
            try:
                tok = jwt.decode(id_token, await self._keyset(force=bool(attempt)), algorithms=ALLOWED_ALGS)
                break
            except (JoseError, ValueError) as exc:
                if attempt:
                    raise OIDCError("signature invalide") from exc
        claims: dict[str, Any] = dict(tok.claims)
        now = int(time.time())
        if claims.get("iss", "").rstrip("/") != self.s.oidc_issuer.rstrip("/"):
            raise OIDCError("iss invalide")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.s.oidc_client_id not in auds:
            raise OIDCError("aud invalide")
        if len(auds) > 1 and claims.get("azp") != self.s.oidc_client_id:
            raise OIDCError("azp invalide")
        if not isinstance(claims.get("exp"), int | float) or claims["exp"] < now - 30:
            raise OIDCError("jeton expiré")
        if isinstance(claims.get("nbf"), int | float) and claims["nbf"] > now + 30:
            raise OIDCError("jeton pas encore valide")
        if not secrets.compare_digest(str(claims.get("nonce", "")), nonce):
            raise OIDCError("nonce invalide")
        if not claims.get("sub"):
            raise OIDCError("sub absent")
        if self.s.oidc_required_acr and claims.get("acr") != self.s.oidc_required_acr:
            raise OIDCError("niveau d'authentification insuffisant")
        return claims
