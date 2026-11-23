"""Configuration : variables d'environnement, secrets lus depuis des fichiers (Docker secrets)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Literal
from urllib.parse import quote

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _read_secret(path: str | None) -> str | None:
    if not path:
        return None
    return Path(path).read_text(encoding="utf-8").strip()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="LASTHOP_", extra="ignore", env_file=None)

    env: Literal["dev", "prod"] = "prod"

    # --- Réseau / HTTP
    frontend_origin: str = "https://lasthop.example.org"  # unique origine CORS autorisée
    max_body_bytes: int = Field(default=1_048_576, ge=1024, le=20_000_000)

    # --- PostgreSQL (rôle applicatif à moindre privilège)
    db_host: str = "postgres"
    db_port: int = 5432
    db_name: str = "lasthop"
    db_user: str = "lasthop_app"
    db_password_file: str | None = None
    db_ssl_ca_file: str | None = None  # si défini : TLS vérifié

    # --- Redis (ACL, utilisateur dédié)
    redis_host: str = "redis"
    redis_port: int = 6379
    redis_user: str = "lasthop"
    redis_password_file: str | None = None
    redis_tls_ca_file: str | None = None

    # --- OIDC
    oidc_issuer: str = ""
    oidc_client_id: str = "lasthop"
    oidc_client_secret_file: str | None = None
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_groups_claim: str = "groups"
    oidc_admin_groups: list[str] = Field(default_factory=lambda: ["lasthop-admins"])
    oidc_operator_groups: list[str] = Field(default_factory=lambda: ["lasthop-operators"])
    oidc_viewer_groups: list[str] = Field(default_factory=lambda: ["lasthop-viewers"])
    oidc_required_acr: str | None = None  # ex. "mfa" si l'IdP l'expose (défense en profondeur)

    # --- Sessions
    session_idle_seconds: int = Field(default=1800, ge=60)
    session_absolute_seconds: int = Field(default=28800, ge=300)

    # --- Chiffrement (trousseau JSON hors BDD : {"active": "k1", "keys": {"k1": "<b64 32o>"}})
    master_keys_file: str | None = None

    # --- Proxy
    forwarded_allow_ips: str = "127.0.0.1"

    # --- Valeurs dérivées des fichiers de secrets (non lues depuis l'env)
    db_password: str = Field(default="", exclude=True, repr=False)
    redis_password: str = Field(default="", exclude=True, repr=False)
    oidc_client_secret: str = Field(default="", exclude=True, repr=False)
    master_keys: dict[str, bytes] = Field(default_factory=dict, exclude=True, repr=False)
    master_key_active: str = ""

    @field_validator("frontend_origin")
    @classmethod
    def _strict_origin(cls, v: str) -> str:
        if v.strip() == "*" or "*" in v:
            raise ValueError("CORS joker interdit")
        if not (v.startswith("https://") or v.startswith("http://localhost")):
            raise ValueError("frontend_origin doit être https:// (ou http://localhost en dev)")
        return v.rstrip("/")

    @model_validator(mode="after")
    def _load_secrets(self) -> Settings:
        self.db_password = self.db_password or (_read_secret(self.db_password_file) or "")
        self.redis_password = self.redis_password or (_read_secret(self.redis_password_file) or "")
        self.oidc_client_secret = self.oidc_client_secret or (_read_secret(self.oidc_client_secret_file) or "")
        if self.master_keys_file and not self.master_keys:
            import base64

            data = json.loads(Path(self.master_keys_file).read_text(encoding="utf-8"))
            keys = {kid: base64.b64decode(b64) for kid, b64 in data["keys"].items()}
            if any(len(k) != 32 for k in keys.values()):
                raise ValueError("Toutes les clés maîtres doivent faire 32 octets (AES-256)")
            if data["active"] not in keys:
                raise ValueError("Clé active absente du trousseau")
            self.master_keys, self.master_key_active = keys, data["active"]
        if self.env == "prod":
            if not self.oidc_issuer.startswith("https://"):
                raise ValueError("oidc_issuer doit être https:// en production")
            if self.frontend_origin.startswith("http://"):
                raise ValueError("frontend_origin doit être https:// en production")
        return self

    @property
    def database_url(self) -> str:
        pw = quote(self.db_password, safe="")
        return f"postgresql+asyncpg://{self.db_user}:{pw}@{self.db_host}:{self.db_port}/{self.db_name}"

    @property
    def redis_url(self) -> str:
        pw = quote(self.redis_password, safe="")
        scheme = "rediss" if self.redis_tls_ca_file else "redis"
        return f"{scheme}://{self.redis_user}:{pw}@{self.redis_host}:{self.redis_port}/0"


@lru_cache
def get_settings() -> Settings:
    return Settings()
