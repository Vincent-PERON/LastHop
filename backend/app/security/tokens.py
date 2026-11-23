"""Tokens d'API : format `lasthop_<prefix>.<secret>`, seul le SHA-256 du secret est stocké."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets

_RE = re.compile(r"^lasthop_([0-9a-f]{8})\.([A-Za-z0-9_-]{43})$")


def generate_token() -> tuple[str, str, bytes]:
    """Retourne (token en clair — affiché une seule fois, préfixe, hash)."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)  # 256 bits -> 43 caractères
    return f"lasthop_{prefix}.{secret}", prefix, hash_secret(secret)


def hash_secret(secret: str) -> bytes:
    # Secret à haute entropie : SHA-256 suffit (pas de besoin d'un KDF lent).
    return hashlib.sha256(secret.encode()).digest()


def parse_token(raw: str) -> tuple[str, str] | None:
    m = _RE.match(raw)
    return (m.group(1), m.group(2)) if m else None


def verify_secret(secret: str, stored_hash: bytes) -> bool:
    return hmac.compare_digest(hash_secret(secret), stored_hash)
