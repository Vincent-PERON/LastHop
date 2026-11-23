"""Mots de passe du compte local : argon2id, politique de robustesse, verrouillage progressif. Aucun mot de passe clair
n'est jamais journalisé ni stocké."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError

# Paramètres OWASP (argon2id, 64 Mio, 3 itérations) : ~50-100 ms par vérification.
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16, type=Type.ID)
_DUMMY_HASH = _ph.hash("dummy-password-used-to-equalize-timing")

MIN_LENGTH, MAX_LENGTH = 12, 128
LOCK_THRESHOLD = 5  # échecs consécutifs avant verrouillage
LOCK_BASE = timedelta(minutes=15)
LOCK_MAX = timedelta(hours=1)
_COMMON = {
    "password1234",
    "motdepasse12",
    "administrator",
    "azerty123456",
    "qwerty123456",
    "123456789012",
    "changeme1234",
    "admin1234567",
    "letmein12345",
    "welcome12345",
}


class PasswordPolicyError(ValueError):
    """Mot de passe refusé : le message est destiné à l'utilisateur (aucune donnée sensible)."""


def validate_new_password(password: str, username: str) -> None:
    if not (MIN_LENGTH <= len(password) <= MAX_LENGTH):
        raise PasswordPolicyError(f"Le mot de passe doit contenir entre {MIN_LENGTH} et {MAX_LENGTH} caractères.")
    low = password.lower()
    if username and username.lower() in low:
        raise PasswordPolicyError("Le mot de passe ne doit pas contenir l'identifiant.")
    if low in _COMMON or len(set(password)) < 5:
        raise PasswordPolicyError("Mot de passe trop prévisible.")
    if password.strip() != password:
        raise PasswordPolicyError("Le mot de passe ne doit pas commencer ni finir par un espace.")


def hash_password_sync(password: str) -> str:
    return _ph.hash(password)


def _verify_sync(hashed: str | None, password: str) -> bool:
    try:
        # Sans hash on vérifie quand même un hash factice : le temps de réponse ne révèle pas l'existence du compte.
        return _ph.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerificationError, InvalidHashError):
        return False


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(hash_password_sync, password)


async def verify_password(hashed: str | None, password: str) -> bool:
    if len(password) > 1024:  # borne le travail (pas de DoS par mot de passe géant)
        return False
    return await asyncio.to_thread(_verify_sync, hashed, password)


def lock_duration(failed_count: int) -> timedelta | None:
    """Verrouillage progressif : 15 min au 5e échec, puis x2 à chaque échec supplémentaire, plafonné à 1 h."""
    if failed_count < LOCK_THRESHOLD:
        return None
    delay: timedelta = LOCK_BASE * (2 ** min(failed_count - LOCK_THRESHOLD, 6))  # exposant borné
    return min(delay, LOCK_MAX)


def is_locked(locked_until: datetime | None, now: datetime | None = None) -> bool:
    return locked_until is not None and locked_until > (now or datetime.now(UTC))
