"""TOTP (RFC 6238) du compte super admin local, sans dépendance : HMAC-SHA1, pas de 30 s, 6 chiffres, tolérance ±1 pas.

Protections : comparaison à temps constant, **anti-rejeu** (un pas déjà accepté ne l'est plus), codes de secours à usage
unique stockés hachés. Le secret est chiffré en base (AES-GCM) par l'appelant."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6
WINDOW = 1  # un pas avant / après (dérive d'horloge de l'appareil)
RECOVERY_COUNT = 10
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # sans 0/O/1/I : lisible et dictable


def new_secret() -> str:
    """Secret de 160 bits (recommandation RFC 4226), en base32 sans remplissage."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _key(secret_b32: str) -> bytes:
    return base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)


def code_at(secret_b32: str, step: int, digits: int = DIGITS) -> str:
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(value).zfill(digits)


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // STEP_SECONDS)


def verify(secret_b32: str, code: str, last_step: int | None, now: float | None = None) -> int | None:
    """Retourne le pas accepté (à enregistrer), ou None. Refuse tout pas ≤ `last_step` (rejeu)."""
    candidate = code.replace(" ", "")
    if len(candidate) != DIGITS or not candidate.isascii() or not candidate.isdigit():
        return None
    now_step = current_step(now)
    accepted: int | None = None
    for step in range(
        now_step - WINDOW, now_step + WINDOW + 1
    ):  # toutes les valeurs sont comparées (pas de sortie anticipée)
        if hmac.compare_digest(code_at(secret_b32, step), candidate) and (last_step is None or step > last_step):
            accepted = step if accepted is None else accepted
    return accepted


def provisioning_uri(secret_b32: str, account: str, issuer: str = "LastHop") -> str:
    label = quote(f"{issuer}:{account}", safe="")
    params = f"secret={secret_b32}&issuer={quote(issuer, safe='')}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    return f"otpauth://totp/{label}?{params}"


def qr_data_uri(uri: str) -> str:
    import segno

    return str(segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#02213d"))


# --- codes de secours (usage unique)
def new_recovery_codes() -> list[str]:
    return ["".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(10)) for _ in range(RECOVERY_COUNT)]


def format_recovery(code: str) -> str:
    return f"{code[:5]}-{code[5:]}"


def normalize_recovery(value: str) -> str:
    return value.replace("-", "").replace(" ", "").upper()


def hash_recovery(code: str) -> str:
    # Codes aléatoires (~50 bits) à usage unique : SHA-256 suffit (pas de mot de passe humain à deviner)
    return hashlib.sha256(normalize_recovery(code).encode()).hexdigest()


def looks_like_recovery(value: str) -> bool:
    n = normalize_recovery(value)
    return len(n) == 10 and all(c in _RECOVERY_ALPHABET for c in n)
