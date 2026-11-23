"""Chiffrement AES-256-GCM des secrets stockés en base.

Enveloppe : b"v1" | len(kid) (1 octet) | kid | nonce (12 o) | ciphertext+tag
L'AAD lie le blob à son contexte (ex. "snmp_credentials:<id>") : un blob copié vers une autre ligne ne se déchiffre pas.
La clé maître vit hors BDD (Docker secret) ; plusieurs `kid` permettent la rotation.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_VERSION = b"v1"


class CryptoError(Exception):
    """Erreur générique volontairement sans détail (pas d'oracle)."""


class KeyRing:
    def __init__(self, keys: dict[str, bytes], active: str) -> None:
        if active not in keys:
            raise CryptoError("clé active inconnue")
        if any(len(k) != 32 for k in keys.values()):
            raise CryptoError("clé invalide")
        self._keys, self._active = keys, active

    @property
    def active_kid(self) -> str:
        return self._active

    def encrypt(self, plaintext: bytes, aad: str) -> bytes:
        kid = self._active.encode()
        nonce = os.urandom(12)
        ct = AESGCM(self._keys[self._active]).encrypt(nonce, plaintext, aad.encode())
        return _VERSION + bytes([len(kid)]) + kid + nonce + ct

    def decrypt(self, blob: bytes, aad: str) -> bytes:
        try:
            if blob[:2] != _VERSION:
                raise CryptoError("format")
            klen = blob[2]
            kid = blob[3 : 3 + klen].decode()
            nonce = blob[3 + klen : 15 + klen]
            ct = blob[15 + klen :]
            return AESGCM(self._keys[kid]).decrypt(nonce, ct, aad.encode())
        except (InvalidTag, KeyError, IndexError, UnicodeDecodeError, CryptoError):
            raise CryptoError("déchiffrement impossible") from None

    def key_id_of(self, blob: bytes) -> str:
        return blob[3 : 3 + blob[2]].decode()

    def needs_rotation(self, blob: bytes) -> bool:
        return self.key_id_of(blob) != self._active


def keyring_from_settings(master_keys: dict[str, bytes], active: str) -> KeyRing:
    if not master_keys:
        raise CryptoError("trousseau de clés non configuré")
    return KeyRing(master_keys, active)
