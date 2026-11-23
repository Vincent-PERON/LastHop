"""Chiffrement/déchiffrement des secrets des profils SNMP. Le déchiffrement n'a lieu que dans le worker."""

from __future__ import annotations

import json
import uuid

from app.db.models import SnmpCredentialRow
from app.security.crypto import KeyRing
from app.snmp.client import SnmpCredential


def _aad(cred_id: uuid.UUID) -> str:
    return f"snmp_credentials:{cred_id}"  # lie le blob à sa ligne : impossible de le copier vers un autre profil


def seal(keyring: KeyRing, cred_id: uuid.UUID, secrets: dict[str, str]) -> tuple[bytes, str]:
    return keyring.encrypt(json.dumps(secrets).encode(), _aad(cred_id)), keyring.active_kid


def unseal(keyring: KeyRing, row: SnmpCredentialRow) -> dict[str, str]:
    data: dict[str, str] = json.loads(keyring.decrypt(row.secret_blob, _aad(row.id)))
    return data


def to_snmp_credential(keyring: KeyRing, row: SnmpCredentialRow) -> SnmpCredential:
    s = unseal(keyring, row)
    if row.version == "v2c":
        return SnmpCredential(version="v2c", community=s.get("community"))
    return SnmpCredential(
        version="v3",
        username=row.v3_username,
        auth_proto=row.auth_proto,
        priv_proto=row.priv_proto,
        auth_key=s.get("auth_key"),
        priv_key=s.get("priv_key"),
    )
