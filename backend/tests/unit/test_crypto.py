import os

import pytest

from app.security.crypto import CryptoError, KeyRing


def ring(**keys: bytes) -> KeyRing:
    return KeyRing(keys or {"k1": os.urandom(32)}, active=next(iter(keys or {"k1": 0})))


def test_roundtrip_and_nondeterministic() -> None:
    r = ring()
    a, b = r.encrypt(b"community-secret", "cred:1"), r.encrypt(b"community-secret", "cred:1")
    assert a != b  # nonce aléatoire
    assert r.decrypt(a, "cred:1") == b"community-secret"
    assert b"community-secret" not in a


def test_aad_binding_prevents_blob_swap() -> None:
    r = ring()
    blob = r.encrypt(b"x", "cred:1")
    with pytest.raises(CryptoError):
        r.decrypt(blob, "cred:2")


def test_tamper_and_wrong_key_rejected() -> None:
    r = ring()
    blob = bytearray(r.encrypt(b"x", "a"))
    blob[-1] ^= 1
    with pytest.raises(CryptoError):
        r.decrypt(bytes(blob), "a")
    other = KeyRing({"k1": os.urandom(32)}, "k1")
    with pytest.raises(CryptoError):
        other.decrypt(r.encrypt(b"x", "a"), "a")
    with pytest.raises(CryptoError):
        r.decrypt(b"garbage", "a")


def test_rotation_old_blob_still_readable() -> None:
    k1, k2 = os.urandom(32), os.urandom(32)
    old = KeyRing({"k1": k1}, "k1").encrypt(b"v", "a")
    new = KeyRing({"k1": k1, "k2": k2}, "k2")
    assert new.decrypt(old, "a") == b"v"
    assert new.needs_rotation(old) and not new.needs_rotation(new.encrypt(b"v", "a"))


def test_invalid_key_length_refused() -> None:
    with pytest.raises(CryptoError):
        KeyRing({"k1": b"short"}, "k1")
