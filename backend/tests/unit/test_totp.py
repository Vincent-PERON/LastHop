from app.security import totp

RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"  # « 12345678901234567890 » (annexe B de la RFC 6238)


def test_rfc6238_vectors() -> None:
    # valeurs de la RFC (8 chiffres) : les 6 derniers chiffres sont le code à 6 chiffres
    for t, expected in ((59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")):
        assert totp.code_at(RFC_SECRET, t // 30, digits=8) == expected
        assert totp.code_at(RFC_SECRET, t // 30) == expected[-6:]


def test_verify_window_and_replay_protection() -> None:
    now = 1_700_000_000.0
    step = totp.current_step(now)
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step), None, now) == step
    assert (
        totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), None, now) == step - 1
    )  # dérive d'horloge tolérée
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 1), None, now) == step + 1
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 2), None, now) is None  # trop ancien
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 2), None, now) is None
    # anti-rejeu : un pas déjà accepté (ou antérieur) ne l'est plus
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step), step, now) is None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step - 1), step, now) is None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, step + 1), step, now) == step + 1


def test_malformed_codes_are_refused() -> None:
    now = 1_700_000_000.0
    good = totp.code_at(RFC_SECRET, totp.current_step(now))
    assert totp.verify(RFC_SECRET, good[:3] + " " + good[3:], None, now) is not None  # espace de présentation toléré
    for bad in ("", good[:5], good + "0", "abcdef", "١٢٣٤٥٦", good + "\n"):
        assert totp.verify(RFC_SECRET, bad, None, now) is None, bad


def test_secret_uri_and_qr() -> None:
    s = totp.new_secret()
    assert len(s) == 32 and s != totp.new_secret()  # 160 bits
    uri = totp.provisioning_uri(s, "admin")
    assert uri.startswith("otpauth://totp/LastHop%3Aadmin?secret=") and "issuer=LastHop" in uri and "digits=6" in uri
    qr = totp.qr_data_uri(uri)
    assert qr.startswith("data:image/svg+xml") and "<script" not in qr


def test_recovery_codes() -> None:
    codes = totp.new_recovery_codes()
    assert len(codes) == 10 and len(set(codes)) == 10 and all(len(c) == 10 for c in codes)
    c = codes[0]
    shown = totp.format_recovery(c)
    assert "-" in shown and totp.looks_like_recovery(shown) and totp.looks_like_recovery(shown.lower())
    assert totp.hash_recovery(shown) == totp.hash_recovery(c.lower()) != totp.hash_recovery(codes[1])
    assert not totp.looks_like_recovery("123456")  # un code TOTP n'est pas pris pour un code de secours
