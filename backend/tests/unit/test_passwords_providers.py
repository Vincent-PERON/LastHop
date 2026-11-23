import pytest

from app.security.passwords import (
    LOCK_BASE,
    LOCK_MAX,
    PasswordPolicyError,
    hash_password_sync,
    lock_duration,
    validate_new_password,
    verify_password,
)
from app.services.auth_providers import (
    ProviderConfigError,
    check_host,
    resolve_role,
    validate_config,
    validate_role_map,
)


def test_password_policy() -> None:
    validate_new_password("Une-Passphrase-Correcte-9", "admin")
    for bad in ("court", "a" * 12, "admin-passphrase-12", "motdepasse12", " espace-au-debut-12", "x" * 129):
        with pytest.raises(PasswordPolicyError):
            validate_new_password(bad, "admin")


async def test_hash_is_argon2id_salted_and_verified() -> None:
    h1, h2 = hash_password_sync("Une-Passphrase-Correcte-9"), hash_password_sync("Une-Passphrase-Correcte-9")
    assert h1.startswith("$argon2id$") and h1 != h2  # sel aléatoire
    assert await verify_password(h1, "Une-Passphrase-Correcte-9")
    assert not await verify_password(h1, "autre")
    assert not await verify_password(None, "Une-Passphrase-Correcte-9")  # compte inexistant : faux, sans exception
    assert not await verify_password(h1, "x" * 2000)  # borne anti-DoS


def test_lock_duration_is_progressive_and_capped() -> None:
    assert [lock_duration(n) for n in range(1, 5)] == [None] * 4
    assert lock_duration(5) == LOCK_BASE and lock_duration(6) == LOCK_BASE * 2
    assert lock_duration(50) == LOCK_MAX


def test_role_map_refuses_admin_and_resolve_never_returns_it() -> None:
    assert validate_role_map({"g": "operator"}) == {"g": "operator"}
    with pytest.raises(ProviderConfigError):
        validate_role_map({"g": "admin"})
    assert resolve_role({"g": "viewer"}, "operator", ["x"]).value == "operator"  # type: ignore[union-attr]


def test_ssrf_host_rules() -> None:
    for bad in ("169.254.169.254", "0.0.0.0", "224.0.0.1", "bad host!", "-x.example"):  # noqa: S104
        with pytest.raises(ProviderConfigError):
            check_host(bad, "prod")
    with pytest.raises(ProviderConfigError):
        check_host("localhost", "prod")
    with pytest.raises(ProviderConfigError):
        check_host("127.0.0.1", "prod")
    check_host("127.0.0.1", "dev")
    check_host("keycloak.corp.local", "prod")
    check_host("10.0.0.5", "prod")  # un annuaire interne est un cas normal


GOOD_OIDC = {"issuer": "https://kc.example.org/realms/lab", "client_id": "lasthop"}


def test_oidc_config_validation_and_presets() -> None:
    assert validate_config("oidc", "keycloak", GOOD_OIDC, env="prod")["scopes"] == "openid profile email"
    for cfg in (
        {**GOOD_OIDC, "issuer": "http://kc.example.org/realms/lab"},  # http refusé en prod
        {**GOOD_OIDC, "issuer": "https://user:pw@kc.example.org/"},  # identifiants dans l'URL
        {**GOOD_OIDC, "issuer": "https://169.254.169.254/"},
        {**GOOD_OIDC, "scopes": "profile email"},  # openid manquant
        {**GOOD_OIDC, "extra": 1},
        {"client_id": "x"},
    ):
        with pytest.raises((ProviderConfigError, ValueError)):
            validate_config("oidc", "generic", cfg, env="prod")
    # Google : domaine Workspace obligatoire (sinon n'importe quel compte Google entrerait), e-mail vérifié forcé
    g = {"issuer": "https://accounts.google.com", "client_id": "x.apps.googleusercontent.com"}
    with pytest.raises(ProviderConfigError):
        validate_config("oidc", "google", g, env="prod")
    out = validate_config("oidc", "google", {**g, "allowed_domains": ["Corp.Example.COM"]}, env="prod")
    assert out["allowed_domains"] == ["corp.example.com"] and out["require_email_verified"] is True
    with pytest.raises(ProviderConfigError):
        validate_config(
            "oidc", "google", {**g, "issuer": "https://evil.example", "allowed_domains": ["a.com"]}, env="prod"
        )
    tenant = "12345678-1234-1234-1234-123456789abc"
    validate_config(
        "oidc", "entra", {**GOOD_OIDC, "issuer": f"https://login.microsoftonline.com/{tenant}/v2.0"}, env="prod"
    )
    with pytest.raises(ProviderConfigError):
        validate_config(
            "oidc", "entra", {**GOOD_OIDC, "issuer": "https://login.microsoftonline.com/common/v2.0"}, env="prod"
        )


GOOD_LDAP = {"url": "ldaps://ldap.corp.example:636", "user_base": "ou=people,dc=corp,dc=example"}


def test_ldap_config_validation() -> None:
    assert validate_config("ldap", "ldap", GOOD_LDAP, env="prod")["user_filter"] == "(uid={username})"
    # connexion en clair : refusée sauf reconnaissance explicite
    plain = {**GOOD_LDAP, "url": "ldap://ldap.corp.example"}
    with pytest.raises(ProviderConfigError):
        validate_config("ldap", "ldap", plain, env="prod")
    assert validate_config("ldap", "ldap", {**plain, "starttls": True}, env="prod")["insecure"] is False
    assert validate_config("ldap", "ldap", {**plain, "insecure": True}, env="prod")["insecure"] is True
    with pytest.raises(ProviderConfigError):
        validate_config("ldap", "ldap", {**GOOD_LDAP, "starttls": True}, env="prod")  # StartTLS + ldaps
    for bad in (
        {**GOOD_LDAP, "user_filter": "(uid=x)"},  # sans {username}
        {**GOOD_LDAP, "user_filter": "uid={username}"},  # sans parenthèses
        {**GOOD_LDAP, "user_filter": "(|(uid={username})(cn={username}))"},  # {username} deux fois
        {**GOOD_LDAP, "ca_pem": "-----BEGIN PRIVATE KEY-----"},
        {**GOOD_LDAP, "url": "http://ldap.corp.example"},
        {**GOOD_LDAP, "url": "ldaps://169.254.169.254"},
        {**GOOD_LDAP, "group_filter": "(member=x)"},
    ):
        with pytest.raises((ProviderConfigError, ValueError)):
            validate_config("ldap", "ldap", bad, env="prod")
