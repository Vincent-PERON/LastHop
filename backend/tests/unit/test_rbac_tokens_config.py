import pytest
from pydantic import ValidationError

from app.config import Settings
from app.db.models import Role
from app.security import tokens as tok
from app.security.rbac import TOKEN_SCOPES, Perm, token_permissions
from app.services.auth_providers import resolve_role
from app.worker.celery_app import celery_app


def test_role_mapping_highest_wins_and_default_deny() -> None:
    m = {"ops": "operator", "view": "viewer"}
    assert resolve_role(m, None, ["view", "ops"]) == Role.operator
    assert resolve_role(m, None, ["VIEW"]) == Role.viewer  # insensible à la casse
    assert resolve_role(m, None, ["other"]) is None and resolve_role(m, None, []) is None
    assert resolve_role(m, "viewer", ["other"]) == Role.viewer  # rôle par défaut du fournisseur
    assert resolve_role({"adm": "admin"}, None, ["adm"]) is None  # « admin » n'est jamais attribuable par un groupe


def test_token_permissions_capped_by_owner_role() -> None:
    assert token_permissions(["read", "realtime"], Role.viewer) == frozenset()
    assert token_permissions(["topology", "search", "realtime"], Role.viewer) == {Perm.topology_read, Perm.search}
    assert Perm.realtime in token_permissions(["realtime"], Role.operator)
    assert Perm.realtime in token_permissions(["realtime"], Role.admin)
    assert token_permissions(["admin"], Role.admin) == frozenset()  # portée inconnue = rien


def test_token_format_and_hash() -> None:
    plain, prefix, h = tok.generate_token()
    parsed = tok.parse_token(plain)
    assert parsed and parsed[0] == prefix and tok.verify_secret(parsed[1], h)
    assert not tok.verify_secret("x" * 43, h)
    assert tok.parse_token("lasthop_zz.bad") is None and tok.parse_token("Bearer x") is None


def test_cors_wildcard_and_http_prod_refused() -> None:
    with pytest.raises(ValidationError):
        Settings(env="dev", frontend_origin="*")
    with pytest.raises(ValidationError):
        Settings(env="prod", frontend_origin="http://localhost")


def test_celery_json_only_no_pickle() -> None:
    assert celery_app.conf.accept_content == ["json"]
    assert celery_app.conf.task_serializer == "json" and celery_app.conf.result_serializer == "json"


def test_non_admin_roles_are_limited_to_search_and_topology() -> None:
    from app.security.rbac import ROLE_PERMS

    assert ROLE_PERMS[Role.viewer] == {Perm.search, Perm.topology_read}
    assert ROLE_PERMS[Role.operator] == {Perm.search, Perm.topology_read, Perm.realtime, Perm.export}
    for p in (
        Perm.tokens_manage,
        Perm.auth_manage,
        Perm.backups_read,
        Perm.backups_run,
        Perm.credentials_write,
        Perm.settings_write,
        Perm.audit_read,
        Perm.inventory_read,
        Perm.inventory_write,
    ):
        assert p not in ROLE_PERMS[Role.operator] and p in ROLE_PERMS[Role.admin]
    assert not any(Perm.tokens_manage in perms for perms in TOKEN_SCOPES.values())  # jamais délégable à un token
