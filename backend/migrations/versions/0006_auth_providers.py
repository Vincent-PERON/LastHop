"""Authentification : compte local, fournisseurs OIDC/LDAP configurables

Revision ID: 0006
Revises: 0005
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("password_hash", sa.Text))
    op.add_column("users", sa.Column("must_change_password", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("users", sa.Column("failed_login_count", sa.Integer, nullable=False, server_default="0"))
    op.add_column("users", sa.Column("locked_until", sa.DateTime(timezone=True)))
    op.add_column("users", sa.Column("password_changed_at", sa.DateTime(timezone=True)))
    # Seul le compte local peut être super admin : les comptes IdP/LDAP existants sont rétrogradés, puis la règle est
    # imposée par la base elle-même (une erreur de code ne peut pas créer un super admin fédéré).
    op.execute("UPDATE users SET role = 'operator' WHERE role = 'admin' AND issuer <> 'local'")
    op.create_check_constraint("ck_users_admin_is_local", "users", "role <> 'admin' OR issuer = 'local'")
    op.create_check_constraint("ck_users_password_only_local", "users", "password_hash IS NULL OR issuer = 'local'")

    op.create_table(
        "auth_providers",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("preset", sa.String(16), nullable=False),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("config", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("secret_blob", sa.LargeBinary),
        sa.Column("key_id", sa.String(64)),
        sa.Column("role_map", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("default_role", sa.String(16)),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('oidc','ldap')", name="ck_authprov_kind"),
        sa.CheckConstraint(
            "default_role IS NULL OR default_role IN ('viewer','operator')", name="ck_authprov_default_role"
        ),
    )


def downgrade() -> None:
    op.drop_table("auth_providers")
    op.drop_constraint("ck_users_password_only_local", "users")
    op.drop_constraint("ck_users_admin_is_local", "users")
    for c in ("password_changed_at", "locked_until", "failed_login_count", "must_change_password", "password_hash"):
        op.drop_column("users", c)
