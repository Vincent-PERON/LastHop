"""TOTP optionnel pour le compte local

Revision ID: 0007
Revises: 0006
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("totp_secret_blob", sa.LargeBinary))
    op.add_column("users", sa.Column("totp_key_id", sa.String(64)))
    op.add_column("users", sa.Column("totp_enabled", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("users", sa.Column("totp_last_step", sa.BigInteger))
    op.add_column(
        "users", sa.Column("totp_recovery", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb"))
    )
    op.create_check_constraint("ck_users_totp_only_local", "users", "totp_secret_blob IS NULL OR issuer = 'local'")
    op.create_check_constraint(
        "ck_users_totp_enabled_has_secret", "users", "NOT totp_enabled OR totp_secret_blob IS NOT NULL"
    )


def downgrade() -> None:
    op.drop_constraint("ck_users_totp_enabled_has_secret", "users")
    op.drop_constraint("ck_users_totp_only_local", "users")
    for c in ("totp_recovery", "totp_last_step", "totp_enabled", "totp_key_id", "totp_secret_blob"):
        op.drop_column("users", c)
