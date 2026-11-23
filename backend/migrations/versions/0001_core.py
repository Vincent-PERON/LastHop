"""Socle : users, api_tokens, audit_log (append-only, chaîné), app_settings, privilèges

Revision ID: 0001
Revises:
"""

import os

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

APP = os.environ.get("LASTHOP_DB_USER", "lasthop_app")
RO = "lasthop_readonly"

# audit_verify() retourne l'id de la première ligne dont la chaîne est rompue, ou NULL si tout est cohérent.
# Le hash est calculé PAR LA BASE (le client ne peut pas forger la chaîne). Le verrou consultatif sérialise les
# insertions : l'ordre de la chaîne == l'ordre des id. Dans le texte haché, 'details' est jsonb::text (canonique).
AUDIT_FNS = [
    r"""
CREATE OR REPLACE FUNCTION audit_row_text(r audit_log) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT concat_ws('|', r.id, to_char(r.ts AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'), r.actor_type,
         coalesce(r.actor_id,''), coalesce(r.actor_label,''), r.action, r.outcome, coalesce(r.target_type,''),
         coalesce(r.target_id,''), coalesce(host(r.source_ip),''), coalesce(r.request_id,''), r.details::text)
$$""",
    r"""CREATE OR REPLACE FUNCTION audit_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_hash bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(727274);
  SELECT row_hash INTO last_hash FROM audit_log ORDER BY id DESC LIMIT 1;
  NEW.id := nextval('audit_log_id_seq');
  NEW.prev_hash := coalesce(last_hash, '\x00'::bytea);
  NEW.row_hash := sha256(NEW.prev_hash || convert_to(audit_row_text(NEW), 'UTF8'));
  RETURN NEW;
END $$""",
    r"""CREATE OR REPLACE FUNCTION audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'audit_log est immuable (% interdit)', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$""",
    r"""CREATE OR REPLACE FUNCTION audit_verify() RETURNS bigint LANGUAGE plpgsql STABLE AS $$
DECLARE r audit_log; expected_prev bytea := '\x00'::bytea;
BEGIN
  FOR r IN SELECT * FROM audit_log ORDER BY id LOOP
    IF r.prev_hash IS DISTINCT FROM expected_prev
       OR r.row_hash IS DISTINCT FROM sha256(r.prev_hash || convert_to(audit_row_text(r), 'UTF8')) THEN
      RETURN r.id;
    END IF;
    expected_prev := r.row_hash;
  END LOOP;
  RETURN NULL;
END $$""",
]


def upgrade() -> None:
    op.execute("CREATE TYPE user_role AS ENUM ('viewer','operator','admin')")
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("issuer", sa.String(255), nullable=False),
        sa.Column("sub", sa.String(255), nullable=False),
        sa.Column("email", sa.String(320)),
        sa.Column("display_name", sa.String(255)),
        sa.Column("role", postgresql.ENUM(name="user_role", create_type=False), nullable=False),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("issuer", "sub"),
    )
    op.create_table(
        "api_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(100), nullable=False),
        sa.Column("prefix", sa.String(8), nullable=False, unique=True),
        sa.Column("token_hash", sa.LargeBinary(32), nullable=False),
        sa.Column("scopes", postgresql.ARRAY(sa.String(32)), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("char_length(name) BETWEEN 1 AND 100"),
    )
    op.create_index("ix_api_tokens_user_id", "api_tokens", ["user_id"])
    op.execute("CREATE SEQUENCE audit_log_id_seq")
    op.create_table(
        "audit_log",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("clock_timestamp()")),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column("actor_id", sa.String(64)),
        sa.Column("actor_label", sa.String(320)),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False, server_default="success"),
        sa.Column("target_type", sa.String(64)),
        sa.Column("target_id", sa.String(64)),
        sa.Column("source_ip", postgresql.INET),
        sa.Column("request_id", sa.String(64)),
        sa.Column("details", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("prev_hash", sa.LargeBinary(32)),
        sa.Column("row_hash", sa.LargeBinary(32)),
    )
    op.create_index("ix_audit_log_action", "audit_log", ["action"])
    op.create_index("ix_audit_log_ts", "audit_log", ["ts"])
    op.create_table(
        "app_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", postgresql.JSONB, nullable=False),
        sa.Column("updated_by", sa.String(64)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )

    for fn in AUDIT_FNS:
        op.execute(fn)
    op.execute(
        "CREATE TRIGGER audit_chain BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION audit_before_insert()"
    )
    op.execute(
        "CREATE TRIGGER audit_no_mutation BEFORE UPDATE OR DELETE ON audit_log "
        "FOR EACH ROW EXECUTE FUNCTION audit_immutable()"
    )
    op.execute(
        "CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_log "
        "FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable()"
    )

    # --- Privilèges : moindre privilège. Le rôle applicatif ne peut qu'INSÉRER/LIRE l'audit.
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON users, api_tokens, app_settings TO {APP}")
    op.execute(f"GRANT SELECT, INSERT ON audit_log TO {APP}")
    op.execute(f"GRANT USAGE ON SEQUENCE audit_log_id_seq TO {APP}")
    op.execute(f"GRANT EXECUTE ON FUNCTION audit_verify() TO {APP}")
    op.execute(f"GRANT SELECT ON users, audit_log, app_settings TO {RO}")
    # Tables des lots suivants : DML par défaut pour l'app (l'audit reste explicitement restreint ci-dessus).
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP}")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {APP}")
    op.execute(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO {RO}")


def downgrade() -> None:
    raise RuntimeError("Downgrade volontairement non supporté pour le socle (audit immuable).")
