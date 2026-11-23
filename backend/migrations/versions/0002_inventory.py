"""Inventaire : sites, profils SNMP, équipements, jobs

Revision ID: 0002
Revises: 0001
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sites",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "snmp_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("version", sa.String(8), nullable=False),
        sa.Column("v3_username", sa.String(32)),
        sa.Column("auth_proto", sa.String(16)),
        sa.Column("priv_proto", sa.String(16)),
        sa.Column("allow_legacy_algos", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("secret_blob", sa.LargeBinary, nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("version IN ('v2c','v3')", name="ck_cred_version"),
        sa.CheckConstraint(
            "auth_proto IS NULL OR auth_proto IN ('sha1','sha224','sha256','sha384','sha512')", name="ck_cred_auth"
        ),
        sa.CheckConstraint("priv_proto IS NULL OR priv_proto IN ('aes128','aes192','aes256')", name="ck_cred_priv"),
        sa.CheckConstraint(
            "(version = 'v2c' AND v3_username IS NULL AND auth_proto IS NULL AND priv_proto IS NULL) OR "
            "(version = 'v3' AND v3_username IS NOT NULL AND auth_proto IS NOT NULL AND priv_proto IS NOT NULL)",
            name="ck_cred_shape",
        ),
        sa.CheckConstraint("auth_proto IS DISTINCT FROM 'sha1' OR allow_legacy_algos", name="ck_cred_legacy"),
    )
    op.create_table(
        "devices",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("mgmt_ip", postgresql.INET, nullable=False, unique=True),
        sa.Column("site_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("sites.id", ondelete="RESTRICT")),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("driver", sa.String(16), nullable=False, server_default="generic"),
        sa.Column("vendor", sa.String(64)),
        sa.Column("model", sa.String(64)),
        sa.Column("sys_name", sa.String(100)),
        sa.Column("sys_descr", sa.String(255)),
        sa.Column("sys_object_id", sa.String(128)),
        sa.Column("is_l3", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("is_l2", sa.Boolean, nullable=False, server_default="true"),
        sa.Column(
            "credential_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("snmp_credentials.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("snmp_port", sa.Integer, nullable=False, server_default="161"),
        sa.Column("timeout_ms", sa.Integer, nullable=False, server_default="3000"),
        sa.Column("retries", sa.Integer, nullable=False, server_default="1"),
        sa.Column("max_repetitions", sa.Integer, nullable=False, server_default="25"),
        sa.Column("poll_interval_s", sa.Integer, nullable=False, server_default="900"),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_identified_at", sa.DateTime(timezone=True)),
        sa.Column("last_poll_status", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("role IN ('core','distribution','access')", name="ck_dev_role"),
        sa.CheckConstraint("driver IN ('generic','aruba_os','comware','cisco_ios')", name="ck_dev_driver"),
        sa.CheckConstraint("snmp_port BETWEEN 1 AND 65535", name="ck_dev_port"),
        sa.CheckConstraint("timeout_ms BETWEEN 500 AND 30000", name="ck_dev_timeout"),
        sa.CheckConstraint("retries BETWEEN 0 AND 5", name="ck_dev_retries"),
        sa.CheckConstraint("max_repetitions BETWEEN 1 AND 100", name="ck_dev_maxrep"),
        sa.CheckConstraint("poll_interval_s BETWEEN 60 AND 86400", name="ck_dev_poll"),
        sa.CheckConstraint(
            "family(mgmt_ip) IN (4,6) AND masklen(mgmt_ip) = CASE family(mgmt_ip) WHEN 4 THEN 32 ELSE 128 END",
            name="ck_dev_host_ip",
        ),
    )
    op.create_table(
        "jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("params", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("result", postgresql.JSONB),
        sa.Column("error_code", sa.String(32)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('pending','running','done','failed')", name="ck_job_status"),
    )
    op.create_index("ix_jobs_requested_by", "jobs", ["requested_by"])
