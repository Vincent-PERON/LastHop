"""Sauvegarde des configurations (SSH) : profils, exécutions, journal, versions

Revision ID: 0005
Revises: 0004
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ssh_credentials",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(100), nullable=False, unique=True),
        sa.Column("username", sa.String(64), nullable=False),
        sa.Column("auth_type", sa.String(8), nullable=False),
        sa.Column("secret_blob", sa.LargeBinary, nullable=False),
        sa.Column("key_id", sa.String(64), nullable=False),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("auth_type IN ('password','key')", name="ck_ssh_auth_type"),
    )
    op.add_column("devices", sa.Column("ssh_credential_id", postgresql.UUID(as_uuid=True),
                                       sa.ForeignKey("ssh_credentials.id", ondelete="SET NULL")))
    op.add_column("devices", sa.Column("ssh_port", sa.Integer, nullable=False, server_default="22"))
    op.add_column("devices", sa.Column("ssh_allow_legacy", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("devices", sa.Column("ssh_host_key", sa.Text))
    op.add_column("devices", sa.Column("backup_enabled", sa.Boolean, nullable=False, server_default="false"))
    op.add_column("devices", sa.Column("last_backup_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("last_backup_status", sa.String(16)))
    op.create_check_constraint("ck_dev_ssh_port", "devices", "ssh_port BETWEEN 1 AND 65535")

    op.create_table(
        "backup_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("device_name", sa.String(100), nullable=False),
        sa.Column("trigger", sa.String(10), nullable=False),
        sa.Column("requested_by", sa.String(320)),
        sa.Column("status", sa.String(10), nullable=False, server_default="running"),
        sa.Column("error_code", sa.String(32)),
        sa.Column("summary", sa.Text),
        sa.Column("results", postgresql.JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("status IN ('running','success','partial','failed')", name="ck_run_status"),
        sa.CheckConstraint("trigger IN ('manual','scheduled')", name="ck_run_trigger"),
    )
    op.create_index("ix_backup_runs_device_id", "backup_runs", ["device_id"])
    op.create_index("ix_backup_runs_started_at", "backup_runs", ["started_at"])
    op.create_table(
        "backup_events",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("backup_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("clock_timestamp()")),
        sa.Column("level", sa.String(8), nullable=False),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("advice", sa.Text),
        sa.Column("detail", sa.Text),
        sa.CheckConstraint("level IN ('info','ok','warn','error')", name="ck_event_level"),
    )
    op.create_index("ix_backup_events_run_id", "backup_events", ["run_id"])
    op.create_table(
        "config_backups",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE")),
        sa.Column("run_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("backup_runs.id", ondelete="SET NULL")),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("status", sa.String(10), nullable=False),
        sa.Column("content_blob", sa.LargeBinary),
        sa.Column("key_id", sa.String(64)),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer, nullable=False),
        sa.Column("same_as_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("config_backups.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("kind IN ('running','startup')", name="ck_cfg_kind"),
        sa.CheckConstraint("status IN ('success','unchanged')", name="ck_cfg_status"),
        sa.CheckConstraint("(status = 'success' AND content_blob IS NOT NULL) OR status = 'unchanged'", name="ck_cfg_blob"),
    )
    op.create_index("ix_config_backups_device_id", "config_backups", ["device_id"])
    op.create_index("ix_config_backups_created_at", "config_backups", ["created_at"])
