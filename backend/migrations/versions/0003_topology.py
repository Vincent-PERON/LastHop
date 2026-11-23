"""Topologie L2 : interfaces, voisins LLDP/CDP, chassis des équipements

Revision ID: 0003
Revises: 0002
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("chassis_mac", postgresql.MACADDR))
    op.add_column("devices", sa.Column("last_topology_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("last_topology_status", sa.String(32)))
    op.create_table(
        "interfaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("if_index", sa.Integer, nullable=False),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("descr", sa.String(255)),
        sa.Column("alias", sa.String(255)),
        sa.Column("if_type", sa.Integer),
        sa.Column("bridge_port", sa.Integer),
        sa.Column("oper_status", sa.Integer),
        sa.Column("is_trunk", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("mac_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("role_detected", sa.String(8), nullable=False, server_default="access"),
        sa.Column("role_reason", sa.String(16)),
        sa.Column("role_override", sa.String(8)),
        sa.Column("override_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("override_at", sa.DateTime(timezone=True)),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("device_id", "if_index"),
        sa.CheckConstraint("role_detected IN ('access','uplink')", name="ck_if_role_detected"),
        sa.CheckConstraint("role_override IS NULL OR role_override IN ('access','uplink')", name="ck_if_role_override"),
        sa.CheckConstraint("mac_count >= 0", name="ck_if_mac_count"),
    )
    op.create_index("ix_interfaces_device_id", "interfaces", ["device_id"])
    op.create_table(
        "neighbors",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "interface_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("interfaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("protocol", sa.String(4), nullable=False),
        sa.Column("remote_chassis_id", sa.String(64), nullable=False),
        sa.Column("remote_port_id", sa.String(128), nullable=False),
        sa.Column("remote_port_desc", sa.String(255)),
        sa.Column("remote_sysname", sa.String(100)),
        sa.Column("remote_sysdescr", sa.String(255)),
        sa.Column("remote_ip", postgresql.INET),
        sa.Column("remote_is_network_device", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("matched_device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column(
            "matched_interface_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("interfaces.id", ondelete="SET NULL")
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.UniqueConstraint("device_id", "interface_id", "protocol", "remote_chassis_id", "remote_port_id"),
        sa.CheckConstraint("protocol IN ('lldp','cdp')", name="ck_nb_protocol"),
    )
    op.create_index("ix_neighbors_device_id", "neighbors", ["device_id"])
