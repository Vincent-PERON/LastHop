"""Learning : ARP, FDB, endpoints, historique, OUI

Revision ID: 0004
Revises: 0003
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("devices", sa.Column("snmp_context", sa.String(32), nullable=False, server_default=""))
    op.add_column("devices", sa.Column("last_learning_at", sa.DateTime(timezone=True)))
    op.add_column("devices", sa.Column("last_learning_status", sa.String(32)))
    op.create_table(
        "arp_entries",
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("ip", postgresql.INET, primary_key=True),
        sa.Column("mac", postgresql.MACADDR, primary_key=True),
        sa.Column("vlan", sa.Integer),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_arp_entries_mac", "arp_entries", ["mac"])
    op.create_table(
        "fdb_entries",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column(
            "interface_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("interfaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mac", postgresql.MACADDR, nullable=False),
        sa.Column("vlan", sa.Integer),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("vlan IS NULL OR vlan BETWEEN 1 AND 4094", name="ck_fdb_vlan"),
    )
    op.create_index("ix_fdb_entries_device_id", "fdb_entries", ["device_id"])
    op.create_index("ix_fdb_entries_mac", "fdb_entries", ["mac"])
    op.execute("CREATE UNIQUE INDEX uq_fdb_device_mac_vlan ON fdb_entries (device_id, mac, vlan) NULLS NOT DISTINCT")
    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mac", postgresql.MACADDR, nullable=False),
        sa.Column("ip", postgresql.INET),
        sa.Column("vlan", sa.Integer),
        sa.Column("device_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("devices.id", ondelete="SET NULL")),
        sa.Column("interface_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("interfaces.id", ondelete="SET NULL")),
        sa.Column("device_name", sa.String(100)),
        sa.Column("port_name", sa.String(64)),
        sa.Column("hostname", sa.String(253)),
        sa.Column("hostname_checked_at", sa.DateTime(timezone=True)),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("active", sa.Boolean, nullable=False, server_default="true"),
        sa.CheckConstraint("vlan IS NULL OR vlan BETWEEN 1 AND 4094", name="ck_ep_vlan"),
    )
    op.execute("CREATE UNIQUE INDEX uq_endpoint_mac_ip ON endpoints (mac, ip) NULLS NOT DISTINCT")
    op.create_index("ix_endpoints_mac", "endpoints", ["mac"])
    op.create_index("ix_endpoints_ip", "endpoints", ["ip"])
    op.create_index("ix_endpoints_device_id", "endpoints", ["device_id"])
    op.create_index("ix_endpoints_last_seen", "endpoints", ["last_seen"])
    op.create_table(
        "endpoint_history",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column(
            "endpoint_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("endpoints.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("change", sa.String(16), nullable=False),
        sa.Column("old", postgresql.JSONB),
        sa.Column("new", postgresql.JSONB),
        sa.CheckConstraint(
            "change IN ('appeared','moved','ip_changed','vlan_changed','disappeared')", name="ck_hist_change"
        ),
    )
    op.create_index("ix_endpoint_history_endpoint_id", "endpoint_history", ["endpoint_id"])
    op.create_index("ix_endpoint_history_ts", "endpoint_history", ["ts"])
    op.create_table(
        "oui",
        sa.Column("prefix", postgresql.MACADDR, primary_key=True),
        sa.Column("vendor", sa.String(255), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )
