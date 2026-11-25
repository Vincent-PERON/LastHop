"""VLAN connus de chaque équipement, PVID et mode des ports

Revision ID: 0009
Revises: 0008
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("interfaces", sa.Column("pvid", sa.Integer))
    op.add_column("interfaces", sa.Column("port_mode", sa.String(8)))
    op.add_column(
        "interfaces", sa.Column("tagged_vlans", postgresql.JSONB, nullable=False, server_default=sa.text("'[]'::jsonb"))
    )
    op.create_check_constraint(
        "ck_if_port_mode", "interfaces", "port_mode IS NULL OR port_mode IN ('access','trunk','hybrid')"
    )
    op.create_table(
        "device_vlans",
        sa.Column(
            "device_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("devices.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("vlan_id", sa.Integer, primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, server_default=""),
        sa.CheckConstraint("vlan_id BETWEEN 1 AND 4094", name="ck_devvlan_id"),
    )


def downgrade() -> None:
    op.drop_table("device_vlans")
    op.drop_constraint("ck_if_port_mode", "interfaces")
    for c in ("tagged_vlans", "port_mode", "pvid"):
        op.drop_column("interfaces", c)
