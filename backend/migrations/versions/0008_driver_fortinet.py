"""Pilote Fortinet

Revision ID: 0008
Revises: 0007
"""

from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_dev_driver", "devices")
    op.create_check_constraint(
        "ck_dev_driver", "devices", "driver IN ('generic','aruba_os','comware','cisco_ios','fortinet')"
    )


def downgrade() -> None:
    op.execute("UPDATE devices SET driver = 'generic' WHERE driver = 'fortinet'")
    op.drop_constraint("ck_dev_driver", "devices")
    op.create_check_constraint("ck_dev_driver", "devices", "driver IN ('generic','aruba_os','comware','cisco_ios')")
