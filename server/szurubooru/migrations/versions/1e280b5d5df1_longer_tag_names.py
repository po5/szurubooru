"""
Longer tag names

Revision ID: 1e280b5d5df1
Created at: 2020-03-15 18:57:12.901148
"""

import sqlalchemy as sa
from alembic import op

revision = "1e280b5d5df1"
down_revision = "52d6ea6584b8"
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    with op.batch_alter_table("tag_name"):
        op.alter_column(
            "tag_name",
            "name",
            type_=sa.Unicode(64),
            existing_type=sa.Unicode(128),
            existing_nullable=False,
        )

    with op.batch_alter_table("snapshot"):
        op.alter_column(
            "snapshot",
            "resource_name",
            type_=sa.Unicode(64),
            existing_type=sa.Unicode(128),
            existing_nullable=False,
        )
