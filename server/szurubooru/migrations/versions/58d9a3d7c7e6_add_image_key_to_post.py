"""
add image key to post

Revision ID: 58d9a3d7c7e6
Created at: 2023-05-23 11:10:13.897840
"""

import sqlalchemy as sa
from alembic import op

revision = "58d9a3d7c7e6"
down_revision = "58bba7e0c554"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "post", sa.Column("image_key", sa.Unicode(32))
    )


def downgrade():
    op.drop_column("post", "image_key")
