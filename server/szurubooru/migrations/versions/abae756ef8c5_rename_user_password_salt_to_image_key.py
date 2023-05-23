"""
rename user password salt to image key

Revision ID: abae756ef8c5
Created at: 2023-05-23 11:20:16.765590
"""

import sqlalchemy as sa
from alembic import op

revision = "abae756ef8c5"
down_revision = "58d9a3d7c7e6"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "user",
        sa.Column("image_key", sa.Unicode(32)),
    )
    op.drop_column("user", "password_salt")


def downgrade():
    op.add_column(
        "user",
        sa.Column("password_salt", sa.Unicode(32)),
    )
    op.drop_column("user", "image_key")
