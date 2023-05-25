"""
add title and alt text to posts

Revision ID: 99de351fb1d0
Created at: 2023-05-25 16:54:36.353151
"""

import sqlalchemy as sa
from alembic import op

revision = "99de351fb1d0"
down_revision = "abae756ef8c5"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "post", sa.Column("title", sa.UnicodeText(), nullable=True)
    )
    op.add_column(
        "post", sa.Column("alt_text", sa.UnicodeText(), nullable=True)
    )


def downgrade():
    op.drop_column("post", "title")
    op.drop_column("post", "alt_text")
