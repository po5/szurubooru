"""
support large file uploads

Revision ID: c867abb456b1
Created at: 2020-10-11 15:37:30.965231
"""

import sqlalchemy as sa
from alembic import op

revision = "c867abb456b1"
down_revision = "c97dc1bf184a"
branch_labels = None
depends_on = None


def upgrade():
    pass

def downgrade():
    with op.batch_alter_table("post"):
        op.alter_column(
            "post", "file_size", type_=sa.Integer, existing_type=sa.BigInteger
        )
