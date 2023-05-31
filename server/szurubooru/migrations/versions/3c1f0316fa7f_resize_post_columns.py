"""
resize post columns

Revision ID: 3c1f0316fa7f
Created at: 2019-07-27 22:29:33.874837
"""

import sqlalchemy as sa
from alembic import op

revision = "3c1f0316fa7f"
down_revision = "1cd4c7b22846"
branch_labels = None
depends_on = None


def upgrade():
    pass

def downgrade():
    with op.batch_alter_table("post"):
        op.alter_column(
            "post", "flags", type_=sa.Unicode(200), existing_type=sa.Unicode(32)
        )

        op.alter_column(
            "post", "source", type_=sa.Unicode(200), existing_type=sa.Unicode(2048)
        )
