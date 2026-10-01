"""Attribute administrative events to the affected user."""

import sqlalchemy as sa
from alembic import op

revision = "7636761bcb6e"
down_revision = "d382a9e2813d"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("security_events", sa.Column("target_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "security_events_target_id_fkey", "security_events", "users", ["target_id"], ["id"]
    )


def downgrade() -> None:
    op.drop_constraint("security_events_target_id_fkey", "security_events", type_="foreignkey")
    op.drop_column("security_events", "target_id")
