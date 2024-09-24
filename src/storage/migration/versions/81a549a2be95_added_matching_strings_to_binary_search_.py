"""Added matching strings to binary search cache

Revision ID: 81a549a2be95
Revises: 05d8effce8b3
Create Date: 2024-06-24 17:00:37.464098

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '81a549a2be95'
down_revision = '05d8effce8b3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'search_cache',
        sa.Column('match_data', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('search_cache', 'match_data')
