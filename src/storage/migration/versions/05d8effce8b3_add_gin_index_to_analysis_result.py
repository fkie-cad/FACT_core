"""Add GIN index to analysis.result

Revision ID: 05d8effce8b3
Revises: 70ae1212bc03
Create Date: 2024-06-17 11:20:06.088480

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '05d8effce8b3'
down_revision = '70ae1212bc03'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        'result_gin_index',
        'analysis',
        ['result'],
        postgresql_using='gin',
    )


def downgrade() -> None:
    op.drop_index('result_gin_index', 'analysis')
