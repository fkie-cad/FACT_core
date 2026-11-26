"""Add unique ids to Comments

Comments were identified by their time (whole seconds), so deleting one deleted all Comments of the File Object with
the same time. New Comments get an id when they are added; this migration adds one to every existing Comment.

Revision ID: d4edc8f54065
Revises: 6a1c50ade0f3
Create Date: 2026-11-26 12:00:00.000000

"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

if TYPE_CHECKING:
    from collections.abc import Callable

# revision identifiers, used by Alembic.
revision = 'd4edc8f54065'
down_revision = '6a1c50ade0f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    _update_comments(lambda comment: {'id': uuid4().hex, **comment} if 'id' not in comment else comment)


def downgrade() -> None:
    _update_comments(lambda comment: {key: value for key, value in comment.items() if key != 'id'})


def _update_comments(update: Callable[[dict], dict]) -> None:
    connection = op.get_bind()
    rows = connection.execute(
        sa.text("SELECT uid, comments FROM file_object WHERE jsonb_typeof(comments) = 'array' AND comments <> '[]'")
    ).fetchall()
    for uid, comments in rows:
        connection.execute(
            sa.text('UPDATE file_object SET comments = CAST(:comments AS JSONB) WHERE uid = :uid'),
            {'uid': uid, 'comments': json.dumps([update(comment) for comment in comments])},
        )
