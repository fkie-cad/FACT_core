"""The author of Comments, set by FACT"""

from __future__ import annotations

from flask_security import current_user

import config

#: author of Comments without authentication and without a name
ANONYMOUS_AUTHOR = 'anonymous'


def get_comment_author(name: str | None) -> str:
    """:return: the logged-in user; without authentication: `name` (``anonymous`` if empty)"""
    if config.frontend.authentication.enabled:
        return current_user.email
    return (name or '').strip() or ANONYMOUS_AUTHOR
