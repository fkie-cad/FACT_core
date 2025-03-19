from functools import wraps

from flask_security import roles_accepted as original_decorator

import config


def roles_accepted(*roles, no_role_needed: bool = False):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not config.frontend.authentication.enabled or no_role_needed:
                return fn(*args, **kwargs)
            return original_decorator(*roles)(fn)(*args, **kwargs)

        return decorated_view

    return wrapper
