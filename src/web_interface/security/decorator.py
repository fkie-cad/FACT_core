from functools import wraps

from flask_security import roles_accepted as original_decorator

from config import cfg


def roles_accepted(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not cfg.expert_settings.authentication:
                return fn(*args, **kwargs)
            return original_decorator(*roles)(fn)(*args, **kwargs)
        return decorated_view
    return wrapper
