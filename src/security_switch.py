from functools import wraps

from flask_security import roles_accepted as original_decorator


def roles_accepted(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not _get_authentication(args):
                return fn(*args, **kwargs)
            return original_decorator(*roles)(fn)(*args, **kwargs)
        return decorated_view
    return wrapper


def _get_config_from_endpoint(endpoint_class):
    if getattr(endpoint_class, 'config', None):
        return endpoint_class.config
    elif getattr(endpoint_class, '_config', None):
        return endpoint_class._config
    else:
        raise AttributeError('There is no accessible config object')


def _get_authentication(args):
    config = _get_config_from_endpoint(endpoint_class=args[0])
    authenticate = config.getboolean('ExpertSettings', 'authentication')
    return authenticate


ALL_ROLES = ['superuser', 'senior_analyst', 'analyst', 'guest_analyst', 'guest']


PRIVILEGES = {
    'status': ['superuser', 'senior_analyst', 'analyst', 'guest_analyst', 'guest'],
    'basic_search': ['superuser', 'senior_analyst', 'analyst', 'guest_analyst'],
    'view_analysis': ['superuser', 'senior_analyst', 'analyst', 'guest_analyst'],
    'comment': ['superuser', 'senior_analyst', 'analyst'],
    'compare': ['superuser', 'senior_analyst', 'analyst'],
    'advanced_search': ['superuser', 'senior_analyst', 'analyst'],
    'pattern_search': ['superuser', 'senior_analyst', 'analyst'],
    'submit_analysis': ['superuser', 'senior_analyst'],
    'download': ['superuser', 'senior_analyst'],
    'delete': ['superuser']
}

for privilege in PRIVILEGES:
    for role in PRIVILEGES[privilege]:
        assert role in ALL_ROLES, 'typo or error in privilege definition'
