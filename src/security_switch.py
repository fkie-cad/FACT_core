USE_AUTHENTICATION = False

if USE_AUTHENTICATION:
    from authenticate_app import add_flask_security_to_app
    from flask_security import login_required, roles_accepted, roles_required
else:
    def roles_accepted(function):
        return function

    def roles_required(function):
        return function

    def login_required(function):
        return function

    def add_flask_security_to_app(input):
        return None, None


ALL_ROLES = ['superuser', 'senior_analyst', 'analyst', 'guest_analyst', 'guest']


PRIVILEGES = {
    'status':           ['superuser', 'senior_analyst', 'analyst', 'guest_analyst', 'guest'],
    'basic_search':     ['superuser', 'senior_analyst', 'analyst', 'guest_analyst'],
    'view_analysis':    ['superuser', 'senior_analyst', 'analyst', 'guest_analyst'],
    'comment':          ['superuser', 'senior_analyst', 'analyst'],
    'compare':          ['superuser', 'senior_analyst', 'analyst'],
    'advanced_search':  ['superuser', 'senior_analyst', 'analyst'],
    'pattern_search':   ['superuser', 'senior_analyst', 'analyst'],
    'submit_analysis':  ['superuser', 'senior_analyst'],
    'download':         ['superuser', 'senior_analyst'],
    'delete':           ['superuser']
}

for privilege in PRIVILEGES:
    for role in PRIVILEGES['privilege']:
        assert role in ALL_ROLES, 'typo or error in privilege definition'


# compare has to be at least as powerful as view analysis
