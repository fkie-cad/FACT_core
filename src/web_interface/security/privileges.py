ROLES = ['superuser', 'senior_analyst', 'analyst', 'guest_analyst', 'guest']

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
    'delete': ['superuser'],
    'manage_users': ['superuser'],
    'view_profile': ['superuser', 'senior_analyst', 'analyst']
}

for privilege in PRIVILEGES:
    for role in PRIVILEGES[privilege]:
        if role not in ROLES:
            raise RuntimeError('typo or error in privilege definition')
