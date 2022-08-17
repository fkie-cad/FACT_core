import os

from flask import Flask
from flask_security import uia_username_mapper


def create_app(config):
    app = Flask(__name__)
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    _add_config_to_app(app, config)
    return app


def _add_config_to_app(app, config):
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = config.get('data-storage', 'password-salt').encode()
    app.config['SQLALCHEMY_DATABASE_URI'] = config.get('data-storage', 'user-database', fallback='sqlite:///')
    # FIXME fix redirect loop here
    app.config['SECURITY_UNAUTHORIZED_VIEW'] = '/login'
    app.config['LOGIN_DISABLED'] = not config.getboolean('expert-settings', 'authentication')

    # As we want to use ONLY usernames and no emails but email is hardcoded in
    # flask-security we change the validation mapper of 'email'.
    # Note that from the perspective of flask-security we still use emails.
    # This means that we do not want to enable SECURITY_USERNAME_ENABLE
    app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = [
        {
            'email': {
                'mapper': uia_username_mapper, 'case_insensitive': True
            }
        }
    ]
