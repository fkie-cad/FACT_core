import os

from flask import Flask
from flask_security import uia_username_mapper

import config


class ExtendedAutoEscapeFlask(Flask):
    AUTOESCAPE_EXTENSIONS = (
        '.j2',
        '.jhtml',
        '.jinja',
        '.jinja2',
    )

    def select_jinja_autoescape(self, filename):
        if filename and filename.endswith(self.AUTOESCAPE_EXTENSIONS):
            return True
        return super().select_jinja_autoescape(filename)


def create_app():
    app = ExtendedAutoEscapeFlask(__name__)
    app.config.from_object(__name__)
    app.config['SECRET_KEY'] = os.urandom(24)
    _add_config_to_app(app)
    app.url_map.strict_slashes = False  # allow trailing slashes in endpoint URLs
    return app


def _add_config_to_app(app):
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECURITY_PASSWORD_SALT'] = config.frontend.authentication.password_salt.encode()
    app.config['SQLALCHEMY_DATABASE_URI'] = config.frontend.authentication.user_database
    # FIXME fix redirect loop here
    app.config['SECURITY_UNAUTHORIZED_VIEW'] = '/login'
    app.config['LOGIN_DISABLED'] = not config.frontend.authentication.enabled

    # rename session cookie to fix user session problems with other flask apps running on the same system
    app.config['SESSION_COOKIE_NAME'] = 'FACT_session_cookie'

    # As we want to use ONLY usernames and no emails but email is hardcoded in
    # flask-security we change the validation mapper of 'email'.
    # Note that from the perspective of flask-security we still use emails.
    # This means that we do not want to enable SECURITY_USERNAME_ENABLE
    app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = [
        {'email': {'mapper': uia_username_mapper, 'case_insensitive': True}}
    ]
