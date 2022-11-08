#!/usr/bin/env python3

import argparse
import getpass
import sys
from pathlib import Path

from flask_security import hash_password
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter

import config
from config import configparser_cfg
from helperFunctions.config_deprecated import get_config_dir
from helperFunctions.web_interface import password_is_legal
from version import __VERSION__
from web_interface.app import create_app
from web_interface.security.authentication import add_flask_security_to_app
from web_interface.security.privileges import ROLES
from web_interface.security.terminal_validators import ActionValidator, ActionValidatorReverse

FACT_ASCII_ART = '''
                                                      ***********.
                                                   *******************.
   *****************  ***********************   ********'       .********   *********************.
  *****************  ***********************  .******                ***      *********************
 *****              *****             *****  *****'                                   '****
.****              *****             *****  *****                                      *****
****'              ****              ****  .****                                        ****
****              *****             *****  ****                                         *****
**********        ***********************  ****                                          ****
**********        ***********************  ****                                          ****
****              *****             *****  ****.                                        *****
****.              ****              ****  '****                                        ****
 ****              *****             *****  *****                                      *****
 *****              *****             *****  ******                                   *****
  *****              *****             *****  '******               .***             *****
   ******             *****             *****   *********       .********           *****
                                                   *******************
                                                      ***********'
'''


def setup_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version=f'FACT User Management (FACTUM) {__VERSION__}')
    parser.add_argument('-C', '--config_file', help='set path to config File', default=f'{get_config_dir()}/main.cfg')
    return parser.parse_args()


class Actions:
    def __init__(self, session, app, store, db):
        self.session = session
        self.app = app
        self.store = store
        self.db = db

    @staticmethod
    def help():
        print(
            '\nOne of the following actions can be chosen:\n'
            '\n\t[add_role_to_user]\tadd existing role to an existing user'
            '\n\t[create_role]\t\tcreate new role'
            '\n\t[create_user]\t\tcreate new user'
            '\n\t[delete_user]\t\tdelete a user'
            '\n\t[get_apikey_for_user]\tretrieve apikey for existing user'
            '\n\t[list_all_users]\tlist all existing users and their roles'
            '\n\t[remove_role_from_user]\tremove role from user'
            '\n\t[help]\t\t\tshow this help'
            '\n\t[exit]\t\t\tclose application'
        )

    def _role_exists(self, role):
        with self.app.app_context():
            exists = self.store.find_role(role)
        return bool(exists)

    def _get_user_list(self):
        with self.app.app_context():
            return [x.email for x in self.store.list_users()]

    def _get_role_list(self):
        with self.app.app_context():
            return [x.name for x in self.store.list_roles()]

    def create_user(self):
        user_list = self._get_user_list()
        user = self.session.prompt(
            'username: ',
            validator=ActionValidatorReverse(user_list, message='user must not exist and not be empty'),
            completer=None,
        )
        while True:
            password = getpass.getpass('password: ')
            if not password_is_legal(password):
                print('Password is not legal. Please choose another password.')
                continue
            break
        with self.app.app_context():
            self.store.create_user(email=user, password=hash_password(password), roles=['guest'])
            self.db.session.commit()

    def delete_user(self):
        user_list = self._get_user_list()
        action_completer = WordCompleter(user_list)
        user = self.session.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist before deleting'),
            completer=action_completer,
        )
        with self.app.app_context():
            self.store.delete_user(user=self.store.find_user(email=user))
            self.db.session.commit()

    def create_role(self):
        role_list = self._get_role_list()
        role = self.session.prompt(
            'role name: ', validator=ActionValidatorReverse(role_list, message='role must not exist and not be empty')
        )
        with self.app.app_context():
            if not self._role_exists(role):
                self.store.create_role(name=role)
                self.db.session.commit()

    def add_role_to_user(self):
        user_list = self._get_user_list()
        role_list = self._get_role_list()
        user_completer = WordCompleter(user_list)
        role_completer = WordCompleter(role_list)
        user = self.session.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exists before adding it to a role'),
            completer=user_completer,
        )
        role = self.session.prompt(
            'rolename: ',
            validator=ActionValidator(role_list, message='role must exists before user can be added'),
            completer=role_completer,
        )
        with self.app.app_context():
            self.store.add_role_to_user(user=self.store.find_user(email=user), role=role)
            self.db.session.commit()

    def remove_role_from_user(self):
        user_list = self._get_user_list()
        user_completer = WordCompleter(user_list)
        user = self.session.prompt(
            'username: ', validator=ActionValidator(user_list, message='user must exist'), completer=user_completer
        )
        with self.app.app_context():
            user = self.store.find_user(email=user)
        user_roles = [role.name for role in user.roles]
        role = self.session.prompt(
            'rolename: ',
            validator=ActionValidator(user_roles, message='user must have that role before it can be removed'),
            completer=WordCompleter(user_roles),
        )
        with self.app.app_context():
            self.store.remove_role_from_user(user=self.store.find_user(email=user.email), role=role)
            self.db.session.commit()

    def get_apikey_for_user(self):
        user_list = self._get_user_list()
        action_completer = WordCompleter(user_list)
        user = self.session.prompt(
            'username: ',
            validator=ActionValidator(user_list, message='user must exist to retrieve apikey.'),
            completer=action_completer,
        )
        with self.app.app_context():
            user = self.store.find_user(email=user)

        apikey = user.api_key
        print(f'key: {apikey}')

    def list_all_users(self):
        user_list = self.store.list_users()
        for user in user_list:
            user_roles = ', '.join([role.name for role in user.roles])
            print(f'\n\t{user.email} ({user_roles})')
        print()

    @staticmethod
    def exit():
        raise EOFError('Quitting ..')


LEGAL_ACTIONS = [action for action in dir(Actions) if not action.startswith('_')]


def initialise_roles(app, interface, db):
    for role in ROLES:
        if not interface.find_role(role):
            with app.app_context():
                interface.create_role(name=role)
                db.session.commit()


def prompt_loop(app, store, db, session):  # pylint: disable=too-complex
    print(FACT_ASCII_ART)
    print('\nWelcome to the FACT User Management (FACTUM)\n')
    initialise_roles(app, store, db)
    actions = Actions(session, app, store, db)

    while True:
        try:
            action_completer = WordCompleter(LEGAL_ACTIONS)
            action = actions.session.prompt(
                'Please choose an action to perform: ',
                validator=ActionValidator(LEGAL_ACTIONS),
                completer=action_completer,
            )
        except (EOFError, KeyboardInterrupt):
            break
        try:
            acting_function = getattr(actions, action)
            acting_function()

        except KeyboardInterrupt:
            print('returning to action selection')
        except AssertionError as assertion_error:
            print(f'error: {assertion_error}')
        except EOFError:
            break

    print('\nQuitting ..')


def start_user_management(app, store, db, session):
    # We expect flask-security to be initialized
    db.create_all()
    prompt_loop(app, store, db, session)


def main():
    args = setup_argparse()
    config.load(Path(args.config_file).name)
    app = create_app(configparser_cfg)
    user_db, user_datastore = add_flask_security_to_app(app)

    start_user_management(app, user_datastore, user_db, PromptSession())

    return 0


if __name__ == '__main__':
    sys.exit(main())
