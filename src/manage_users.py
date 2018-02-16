#!/usr/bin/env python3

import argparse
import getpass
import os
import sys

from flask_security import Security
from flask_sqlalchemy import SQLAlchemy

from authenticate_app import create_db_interface
from helperFunctions.config import load_config
from version import __VERSION__
from web_interface.frontend_main import WebFrontEnd


def setup_argparse():
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='FACT User Management (FACTUM) {}'.format(__VERSION__))
    parser.add_argument('config_file', help='path to fact config file')
    return parser.parse_args()


def get_input(message, expected_type, max_len=0):
    correct_input_form = False
    user_input = None
    while not correct_input_form:
        user_input = input(message)
        try:
            if max_len and len(user_input) > max_len:
                print('Error: input too long (max length: {})'.format(max_len))
            else:
                user_input = expected_type(user_input)
                correct_input_form = True
        except TypeError:
            print('Error: wrong type. expected type {}'.format(repr(expected_type)))
    return user_input


def choose_action():
    print('\nPlease choose an action (use "help" for a list of available actions)')
    chosen_action = input('action: ')
    return chosen_action


class Actions:
    @staticmethod
    def help(*_):
        print(
            '\nPlease choose an action:\n'
            '\n\t[create_user]\t\tcreate new user'
            '\n\t[delete_user]\t\tdelete a user'
            '\n\t[create_role]\t\tcreate new role'
            '\n\t[add_role_to_user]\tadd existing role to an existing user'
            '\n\t[remove_role_from_user]\tremove role from user'
            '\n\t[get_apikey_for_user]\tretrieve apikey for existing user'
            '\n\t[help]\t\t\tshow this help'
            '\n\t[exit]\t\t\tclose application'
        )

    @staticmethod
    def _user_exists(app, interface, name):
        with app.app_context():
            user = interface.find_user(email=name)
        return True if user else False

    @staticmethod
    def exit(*_):
        exit('Quitting ..')

    @staticmethod
    def create_user(app, interface, db):
        user = get_input('username: ', str, max_len=15)
        assert not Actions._user_exists(app, interface, user), 'user must not exist'

        password = getpass.getpass('password: ')
        with app.app_context():
            interface.create_user(email=user, password=password)
            db.session.commit()

    @staticmethod
    def get_apikey_for_user(app, interface, _):
        user = get_input('username: ', str, max_len=15)
        assert Actions._user_exists(app, interface, user), 'user must exist to retrieve apikey'

        with app.app_context():
            user = interface.find_user(email=user)

        apikey = user.api_key
        print('key: {}'.format(apikey))

    @staticmethod
    def _role_exists(app, interface, role):
        with app.app_context():
            exists = interface.find_role(role)
        return True if exists else False

    @staticmethod
    def create_role(app, interface, db):
        role = get_input('role name: ', str, max_len=15)
        with app.app_context():
            interface.create_role(name=role)
            db.session.commit()

    @staticmethod
    def add_role_to_user(app, interface, db):
        user = get_input('username:', str, max_len=15)
        assert Actions._user_exists(app, interface, user), 'user must exists before adding it to role'

        role = get_input('role name: ', str, max_len=15)
        assert Actions._role_exists(app, interface, role), 'role must exists before user can be added'

        with app.app_context():
            interface.add_role_to_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def remove_role_from_user(app, interface, db):
        user = get_input('username: ', str, max_len=15)
        assert Actions._user_exists(app, interface, user), 'user must exists before adding it to role'

        role = get_input('role name: ', str, max_len=15)
        assert Actions._role_exists(app, interface, role), 'role must exists before user can be added'

        with app.app_context():
            interface.remove_role_from_user(user=interface.find_user(email=user), role=role)
            db.session.commit()

    @staticmethod
    def delete_user(app, interface, db):
        user = get_input('username: ', str, max_len=15)
        assert Actions._user_exists(app, interface, user), 'user must exists before adding it to role'

        with app.app_context():
            interface.delete_user(user)
            db.session.commit()


legal_actions = [action for action in dir(Actions) if not action.startswith('_')]


def prompt_for_actions(app, store, db):
    print('''
                                                      ***********.
                                                   *******************,
   *****************. ***********************   ********,       .********   *********************.
  *****************  ***********************  ,******                ***      *********************
 *****              *****             *****  *****,                                   ,****
.****              *****             *****  *****                                      *****
****,              ****              ****  ,****                                        ****
****              *****             *****  ****                                         *****
**********.       ***********************  ****                                          ****
**********.       ***********************  ****                                          ****
****              *****             *****  ****.                                        *****
****,              ****              ****  ,****                                        ****
 ****              *****             *****  *****                                      *****
 *****              *****             *****  ******                                   *****
  *****              *****             *****  .******               .***             *****
   ******             *****             *****   *********       ,********           *****
                                                   *******************
    ''')

    print('\nWelcome to the FACT User Management (FACTUM)\n')

    while True:
        try:
            action = choose_action()
        except (EOFError, KeyboardInterrupt):
            print('\nQuitting ..')
            break
        if action not in legal_actions:
            print('error: please choose a legal action.')
        else:
            try:
                f = getattr(Actions, action)
                f(app, store, db)
            except AttributeError:
                print('error: action not found')


def start_user_management(app):
    db = SQLAlchemy(app)
    Security(app)
    store = create_db_interface(db)
    prompt_for_actions(app, store, db)


def main():
    args = setup_argparse()
    file_name = os.path.basename(args.config_file)

    config = load_config(file_name)
    frontend = WebFrontEnd(config)

    start_user_management(frontend.app)

    return 0


if __name__ == '__main__':
    sys.exit(main())
