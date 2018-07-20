# -*- coding: utf-8 -*-
import logging
from contextlib import contextmanager

from flask import render_template, request, flash, redirect, url_for
from flask_security import current_user
from sqlalchemy.exc import SQLAlchemyError

from helperFunctions.web_interface import password_is_legal
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES, ROLES


class UserManagementRoutes(ComponentBase):

    def __init__(self, app, config, api=None, user_db=None, user_db_interface=None):
        super().__init__(app, config, api=api)
        self._user_db = user_db
        self._user_db_interface = user_db_interface

    def _init_component(self):
        self._app.add_url_rule('/admin/manage_users', 'admin/manage_users', self._app_manage_users, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/user/<user_id>', 'admin/user/<user_id>', self._app_edit_user, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/edit_user', 'admin/edit_user', self._ajax_edit_user, methods=['POST'])
        self._app.add_url_rule('/admin/delete_user/<user_name>', 'admin/delete_user/<user_name>', self._app_delete_user)
        self._app.add_url_rule('/user_profile', 'user_profile', self._app_show_profile, methods=['GET', 'POST'])

    @contextmanager
    def user_db_session(self, error_message=None):
        session = self._user_db.session
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, TypeError) as exception:
            logging.error('error while accessing user db: {}'.format(exception))
            session.rollback()
            if error_message:
                flash(error_message)

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_manage_users(self):
        if request.method == 'POST':
            self._add_user()
        user_list = self._user_db_interface.list_users()
        return render_template(
            'user_management/manage_users.html',
            users=user_list
        )

    def _add_user(self):
        name = request.form['username']
        password = request.form['password1']
        password_retype = request.form['password2']
        if self._user_db_interface.user_exists(name):
            flash('Error: user is already in the database', 'danger')
        elif password != password_retype:
            flash('Error: passwords do not match', 'danger')
        else:
            with self.user_db_session('Error while creating user'):
                self._user_db_interface.create_user(email=name, password=password)
                flash('Successfully created user', 'success')
                logging.info('Created user: {}'.format(name))

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_edit_user(self, user_id):
        user = self._user_db_interface.find_user(id=user_id)
        if not user:
            flash('Error: user with ID {} not found'.format(user_id), 'danger')
            return redirect(url_for('admin/manage_users'))
        if request.method == 'POST':
            self._change_user_password(user_id)
        available_roles = sorted(ROLES)
        role_indexes = [available_roles.index(r.name) for r in user.roles if r.name in ROLES]
        return render_template(
            'user_management/edit_user.html',
            available_roles=available_roles,
            user=user,
            role_indexes=role_indexes,
            privileges=PRIVILEGES
        )

    def _change_user_password(self, user_id):
        new_password = request.form['admin_change_password']
        retype_password = request.form['admin_confirm_password']
        if not new_password == retype_password:
            flash('Error: passwords do not match')
        elif not password_is_legal(new_password):
            flash('Error: password is not legal. Please choose another password.')
        else:
            user = self._user_db_interface.find_user(id=user_id)
            with self.user_db_session('Error: could not change password'):
                self._user_db_interface.change_password(user.email, new_password)
                flash('password change successful', 'success')

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _ajax_edit_user(self):
        element_name = request.values['name']
        if element_name == 'roles':
            return self._edit_roles()
        return 'Not found', 400

    def _edit_roles(self):
        user_name = request.form['pk']
        selected_role_indexes = sorted(request.form.getlist('value[]'))

        try:
            user = self._user_db_interface.find_user(email=user_name)
        except SQLAlchemyError:
            return 'Not found', 400

        added_roles, removed_roles = self._determine_role_changes(user.roles, selected_role_indexes)

        with self.user_db_session('Error: while changing roles'):
            for role in added_roles:
                if not self._user_db_interface.role_exists(role):
                    self._user_db_interface.create_role(name=role)
                    logging.info('Creating user role "{}"'.format(role))
                self._user_db_interface.add_role_to_user(user=user, role=role)

            for role in removed_roles:
                self._user_db_interface.remove_role_from_user(user=user, role=role)

        logging.info('Changed roles of user {}: added roles {}, removed roles {}'.format(user_name, added_roles, removed_roles))
        return 'OK', 200

    @staticmethod
    def _determine_role_changes(user_roles, selected_role_indexes):
        available_roles = sorted(ROLES)
        selected_roles = [available_roles[int(i)] for i in selected_role_indexes]
        current_roles = [r.name for r in user_roles if r.name in ROLES]

        added_roles = [r for r in selected_roles if r not in current_roles]
        removed_roles = [r for r in current_roles if r not in selected_roles]
        return added_roles, removed_roles

    @roles_accepted(*PRIVILEGES['manage_users'])
    def _app_delete_user(self, user_name):
        with self.user_db_session('Error: could not delete user'):
            user = self._user_db_interface.find_user(email=user_name)
            self._user_db_interface.delete_user(user=user)
            flash('Successfully deleted user "{}"'.format(user_name), 'success')
        return redirect(url_for('admin/manage_users'))

    @roles_accepted(*PRIVILEGES['view_profile'])
    def _app_show_profile(self):
        if request.method == 'POST':
            self._change_own_password()
        return render_template('user_management/user_profile.html', user=current_user)

    def _change_own_password(self):
        new_password = request.form['new_password']
        new_password_confirm = request.form['new_password_confirm']
        old_password = request.form['old_password']
        if new_password != new_password_confirm:
            flash('Error: new password did not match', 'warning')
        elif not self._user_db_interface.password_is_correct(current_user.email, old_password):
            flash('Error: wrong password', 'warning')
        elif not password_is_legal(new_password):
            flash('Error: password is not legal. Please choose another password.')
        else:
            with self.user_db_session('Error: could not change password'):
                self._user_db_interface.change_password(current_user.email, new_password)
                flash('password change successful', 'success')
