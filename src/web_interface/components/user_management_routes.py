import logging
from contextlib import contextmanager

from flask import flash, redirect, render_template, request, url_for
from flask_security import current_user
from flask_security.utils import hash_password
from sqlalchemy.exc import SQLAlchemyError

from helperFunctions.web_interface import password_is_legal
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES, ROLES


class UserManagementRoutes(ComponentBase):
    def __init__(self, user_db=None, user_db_interface=None, **kwargs):
        super().__init__(**kwargs)
        self._user_db = user_db
        self._user_db_interface = user_db_interface

    @contextmanager
    def user_db_session(self, error_message=None):
        session = self._user_db.session
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, TypeError):
            logging.error('error while accessing user db:', exc_info=True)
            session.rollback()
            if error_message:
                flash(error_message)

    @roles_accepted(*PRIVILEGES['manage_users'])
    @AppRoute('/admin/manage_users', GET, POST)
    def manage_users(self):
        if request.method == 'POST':
            self._add_user()
        user_list = self._user_db_interface.list_users()
        return render_template('user_management/manage_users.html', users=user_list)

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
                self._user_db_interface.create_user(email=name, password=hash_password(password))
                flash('Successfully created user', 'success')
                logging.info(f'Created user: {name}')

    @roles_accepted(*PRIVILEGES['manage_users'])
    @AppRoute('/admin/user/<user_id>', GET)
    def show_user(self, user_id):
        user = self._user_db_interface.find_user(id=user_id)
        if not user:
            flash(f'Error: user with ID {user_id} not found', 'danger')
            return redirect(url_for('manage_users'))
        available_roles = sorted(ROLES)
        return render_template(
            'user_management/edit_user.html',
            available_roles=available_roles,
            user=user,
            privileges=PRIVILEGES,
        )

    @roles_accepted(*PRIVILEGES['manage_users'])
    @AppRoute('/admin/user/<user_id>', POST)
    def edit_user(self, user_id):
        if 'admin_change_password' in request.form:
            self._change_user_password(user_id)
        elif 'input_roles' in request.form:
            self._edit_roles(user_id)
        else:
            flash('Error: unknown request', 'danger')
        return redirect(url_for('show_user', user_id=user_id))

    def _change_user_password(self, user_id):
        new_password = request.form['admin_change_password']
        retype_password = request.form['admin_confirm_password']
        if not new_password == retype_password:
            flash('Error: passwords do not match', 'danger')
        elif not password_is_legal(new_password):
            flash('Error: password is not legal. Please choose another password.', 'danger')
        else:
            user = self._user_db_interface.find_user(id=user_id)
            with self.user_db_session('Error: could not change password'):
                self._user_db_interface.change_password(user.email, new_password)
                flash('password change successful', 'success')

    def _edit_roles(self, user_id):
        user = self._user_db_interface.find_user(id=user_id)
        if user is None:
            return  # Error will flash from redirect to `show_user`

        selected_roles = request.form.getlist('input_roles')
        added_roles, removed_roles = self._determine_role_changes(user.roles, set(selected_roles))

        with self.user_db_session('Error: while changing roles'):
            for role in added_roles:
                if not self._user_db_interface.role_exists(role):
                    self._user_db_interface.create_role(name=role)
                    logging.info(f'Creating user role "{role}"')
                self._user_db_interface.add_role_to_user(user=user, role=role)

            for role in removed_roles:
                self._user_db_interface.remove_role_from_user(user=user, role=role)

        logging.info(f'Changed roles of user {user.email}: added roles {added_roles}, removed roles {removed_roles}')

    @staticmethod
    def _determine_role_changes(user_roles, selected_roles: set):
        current_roles = {r.name for r in user_roles if r.name in ROLES}
        added_roles = selected_roles - current_roles
        removed_roles = current_roles - selected_roles
        return added_roles, removed_roles

    @roles_accepted(*PRIVILEGES['manage_users'])
    @AppRoute('/admin/delete_user/<user_name>', GET)
    def delete_user(self, user_name):
        with self.user_db_session('Error: could not delete user'):
            user = self._user_db_interface.find_user(email=user_name)
            self._user_db_interface.delete_user(user=user)
            flash(f'Successfully deleted user "{user_name}"', 'success')
        return redirect(url_for('manage_users'))

    @roles_accepted(*PRIVILEGES['view_profile'])
    @AppRoute('/user_profile', GET, POST)
    def show_profile(self):
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
