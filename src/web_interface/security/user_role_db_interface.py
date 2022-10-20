from flask_security import SQLAlchemyUserDatastore
from flask_security.utils import hash_password, verify_password


class UserRoleDbInterface(SQLAlchemyUserDatastore):
    def list_users(self):
        user_list = self.user_model.query.all()
        return user_list

    def list_roles(self):
        role_list = self.role_model.query.all()
        return role_list

    def password_is_correct(self, user_name, password):
        user = self.find_user(email=user_name)
        return verify_password(password, user.password)

    def change_password(self, user_name, password):
        user = self.find_user(email=user_name)
        user.password = hash_password(password)
        self.put(user)

    def user_exists(self, user_name):
        user = self.find_user(email=user_name)
        return True if user else False

    def role_exists(self, role):
        role = self.find_role(role)
        return True if role else False
