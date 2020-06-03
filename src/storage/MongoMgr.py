import logging
import os

from common_helper_files.file_functions import create_dir_for_file
from common_helper_process import execute_shell_command
from pymongo import MongoClient, errors

from helperFunctions.config import get_config_dir
from helperFunctions.mongo_config_parser import get_mongo_path
from helperFunctions.process import complete_shutdown


class MongoMgr:
    '''
    mongo server startup and shutdown
    '''

    def __init__(self, config=None, auth=True):
        self.config = config
        try:
            self.mongo_log_path = config['Logging']['mongoDbLogFile']
        except (KeyError, TypeError):
            self.mongo_log_path = '/tmp/fact_mongo.log'
        self.config_path = os.path.join(get_config_dir(), 'mongod.conf')
        self.mongo_db_file_path = get_mongo_path(self.config_path)
        logging.debug('Data Storage Path: {}'.format(self.mongo_db_file_path))
        create_dir_for_file(self.mongo_log_path)
        os.makedirs(self.mongo_db_file_path, exist_ok=True)
        self.start(_authenticate=auth)

    def auth_is_enabled(self):
        try:
            mongo_server, mongo_port = self.config['data_storage']['mongo_server'], self.config['data_storage']['mongo_port']
            client = MongoClient('mongodb://{}:{}'.format(mongo_server, mongo_port), connect=False)
            users = list(client.admin.system.users.find({}))
            return len(users) > 0
        except errors.OperationFailure:
            return True

    def start(self, _authenticate=True):
        if self.config['data_storage']['mongo_server'] == 'localhost':
            logging.info("start local mongo database")
            self.check_file_and_directory_existence_and_permissions()
            auth_option = '--auth ' if _authenticate else ''
            command = 'mongod {}--config {} --fork --logpath {}'.format(auth_option, self.config_path, self.mongo_log_path)
            output = execute_shell_command(command)
            logging.debug(output)
        else:
            logging.info('using external mongodb: {}:{}'.format(self.config['data_storage']['mongo_server'], self.config['data_storage']['mongo_port']))

    def check_file_and_directory_existence_and_permissions(self):
        if not os.path.isfile(self.config_path):
            complete_shutdown('Error: config file not found: {}'.format(self.config_path))
        if not os.path.isdir(os.path.dirname(self.mongo_log_path)):
            complete_shutdown('Error: log path not found: {}'.format(self.mongo_log_path))
        if not os.path.isdir(self.mongo_db_file_path):
            complete_shutdown('Error: MongoDB storage path not found: {}'.format(self.mongo_db_file_path))
        if not os.access(self.mongo_db_file_path, os.W_OK):
            complete_shutdown('Error: no write permissions for MongoDB storage path: {}'.format(self.mongo_db_file_path))

    def shutdown(self):
        if self.config['data_storage']['mongo_server'] == 'localhost':
            logging.info('stop local mongo database')
            command = 'mongo --eval "db.shutdownServer()" {}:{}/admin --username {} --password "{}"'.format(
                self.config['data_storage']['mongo_server'], self.config['data_storage']['mongo_port'],
                self.config['data_storage']['db_admin_user'], self.config['data_storage']['db_admin_pw']
            )
            output = execute_shell_command(command)
            logging.debug(output)

    def init_users(self):
        logging.info('Creating users for MongoDB authentication')
        if self.auth_is_enabled():
            logging.error("The DB seems to be running with authentication. Try terminating the MongoDB process.")
        mongo_server = self.config['data_storage']['mongo_server']
        mongo_port = self.config['data_storage']['mongo_port']
        try:
            client = MongoClient('mongodb://{}:{}'.format(mongo_server, mongo_port), connect=False)
            client.admin.command(
                "createUser",
                self.config['data_storage']['db_admin_user'],
                pwd=self.config['data_storage']['db_admin_pw'],
                roles=[
                    {'role': 'dbOwner', 'db': 'admin'},
                    {'role': 'readWriteAnyDatabase', 'db': 'admin'},
                    {'role': 'root', 'db': "admin"}
                ]
            )
            client.admin.command(
                "createUser",
                self.config['data_storage']['db_readonly_user'],
                pwd=self.config['data_storage']['db_readonly_pw'],
                roles=[{'role': 'readAnyDatabase', 'db': 'admin'}]
            )
        except (AttributeError, ValueError, errors.PyMongoError) as error:
            logging.error('Could not create users:\n{}'.format(error))
