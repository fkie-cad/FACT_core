import logging
import os

from common_helper_files.file_functions import create_dir_for_file
from pymongo import MongoClient, errors

from helperFunctions.config import get_config_dir
from helperFunctions.process import complete_shutdown


class MongoMgr:
    '''
    mongo server connection
    '''

    def __init__(self, config=None):
        self.config = config
        self.mongo_log_path = config['Logging']['mongoDbLogPath']
        self.config_path = os.path.join(get_config_dir(), 'mongod.conf')
        self.mongo_db_file_path = config['data_storage']['mongo_storage_directory']
        logging.debug('Data Storage Path: {}'.format(self.mongo_db_file_path))
        create_dir_for_file(self.mongo_log_path)
        os.makedirs(self.mongo_db_file_path, exist_ok=True)

    def auth_is_enabled(self):
        try:
            mongo_server, mongo_port = self.config['data_storage']['mongo_server'], self.config['data_storage']['mongo_port']
            client = MongoClient('mongodb://{}:{}'.format(mongo_server, mongo_port), connect=False)
            users = list(client.admin.system.users.find({}))
            return len(users) > 0
        except errors.OperationFailure:
            return True

    def check_file_and_directory_existence_and_permissions(self):
        if not os.path.isfile(self.config_path):
            complete_shutdown('Error: config file not found: {}'.format(self.config_path))
        if not os.path.isdir(os.path.dirname(self.mongo_log_path)):
            complete_shutdown('Error: log path not found: {}'.format(self.mongo_log_path))
        if not os.path.isdir(self.mongo_db_file_path):
            complete_shutdown('Error: MongoDB storage path not found: {}'.format(self.mongo_db_file_path))
        if not os.access(self.mongo_db_file_path, os.W_OK):
            complete_shutdown('Error: no write permissions for MongoDB storage path: {}'.format(self.mongo_db_file_path))
        for path in [self.mongo_log_path, self.mongo_db_file_path]:
            file_stats = os.stat(path)
            if not file_stats.st_uid == file_stats.st_gid == 999:
                complete_shutdown('Error: wrong owner for MongoDB storage path: {} {}'.format(path, file_stats.st_uid))

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
