import warnings

from pymongo import MongoClient, errors

from helperFunctions.process import complete_shutdown


warnings.filterwarnings('ignore', module='pymongo.topology')


class MongoInterface(object):
    '''
    This is the mongo interface base class handling:
    - load config
    - setup connection including authentication
    '''

    READ_ONLY = False

    def __init__(self, config=None):
        self.config = config
        mongo_server = self.config['data_storage']['mongo_server']
        mongo_port = self.config['data_storage']['mongo_port']
        self.client = MongoClient('mongodb://{}:{}'.format(mongo_server, mongo_port), connect=False)
        self._authenticate()
        self._setup_database_mapping()

    def shutdown(self):
        self.client.close()

    def _setup_database_mapping(self):
        pass

    def _authenticate(self):
        if self.READ_ONLY:
            user, pw = self.config['data_storage']['db_readonly_user'], self.config['data_storage']['db_readonly_pw']
        else:
            user, pw = self.config['data_storage']['db_admin_user'], self.config['data_storage']['db_admin_pw']
        try:
            self.client.admin.authenticate(user, pw, mechanism='SCRAM-SHA-1')
        except errors.OperationFailure as e:  # Authentication not successful
            complete_shutdown('Error: Authentication not successful: {}'.format(e))
