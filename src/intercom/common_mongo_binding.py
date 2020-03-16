import logging
import pickle
from time import time

import gridfs

from helperFunctions.hash import get_sha256
from storage.mongo_interface import MongoInterface


def generate_task_id(input_data):
    serialized_data = pickle.dumps(input_data)
    task_id = '{}_{}'.format(get_sha256(serialized_data), time())
    return task_id


class InterComMongoInterface(MongoInterface):
    '''
    Common parts of the InterCom Mongo interface
    '''

    INTERCOM_CONNECTION_TYPES = [
        'test',
        'analysis_task',
        'analysis_plugins',
        're_analyze_task',
        'update_task',
        'compare_task',
        'file_delete_task',
        'raw_download_task',
        'raw_download_task_resp',
        'tar_repack_task',
        'tar_repack_task_resp',
        'binary_search_task',
        'binary_search_task_resp',
        'single_file_task'
    ]

    def _setup_database_mapping(self):
        self.connections = {}
        for item in self.INTERCOM_CONNECTION_TYPES:
            self.connections[item] = {'name': '{}_{}'.format(self.config['data_storage']['intercom_database_prefix'], item)}
            self.connections[item]['collection'] = self.client[self.connections[item]['name']]
            self.connections[item]['fs'] = gridfs.GridFS(self.connections[item]['collection'])


class InterComListener(InterComMongoInterface):
    '''
    InterCom Listener Base Class
    '''

    CONNECTION_TYPE = 'test'  # unique for each listener

    def __init__(self, config=None):
        super().__init__(config=config)
        self.additional_setup(config=config)

    def get_next_task(self):
        try:
            task_obj = self.connections[self.CONNECTION_TYPE]['fs'].find_one()
        except Exception as exc:
            logging.error('Could not get next task: {} {}'.format(type(exc), str(exc)))
            return None
        if task_obj is not None:
            task = pickle.loads(task_obj.read())
            task_id = task_obj.filename
            self.connections[self.CONNECTION_TYPE]['fs'].delete(task_obj._id)
            task = self.post_processing(task, task_id)
            logging.debug('{}: New task received: {}'.format(self.CONNECTION_TYPE, task))
            return task
        return None

    def additional_setup(self, config=None):
        '''
        optional additional setup
        '''
        pass  # pylint: disable=unnecessary-pass

    def post_processing(self, task, task_id):  # pylint: disable=no-self-use,unused-argument
        '''
        optional post processing of a task
        '''
        return task


class InterComListenerAndResponder(InterComListener):
    '''
    CONNECTION_TYPE and OUTGOING_CONNECTION_TYPE must be implmented by the sub_class
    '''

    CONNECTION_TYPE = 'test'
    OUTGOING_CONNECTION_TYPE = 'test'

    def post_processing(self, task, task_id):
        logging.debug('request received: {} -> {}'.format(self.CONNECTION_TYPE, task_id))
        response = self.get_response(task)
        self.connections[self.OUTGOING_CONNECTION_TYPE]['fs'].put(pickle.dumps(response), filename='{}'.format(task_id))
        logging.debug('response send: {} -> {}'.format(self.OUTGOING_CONNECTION_TYPE, task_id))
        return task

    def get_response(self, task):  # pylint: disable=no-self-use
        '''
        this function must be implemented by the sub_class
        '''
        return task
