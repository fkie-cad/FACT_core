import logging
import pickle
from configparser import ConfigParser
from time import time
from typing import Any

from redis import Redis

from helperFunctions.hash import get_sha256


def generate_task_id(input_data: Any) -> str:
    serialized_data = pickle.dumps(input_data)
    task_id = f'{get_sha256(serialized_data)}_{time()}'
    return task_id


class InterComRedisInterface:
    def __init__(self, config: ConfigParser):
        self.config = config
        redis_db = config.getint('data_storage', 'redis_fact_db')
        redis_host = config.get('data_storage', 'redis_host')
        redis_port = config.getint('data_storage', 'redis_port')
        self.redis = Redis(host=redis_host, port=redis_port, db=redis_db)

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
        'binary_peek_task',
        'binary_peek_task_resp',
        'binary_search_task',
        'binary_search_task_resp',
        'single_file_task',
        'logs_task',
        'logs_task_resp'
    ]

    def _setup_database_mapping(self):
        pass


class InterComListener(InterComRedisInterface):
    '''
    InterCom Listener Base Class
    '''

    CONNECTION_TYPE = 'test'  # unique for each listener

    def get_next_task(self):
        try:
            task_obj = self.redis.lpop(self.CONNECTION_TYPE)
        except Exception as exc:
            logging.error(f'Could not get next task: {str(exc)}', exc_info=True)
            return None
        if task_obj is not None:
            task, task_id = pickle.loads(task_obj)
            task = self.post_processing(task, task_id)
            logging.debug(f'{self.CONNECTION_TYPE}: New task received: {task}')
            return task
        return None

    def post_processing(self, task, task_id):  # pylint: disable=no-self-use,unused-argument
        '''
        optional post-processing of a task
        '''
        return task


class InterComListenerAndResponder(InterComListener):
    '''
    CONNECTION_TYPE and OUTGOING_CONNECTION_TYPE must be implemented by the sub_class
    '''

    CONNECTION_TYPE = 'test'
    OUTGOING_CONNECTION_TYPE = 'test'

    def post_processing(self, task, task_id):
        logging.debug(f'request received: {self.CONNECTION_TYPE} -> {task_id}')
        response = self.get_response(task)
        self.redis.set(task_id, pickle.dumps(response))
        logging.debug(f'response send: {self.OUTGOING_CONNECTION_TYPE} -> {task_id}')
        return task

    def get_response(self, task):  # pylint: disable=no-self-use
        '''
        this function must be implemented by the sub_class
        '''
        return task
