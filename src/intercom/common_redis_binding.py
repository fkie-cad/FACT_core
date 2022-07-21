import logging
import pickle
from configparser import ConfigParser
from time import time
from typing import Any

from redis.exceptions import RedisError

from helperFunctions.hash import get_sha256
from storage.redis_interface import RedisInterface


def generate_task_id(input_data: Any) -> str:
    serialized_data = pickle.dumps(input_data)
    task_id = f'{get_sha256(serialized_data)}_{time()}'
    return task_id


class InterComRedisInterface:
    def __init__(self, config: ConfigParser):
        self.config = config
        self.redis = RedisInterface(config)


class InterComListener(InterComRedisInterface):
    '''
    InterCom Listener Base Class
    '''

    CONNECTION_TYPE = 'test'  # unique for each listener

    def get_next_task(self):
        try:
            task_obj = self.redis.queue_get(self.CONNECTION_TYPE)
        except RedisError as exc:
            logging.error(f'Could not get next task: {str(exc)}', exc_info=True)
            return None
        if task_obj is not None:
            task, task_id = task_obj
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
        self.redis.set(task_id, response)
        logging.debug(f'response send: {self.OUTGOING_CONNECTION_TYPE} -> {task_id}')
        return task

    def get_response(self, task):  # pylint: disable=no-self-use
        '''
        this function must be implemented by the sub_class
        '''
        return task
