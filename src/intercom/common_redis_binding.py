from __future__ import annotations

import logging
import os
import pickle
from multiprocessing import Process, Value
from time import sleep, time
from typing import TYPE_CHECKING, Any, Callable

from redis.exceptions import RedisError

import config
from helperFunctions.hash import get_sha256
from storage.redis_interface import RedisInterface

if TYPE_CHECKING:
    from objects.file import FileObject


def generate_task_id(input_data: Any) -> str:
    serialized_data = pickle.dumps(input_data)
    return f'{get_sha256(serialized_data)}_{time()}'


def publish_available_analysis_plugins(plugin_dict: dict[str, tuple]):
    redis = RedisInterface()
    redis.set('analysis_plugins', plugin_dict)


class InterComListener:
    """
    InterCom Listener Base Class
    """

    CONNECTION_TYPE = 'test'  # unique for each listener

    def __init__(self, processing_function: Callable[[FileObject], None] | None = None):
        super().__init__()
        self.redis = RedisInterface()
        self.process = None
        self.processing_function = processing_function
        self.stop_condition = Value('i', 0)

    def start(self):
        self.process = Process(target=self._worker)
        self.process.start()

    def shutdown(self):
        self.stop_condition.value = 1

    def _worker(self):
        logging.debug(f'{self.CONNECTION_TYPE} listener started (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            task = self.get_next_task()
            if task is None:
                sleep(config.backend.intercom_poll_delay)
            elif self.processing_function is not None:
                self.processing_function(task)
        logging.debug(f'{self.CONNECTION_TYPE} listener stopped')

    def get_next_task(self):
        try:
            task_obj = self.redis.queue_get(self.CONNECTION_TYPE)
        except RedisError as exc:
            logging.error(f'Could not get next task: {exc!s}', exc_info=True)
            return None
        if task_obj is not None:
            task, task_id = task_obj
            task = self.pre_process(task, task_id)
            logging.debug(f'{self.CONNECTION_TYPE}: New task received: {task}')
            return task
        return None

    def pre_process(self, task, task_id):  # noqa: ARG002
        """
        optional pre-processing of a task
        """
        return task


class InterComListenerAndResponder(InterComListener):
    """
    CONNECTION_TYPE and OUTGOING_CONNECTION_TYPE must be implemented by the sub_class
    """

    OUTGOING_CONNECTION_TYPE = 'test'

    def pre_process(self, task, task_id):
        logging.debug(f'request received: {self.CONNECTION_TYPE} -> {task_id}')
        response = self.get_response(task)
        self.redis.set(task_id, response)
        logging.debug(f'response send: {self.OUTGOING_CONNECTION_TYPE} -> {task_id}')
        return task

    def get_response(self, task):
        """
        this function must be implemented by the sub_class
        """
        return task
