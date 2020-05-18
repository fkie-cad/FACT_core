# pylint:disable=attribute-defined-outside-init,no-self-use

import gc
import pickle

import pytest

from helperFunctions.entropy import generate_random_data
from intercom.common_mongo_binding import InterComListener
from test.common_helper import TestBase

BSON_MAX_FILE_SIZE = 16 * 1024**2


@pytest.mark.usefixtures('use_db')
class TestInterComListener(TestBase):

    def setup(self):
        self.generic_listener = InterComListener(config=self.config)

    def teardown(self):
        for item in self.generic_listener.connections.keys():
            self.generic_listener.client.drop_database(self.generic_listener.connections[item]['name'])
        self.generic_listener.shutdown()
        gc.collect()

    def check_file(self, binary):
        self.generic_listener.connections[self.generic_listener.CONNECTION_TYPE]['fs'].put(pickle.dumps(binary))
        task = self.generic_listener.get_next_task()
        assert task == binary
        another_task = self.generic_listener.get_next_task()
        assert another_task is None, 'task not deleted'

    def test_small_file(self):
        self.check_file(b'this is a test')

    def test_big_file(self):
        large_test_data = generate_random_data(size=BSON_MAX_FILE_SIZE + 1024)
        self.check_file(large_test_data)
