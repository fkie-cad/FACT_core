import gc
import pickle
import unittest
from tempfile import TemporaryDirectory

from helperFunctions.entropy import generate_random_data
from intercom.common_mongo_binding import InterComListener
from storage.MongoMgr import MongoMgr
from test.common_helper import get_config_for_testing

TMP_DIR = TemporaryDirectory(prefix='fact_test_')

BSON_MAX_FILE_SIZE = 16 * 1024**2


class TestInterComListener(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = get_config_for_testing(temp_dir=TMP_DIR)
        cls.mongo_server = MongoMgr(config=cls.config)

    def setUp(self):
        self.generic_listener = InterComListener(config=self.config)

    def tearDown(self):
        for item in self.generic_listener.connections.keys():
            self.generic_listener.client.drop_database(self.generic_listener.connections[item]['name'])
        self.generic_listener.shutdown()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()
        TMP_DIR.cleanup()

    def check_file(self, binary):
        self.generic_listener.connections[self.generic_listener.CONNECTION_TYPE]['fs'].put(pickle.dumps(binary))
        task = self.generic_listener.get_next_task()
        self.assertEqual(task, binary)
        another_task = self.generic_listener.get_next_task()
        self.assertIsNone(another_task, 'task not deleted')

    def test_small_file(self):
        self.check_file(b'this is a test')

    def test_big_file(self):
        large_test_data = generate_random_data(size=BSON_MAX_FILE_SIZE + 1024)
        self.check_file(large_test_data)
