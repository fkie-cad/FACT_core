import unittest
from tempfile import TemporaryDirectory
import pickle

from helperFunctions.entropy import generate_random_data
from helperFunctions.config import get_config_for_testing
from storage.MongoMgr import MongoMgr
from intercom.common_mongo_binding import InterComListener

TMP_DIR = TemporaryDirectory(prefix='fact_test_')

BSON_MAX_FILE_SIZE = 16 * 1024**2


class TestInterComListener(unittest.TestCase):

    def setUp(self):
        config = get_config_for_testing(temp_dir=TMP_DIR)
        self.mongo_server = MongoMgr(config=config)
        self.generic_listener = InterComListener(config=config)

    def tearDown(self):
        for item in self.generic_listener.connections.keys():
            self.generic_listener.client.drop_database(self.generic_listener.connections[item]['name'])
        self.generic_listener.shutdown()
        self.mongo_server.shutdown()
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
