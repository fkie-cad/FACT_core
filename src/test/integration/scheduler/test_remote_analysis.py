import gc
import time
import unittest
from tempfile import TemporaryDirectory

import pika

from helperFunctions.remote_analysis import serialize, create_task_id
from scheduler.Analysis import AnalysisScheduler
from storage.MongoMgr import MongoMgr
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import get_database_names, TEST_FW
from test.integration.common import initialize_config
from test.unit.helperFunctions_setup_test_data import clean_test_database


class TestFileAddition(unittest.TestCase):
    def setUp(self):
        self._tmp_dir = TemporaryDirectory()
        self._config = initialize_config(self._tmp_dir)
        self._config.set('remote_tasks', 'use_rabbit', 'true')

        self._mongo_server = MongoMgr(config=self._config, auth=False)
        self._backend_interface = BackEndDbInterface(config=self._config)

        self._analysis_scheduler = AnalysisScheduler(config=self._config, db_interface=self._backend_interface)

    def tearDown(self):
        self._analysis_scheduler.shutdown()

        clean_test_database(self._config, get_database_names(self._config))
        self._mongo_server.shutdown()

        self._tmp_dir.cleanup()

        gc.collect()

    def test_catch_remote_analysis(self):
        remote_analysis = StubRemoteAnalysis(self._config)

        TEST_FW.processed_analysis.update({'remote_stub_plugin': {'placeholder': 'foo', 'analysis_date': 0.0}})
        self._backend_interface.add_object(TEST_FW)

        remote_analysis.process_task(TEST_FW.uid)

        time.sleep(2)

        new_object = self._backend_interface.get_object(TEST_FW.uid)

        self.assertNotIn('placeholder', new_object.processed_analysis['remote_stub_plugin'], 'remote analysis not added')
        self.assertEqual(new_object.processed_analysis['remote_stub_plugin']['bar'], 'anything')

        remote_analysis.shutdown()


class StubRemoteAnalysis:
    def __init__(self, config):
        self._config = config
        self._out_connection, self._out_channel = self._set_up_out_channel()

    def _set_up_out_channel(self) -> tuple:
        connection = pika.BlockingConnection(pika.ConnectionParameters(self._config.get('remote_tasks', 'exchange_host')))
        channel = connection.channel()
        channel.exchange_declare(exchange=self._config.get('remote_tasks', 'write_back_exchange'), exchange_type='direct')
        return connection, channel

    def process_task(self, uid: str):
        result = dict(value='foo', bar='anything', analysis_date=1.0, plugin_version='0.1')

        task_message = {
            'uid': uid,
            'task_id': create_task_id(uid),
            'timestamp': 2.0,
            'analysis': result,
            'analysis_system': 'remote_stub_plugin'
        }
        exchange, key = self._config.get('remote_tasks', 'write_back_exchange'), self._config.get('remote_tasks', 'write_back_key')
        self._out_channel.basic_publish(exchange=exchange, routing_key=key, body=serialize(task_message))

    def shutdown(self):
        self._out_connection.close()
