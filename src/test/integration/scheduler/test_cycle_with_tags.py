import gc
import unittest
from multiprocessing import Event
from tempfile import TemporaryDirectory
from time import sleep

from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler
from scheduler.analysis_tag import TaggingDaemon
from scheduler.Unpacking import UnpackingScheduler
from storage.db_interface_backend import BackEndDbInterface
from storage.MongoMgr import MongoMgr
from test.common_helper import clean_test_database, get_database_names, get_test_data_dir
from test.integration.common import initialize_config


class TestTagPropagation(unittest.TestCase):

    def setUp(self):
        self._tmp_dir = TemporaryDirectory()
        self._config = initialize_config(self._tmp_dir)
        self.analysis_finished_event = Event()
        self.uid_of_key_file = '530bf2f1203b789bfe054d3118ebd29a04013c587efd22235b3b9677cee21c0e_2048'

        self._mongo_server = MongoMgr(config=self._config, auth=False)
        self.backend_interface = BackEndDbInterface(config=self._config)

        self._analysis_scheduler = AnalysisScheduler(config=self._config, pre_analysis=self.backend_interface.add_object, post_analysis=self.count_analysis_finished_event)
        self._tagging_scheduler = TaggingDaemon(analysis_scheduler=self._analysis_scheduler)
        self._unpack_scheduler = UnpackingScheduler(config=self._config, post_unpack=self._analysis_scheduler.start_analysis_of_object)

    def count_analysis_finished_event(self, fw_object):
        self.backend_interface.add_analysis(fw_object)
        if fw_object.uid == self.uid_of_key_file and 'crypto_material' in fw_object.processed_analysis:
            sleep(1)
            self.analysis_finished_event.set()

    def _wait_for_empty_tag_queue(self):
        while not self._analysis_scheduler.tag_queue.empty():
            sleep(0.1)

    def tearDown(self):
        self._unpack_scheduler.shutdown()
        self._tagging_scheduler.shutdown()
        self._analysis_scheduler.shutdown()

        clean_test_database(self._config, get_database_names(self._config))
        self._mongo_server.shutdown()

        self._tmp_dir.cleanup()
        gc.collect()

    def test_run_analysis_with_tag(self):
        test_fw = Firmware(file_path='{}/container/with_key.7z'.format(get_test_data_dir()))
        test_fw.release_date = '2017-01-01'
        test_fw.scheduled_analysis = ['crypto_material']

        self._unpack_scheduler.add_task(test_fw)

        assert self.analysis_finished_event.wait(timeout=20)

        processed_fo = self.backend_interface.get_object(self.uid_of_key_file, analysis_filter=['crypto_material'])
        assert processed_fo.processed_analysis['crypto_material']['tags'], 'no tags set in analysis'

        self._wait_for_empty_tag_queue()

        processed_fw = self.backend_interface.get_object(test_fw.uid, analysis_filter=['crypto_material'])
        assert processed_fw.analysis_tags, 'tags not propagated properly'
        assert processed_fw.analysis_tags['crypto_material']['private_key_inside']
