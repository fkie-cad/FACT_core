import gc
import os
from tempfile import TemporaryDirectory
from unittest import mock
import unittest

from helperFunctions.config import get_config_for_testing
from intercom.back_end_binding import InterComBackEndAnalysisTask, \
    InterComBackEndReAnalyzeTask, InterComBackEndCompareTask, \
    InterComBackEndAnalysisPlugInsPublisher, InterComBackEndRawDownloadTask, \
    InterComBackEndTarRepackTask
from intercom.front_end_binding import InterComFrontEndBinding
from storage.MongoMgr import MongoMgr
from storage.fs_organizer import FS_Organizer
from test.common_helper import create_test_firmware


TMP_DIR = TemporaryDirectory(prefix='fact_test_')


class AnalysisServiceMock():

    def __init__(self, config=None):
        pass

    def get_plugin_dict(self):
        return {'dummy': 'dummy description'}


class TestInterComTaskCommunication(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.config = get_config_for_testing(temp_dir=TMP_DIR)
        cls.config.set('ExpertSettings', 'communication_timeout', '1')
        cls.mongo_server = MongoMgr(config=cls.config)

    def setUp(self):
        self.frontend = InterComFrontEndBinding(config=self.config)
        self.backend = None

    def tearDown(self):
        for item in self.frontend.connections.keys():
            self.frontend.client.drop_database(self.frontend.connections[item]['name'])
        if self.backend:
            self.backend.shutdown()
        self.frontend.shutdown()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()
        TMP_DIR.cleanup()

    def test_analysis_task(self):
        self.backend = InterComBackEndAnalysisTask(config=self.config)
        test_fw = create_test_firmware()
        test_fw.file_path = None
        self.frontend.add_analysis_task(test_fw)
        task = self.backend.get_next_task()
        self.assertEqual(task.get_uid(), test_fw.get_uid(), 'uid not correct')
        self.assertIsNotNone(task.file_path, 'file_path not set')
        self.assertTrue(os.path.exists(task.file_path), 'file does not exist')

    def test_re_analyze_task(self):
        self.backend = InterComBackEndReAnalyzeTask(config=self.config)
        fs_organizer = FS_Organizer(config=self.config)
        test_fw = create_test_firmware()
        fs_organizer.store_file(test_fw)
        original_file_path = test_fw.file_path
        original_binary = test_fw.binary
        test_fw.file_path = None
        test_fw.binary = None
        self.frontend.add_re_analyze_task(test_fw)
        task = self.backend.get_next_task()
        self.assertEqual(task.get_uid(), test_fw.get_uid(), 'uid not correct')
        self.assertIsNotNone(task.file_path, 'file path not set')
        self.assertEqual(task.file_path, original_file_path)
        self.assertIsNotNone(task.binary, 'binary not set')
        self.assertEqual(task.binary, original_binary, 'binary content not correct')

    def test_compare_task(self):
        self.backend = InterComBackEndCompareTask(config=self.config)
        self.frontend.add_compare_task('valid_id', force=False)
        result = self.backend.get_next_task()
        self.assertEqual(result, ('valid_id', False))

    def test_analysis_plugin_publication(self):
        self.backend = InterComBackEndAnalysisPlugInsPublisher(config=self.config, analysis_service=AnalysisServiceMock())
        plugins = self.frontend.get_available_analysis_plugins()
        self.assertEqual(len(plugins), 1, 'Not all plug-ins found')
        self.assertEqual(plugins, {'dummy': 'dummy description'}, 'content not correct')

    def test_analysis_plugin_publication_not_available(self):
        with self.assertRaises(Exception):
            self.frontend.get_available_analysis_plugins()

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_raw_download_task(self, binaryServiceMock, generateTaskIdMock):
        binaryServiceMock().get_binary_and_file_name.return_value = (b'test', 'test.txt')
        generateTaskIdMock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_binary_and_filename('valid_uid')
        self.assertIsNone(result, 'should be none because of timeout')

        self.backend = InterComBackEndRawDownloadTask(config=self.config)
        task = self.backend.get_next_task()
        self.assertEqual(task, 'valid_uid', 'task not correct')
        result = self.frontend.get_binary_and_filename('valid_uid_0.0')
        self.assertEqual(result, (b'test', 'test.txt'), 'retrieved binary not correct')

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_tar_repack_task(self, binaryServiceMock, generateTaskIdMock):
        binaryServiceMock().get_repacked_binary_and_file_name.return_value = (b'test', 'test.tar')
        generateTaskIdMock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_repacked_binary_and_file_name('valid_uid')
        self.assertIsNone(result, 'should be none because of timeout')

        self.backend = InterComBackEndTarRepackTask(config=self.config)
        task = self.backend.get_next_task()
        self.assertEqual(task, 'valid_uid', 'task not correct')
        result = self.frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        self.assertEqual(result, (b'test', 'test.tar'), 'retrieved binary not correct')
