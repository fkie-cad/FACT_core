# pylint: disable=wrong-import-order

import gc
import os
import unittest
from tempfile import TemporaryDirectory
from unittest import mock

from intercom.back_end_binding import (
    InterComBackEndAnalysisPlugInsPublisher,
    InterComBackEndAnalysisTask,
    InterComBackEndCompareTask,
    InterComBackEndPeekBinaryTask,
    InterComBackEndRawDownloadTask,
    InterComBackEndReAnalyzeTask,
    InterComBackEndSingleFileTask,
    InterComBackEndTarRepackTask,
)
from intercom.front_end_binding import InterComFrontEndBinding
from test.common_helper import create_test_firmware, get_config_for_testing


class AnalysisServiceMock:
    def __init__(self, config=None):
        pass

    def get_plugin_dict(self):  # pylint: disable=no-self-use
        return {'dummy': 'dummy description'}


class TestInterComTaskCommunication(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp_dir = TemporaryDirectory(prefix='fact_test_')
        cls.config = get_config_for_testing(temp_dir=cls.tmp_dir)
        cls.config.set('expert-settings', 'communication-timeout', '1')

    def setUp(self):
        self.frontend = InterComFrontEndBinding(config=self.config)
        self.backend = None

    def tearDown(self):
        self.frontend.redis.redis.flushdb()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.tmp_dir.cleanup()

    def test_analysis_task(self):
        self.backend = InterComBackEndAnalysisTask(config=self.config)
        test_fw = create_test_firmware()
        test_fw.file_path = None
        self.frontend.add_analysis_task(test_fw)
        task = self.backend.get_next_task()
        self.assertEqual(task.uid, test_fw.uid, 'uid not correct')
        self.assertIsNotNone(task.file_path, 'file_path not set')
        self.assertTrue(os.path.exists(task.file_path), 'file does not exist')

    def test_single_file_task(self):
        self.backend = InterComBackEndSingleFileTask(config=self.config)
        test_fw = create_test_firmware()
        test_fw.file_path = None
        test_fw.scheduled_analysis = ['binwalk']
        self.frontend.add_single_file_task(test_fw)
        task = self.backend.get_next_task()

        assert task.uid == test_fw.uid, 'uid not transported correctly'
        assert task.scheduled_analysis

    def test_re_analyze_task(self):
        self.backend = InterComBackEndReAnalyzeTask(config=self.config)
        test_fw = create_test_firmware()
        test_fw.file_path = None
        test_fw.binary = None
        self.frontend.add_re_analyze_task(test_fw)
        task = self.backend.get_next_task()
        self.assertEqual(task.uid, test_fw.uid, 'uid not correct')

    def test_compare_task(self):
        self.backend = InterComBackEndCompareTask(config=self.config)
        self.frontend.add_compare_task('valid_id', force=False)
        result = self.backend.get_next_task()
        self.assertEqual(result, ('valid_id', False))

    def test_analysis_plugin_publication(self):
        self.backend = InterComBackEndAnalysisPlugInsPublisher(
            config=self.config, analysis_service=AnalysisServiceMock()
        )
        plugins = self.frontend.get_available_analysis_plugins()
        self.assertEqual(len(plugins), 1, 'Not all plug-ins found')
        self.assertEqual(plugins, {'dummy': 'dummy description'}, 'content not correct')

    def test_analysis_plugin_publication_not_available(self):
        with self.assertRaises(Exception):
            self.frontend.get_available_analysis_plugins()

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_raw_download_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().get_binary_and_file_name.return_value = (b'test', 'test.txt')
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_binary_and_filename('valid_uid')
        self.assertIsNone(result, 'should be none because of timeout')

        self.backend = InterComBackEndRawDownloadTask(config=self.config)
        task = self.backend.get_next_task()
        self.assertEqual(task, 'valid_uid', 'task not correct')
        result = self.frontend.get_binary_and_filename('valid_uid_0.0')
        self.assertEqual(result, (b'test', 'test.txt'), 'retrieved binary not correct')

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_peek_binary_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().read_partial_binary.return_value = b'foobar'
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.peek_in_binary('valid_uid', 0, 512)
        assert result is None, 'should be none because of timeout'

        self.backend = InterComBackEndPeekBinaryTask(config=self.config)
        task = self.backend.get_next_task()
        assert task == ('valid_uid', 0, 512), 'task not correct'
        result = self.frontend.peek_in_binary('valid_uid', 0, 512)
        assert result == b'foobar', 'retrieved binary not correct'

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_tar_repack_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().get_repacked_binary_and_file_name.return_value = (b'test', 'test.tar')
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_repacked_binary_and_file_name('valid_uid')
        self.assertIsNone(result, 'should be none because of timeout')

        self.backend = InterComBackEndTarRepackTask(config=self.config)
        task = self.backend.get_next_task()
        self.assertEqual(task, 'valid_uid', 'task not correct')
        result = self.frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        self.assertEqual(result, (b'test', 'test.tar'), 'retrieved binary not correct')
