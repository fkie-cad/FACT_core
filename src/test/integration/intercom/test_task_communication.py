# pylint: disable=wrong-import-order
from __future__ import annotations

import gc
import os
import unittest
from unittest import mock

import pytest

from intercom.back_end_binding import (
    InterComBackEndAnalysisPlugInsPublisher,
    InterComBackEndAnalysisTask,
    InterComBackEndCompareTask,
    InterComBackEndFileDiffTask,
    InterComBackEndPeekBinaryTask,
    InterComBackEndRawDownloadTask,
    InterComBackEndReAnalyzeTask,
    InterComBackEndSingleFileTask,
    InterComBackEndTarRepackTask,
)
from intercom.front_end_binding import InterComFrontEndBinding
from test.common_helper import create_test_firmware


class AnalysisServiceMock:
    def get_plugin_dict(self):  # pylint: disable=no-self-use
        return {'dummy': 'dummy description'}


class BinaryServiceMock:
    def __init__(self, *_, **__):
        pass

    @staticmethod
    def get_binary_and_file_name(uid: str) -> tuple[bytes, str]:
        if uid == 'uid1':
            return b'binary content 1', 'file_name_1'
        if uid == 'uid2':
            return b'binary content 2', 'file_name_2'
        assert False, 'if this line reached something went wrong'


@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'communication-timeout': '1',
        }
    }
)
class TestInterComTaskCommunication(unittest.TestCase):
    def setUp(self):
        self.frontend = InterComFrontEndBinding()
        self.backend = None

    def tearDown(self):
        self.frontend.redis.redis.flushdb()
        gc.collect()

    def test_analysis_task(self):
        self.backend = InterComBackEndAnalysisTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        self.frontend.add_analysis_task(test_fw)
        task = self.backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'
        assert task.file_path is not None, 'file_path not set'
        assert os.path.exists(task.file_path), 'file does not exist'

    def test_single_file_task(self):
        self.backend = InterComBackEndSingleFileTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        test_fw.scheduled_analysis = ['binwalk']
        self.frontend.add_single_file_task(test_fw)
        task = self.backend.get_next_task()

        assert task.uid == test_fw.uid, 'uid not transported correctly'
        assert task.scheduled_analysis

    def test_re_analyze_task(self):
        self.backend = InterComBackEndReAnalyzeTask()
        test_fw = create_test_firmware()
        test_fw.file_path = None
        self.frontend.add_re_analyze_task(test_fw)
        task = self.backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'

    def test_compare_task(self):
        self.backend = InterComBackEndCompareTask()
        self.frontend.add_compare_task('valid_id', force=False)
        result = self.backend.get_next_task()
        assert result == ('valid_id', False)

    def test_analysis_plugin_publication(self):

        self.backend = InterComBackEndAnalysisPlugInsPublisher(analysis_service=AnalysisServiceMock())
        plugins = self.frontend.get_available_analysis_plugins()
        assert len(plugins) == 1, 'Not all plug-ins found'
        assert plugins == {'dummy': 'dummy description'}, 'content not correct'

    def test_analysis_plugin_publication_not_available(self):
        with pytest.raises(Exception):
            self.frontend.get_available_analysis_plugins()

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_raw_download_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().get_binary_and_file_name.return_value = (b'test', 'test.txt')
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_binary_and_filename('valid_uid')
        assert result is None, 'should be none because of timeout'

        self.backend = InterComBackEndRawDownloadTask()
        task = self.backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = self.frontend.get_binary_and_filename('valid_uid_0.0')
        assert result == (b'test', 'test.txt'), 'retrieved binary not correct'

    @mock.patch('intercom.front_end_binding.generate_task_id', new=lambda _: 'valid_uid_0.0')
    @mock.patch('intercom.back_end_binding.BinaryService', new=BinaryServiceMock)
    def test_file_diff_task(self):

        result = self.frontend.get_file_diff(('uid1', 'uid2'))
        assert result is None, 'should be None because of timeout'

        self.backend = InterComBackEndFileDiffTask()
        task = self.backend.get_next_task()
        assert task == ('uid1', 'uid2'), 'task not correct'
        result = self.frontend.get_file_diff(('uid1', 'uid2'))
        expected_diff = '--- file_name_1\n+++ file_name_2\n@@ -1 +1 @@\n-binary content 1+binary content 2'
        assert result == expected_diff, 'file diff not correct'

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_peek_binary_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().read_partial_binary.return_value = b'foobar'
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.peek_in_binary('valid_uid', 0, 512)
        assert result is None, 'should be none because of timeout'

        self.backend = InterComBackEndPeekBinaryTask()
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
        assert result is None, 'should be none because of timeout'

        self.backend = InterComBackEndTarRepackTask()
        task = self.backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = self.frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        assert result == (b'test', 'test.tar'), 'retrieved binary not correct'
