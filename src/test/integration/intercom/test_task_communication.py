import gc
import os
from unittest import mock

import pytest

from intercom.back_end_binding import (
    InterComBackEndAnalysisPlugInsPublisher, InterComBackEndAnalysisTask, InterComBackEndCompareTask,
    InterComBackEndRawDownloadTask, InterComBackEndReAnalyzeTask, InterComBackEndSingleFileTask,
    InterComBackEndTarRepackTask
)
from intercom.front_end_binding import InterComFrontEndBinding
from storage.fs_organizer import FS_Organizer
from test.common_helper import TestBase, create_test_firmware


class AnalysisServiceMock:

    def __init__(self, config=None):
        pass

    def get_plugin_dict(self):  # pylint: disable=no-self-use
        return {'dummy': 'dummy description'}


@pytest.mark.usefixtures('start_db')
class TestInterComTaskCommunication(TestBase):

    @classmethod
    def setup_class(cls):
        super().setup_class()
        cls.config.set('ExpertSettings', 'communication_timeout', '1')

    def setup(self):
        self.frontend = InterComFrontEndBinding(config=self.config)
        self.backend = None

    def teardown(self):
        for item in self.frontend.connections.keys():
            self.frontend.client.drop_database(self.frontend.connections[item]['name'])
        if self.backend:
            self.backend.shutdown()
        self.frontend.shutdown()
        gc.collect()

    def test_analysis_task(self):
        self.backend = InterComBackEndAnalysisTask(config=self.config)
        test_fw = create_test_firmware()
        test_fw.file_path = None
        self.frontend.add_analysis_task(test_fw)
        task = self.backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'
        assert task.file_path is not None, 'file_path not set'
        assert os.path.exists(task.file_path), 'file does not exist'

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
        fs_organizer = FS_Organizer(config=self.config)
        test_fw = create_test_firmware()
        fs_organizer.store_file(test_fw)
        original_file_path = test_fw.file_path
        original_binary = test_fw.binary
        test_fw.file_path = None
        test_fw.binary = None
        self.frontend.add_re_analyze_task(test_fw)
        task = self.backend.get_next_task()
        assert task.uid == test_fw.uid, 'uid not correct'
        assert task.file_path is not None, 'file path not set'
        assert task.file_path == original_file_path
        assert task.binary is not None, 'binary not set'
        assert task.binary == original_binary, 'binary content not correct'

    def test_compare_task(self):
        self.backend = InterComBackEndCompareTask(config=self.config)
        self.frontend.add_compare_task('valid_id', force=False)
        result = self.backend.get_next_task()
        assert result == ('valid_id', False)

    def test_analysis_plugin_publication(self):
        self.backend = InterComBackEndAnalysisPlugInsPublisher(config=self.config, analysis_service=AnalysisServiceMock())
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

        self.backend = InterComBackEndRawDownloadTask(config=self.config)
        task = self.backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = self.frontend.get_binary_and_filename('valid_uid_0.0')
        assert result == (b'test', 'test.txt'), 'retrieved binary not correct'

    @mock.patch('intercom.front_end_binding.generate_task_id')
    @mock.patch('intercom.back_end_binding.BinaryService')
    def test_tar_repack_task(self, binary_service_mock, generate_task_id_mock):
        binary_service_mock().get_repacked_binary_and_file_name.return_value = (b'test', 'test.tar')
        generate_task_id_mock.return_value = 'valid_uid_0.0'

        result = self.frontend.get_repacked_binary_and_file_name('valid_uid')
        assert result is None, 'should be none because of timeout'

        self.backend = InterComBackEndTarRepackTask(config=self.config)
        task = self.backend.get_next_task()
        assert task == 'valid_uid', 'task not correct'
        result = self.frontend.get_repacked_binary_and_file_name('valid_uid_0.0')
        assert result == (b'test', 'test.tar'), 'retrieved binary not correct'
