import gc
import os
import unittest
import unittest.mock
from multiprocessing import Queue

from helperFunctions.config import get_config_for_testing
from helperFunctions.fileSystem import get_test_data_dir
from objects.firmware import Firmware
from scheduler.Analysis import AnalysisScheduler, MANDATORY_PLUGINS
from test.common_helper import DatabaseMock, fake_exit


class TestScheduleInitialAnalysis(unittest.TestCase):

    def setUp(self):
        self.mocked_interface = DatabaseMock()
        self.enter_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__enter__', new=lambda _: self.mocked_interface)
        self.enter_patch.start()
        self.exit_patch = unittest.mock.patch(target='helperFunctions.web_interface.ConnectTo.__exit__', new=fake_exit)
        self.exit_patch.start()

        config = get_config_for_testing()
        config.add_section('ip_and_uri_finder')
        config.set('ip_and_uri_finder', 'signature_directory', 'analysis/signatures/ip_and_uri_finder/')
        config.add_section('default_plugins')
        config.set('default_plugins', 'default', 'file_hashes')
        self.tmp_queue = Queue()
        self.sched = AnalysisScheduler(config=config, pre_analysis=lambda *_: None, post_analysis=self.dummy_callback, db_interface=DatabaseMock())

    def tearDown(self):
        self.sched.shutdown()

        self.tmp_queue.close()

        self.enter_patch.stop()
        self.exit_patch.stop()
        self.mocked_interface.shutdown()
        gc.collect()

    def test_plugin_registration(self):
        self.assertIn('dummy_plugin_for_testing_only', self.sched.analysis_plugins, 'Dummy plugin not found')

    def test_schedule_firmware_init_no_analysis_selected(self):
        self.sched.shutdown()
        self.sched.process_queue = Queue()
        test_fw = Firmware(binary=b'test')
        self.sched.add_task(test_fw)
        test_fw = self.sched.process_queue.get(timeout=5)
        self.assertEqual(len(test_fw.scheduled_analysis), len(MANDATORY_PLUGINS), 'Mandatory Plugins not selected')
        for item in MANDATORY_PLUGINS:
            self.assertIn(item, test_fw.scheduled_analysis)

    def test_whole_run_analysis_selected(self):
        test_fw = Firmware(file_path=os.path.join(get_test_data_dir(), 'get_files_test/testfile1'))
        test_fw.scheduled_analysis = ['dummy_plugin_for_testing_only']
        self.sched.add_task(test_fw)
        for _ in range(3):  # 3 plugins have to run
            test_fw = self.tmp_queue.get(timeout=10)
        self.assertEqual(len(test_fw.processed_analysis), 3, 'analysis not done')
        self.assertEqual(test_fw.processed_analysis['dummy_plugin_for_testing_only']['1'], 'first result', 'result not correct')
        self.assertEqual(test_fw.processed_analysis['dummy_plugin_for_testing_only']['summary'], ['first result', 'second result'])
        self.assertIn('file_hashes', test_fw.processed_analysis.keys(), 'Mandatory plug-in not executed')
        self.assertIn('file_type', test_fw.processed_analysis.keys(), 'Mandatory plug-in not executed')

    def test_expected_plugins_are_found(self):
        result = self.sched.get_plugin_dict()

        self.assertIn('file_hashes', result.keys(), 'file hashes plugin not found')
        self.assertIn('file_type', result.keys(), 'file type plugin not found')

        self.assertNotIn('dummy_plug_in_for_testing_only', result.keys(), 'dummy plug-in not removed')

    def test_get_plugin_dict_description(self):
        result = self.sched.get_plugin_dict()
        self.assertEqual(result['file_type'][0], self.sched.analysis_plugins['file_type'].DESCRIPTION, 'description not correct')

    def test_get_plugin_dict_flags(self):
        result = self.sched.get_plugin_dict()

        self.assertTrue(result['file_hashes'][1], 'mandatory flag not set')
        self.assertTrue(result['unpacker'][1], 'unpacker plugin not marked as mandatory')

        self.assertTrue(result['file_hashes'][2]['default'], 'default flag not set')
        self.assertFalse(result['file_type'][2]['default'], 'default flag set but should not')

    def test_get_plugin_dict_version(self):
        result = self.sched.get_plugin_dict()
        self.assertEqual(self.sched.analysis_plugins['file_type'].VERSION, result['file_type'][3], 'version not correct')
        self.assertEqual(self.sched.analysis_plugins['file_hashes'].VERSION, result['file_hashes'][3], 'version not correct')

    def dummy_callback(self, fw, _):
        self.tmp_queue.put(fw)
