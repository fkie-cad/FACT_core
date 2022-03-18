# pylint: disable=protected-access,redefined-outer-name,unused-argument,no-self-use

import gc
import unittest
from configparser import ConfigParser
from pathlib import Path
from time import sleep
from unittest import mock

import pytest

from analysis.PluginBase import AnalysisBasePlugin, PluginInitException
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from plugins.analysis.dummy.code.dummy import AnalysisPlugin as DummyPlugin

PLUGIN_PATH = Path(get_src_dir()) / 'plugins' / 'analysis'


class TestPluginBase(unittest.TestCase):

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def setUp(self):
        self.config = self.set_up_base_config()
        self.base_plugin = DummyPlugin(self, self.config)

    @staticmethod
    def set_up_base_config():
        config = ConfigParser()
        config.add_section('dummy_plugin_for_testing_only')
        config.set('dummy_plugin_for_testing_only', 'threads', '2')
        config.add_section('expert-settings')
        config.set('expert-settings', 'block-delay', '0.1')
        return config

    def tearDown(self):
        self.base_plugin.shutdown()
        gc.collect()

    def register_plugin(self, name, plugin_object):  # pylint: disable=no-self-use
        '''
        This is a mock checking if the plugin registers correctly
        '''
        assert name == 'dummy_plugin_for_testing_only', 'plugin registers with wrong name'
        assert plugin_object.NAME == 'dummy_plugin_for_testing_only', 'plugin object has wrong name'


class TestPluginBaseCore(TestPluginBase):

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def test_attribute_check(self):
        with pytest.raises(PluginInitException):
            AnalysisBasePlugin(self)

    @staticmethod
    def test_start_stop_workers():
        sleep(2)

    def test_object_processing_no_children(self):
        root_object = FileObject(binary=b'root_file')
        self.base_plugin.in_queue.put(root_object)
        processed_object = self.base_plugin.out_queue.get()
        self.assertEqual(processed_object.uid, root_object.uid, 'uid changed')
        self.assertTrue('dummy_plugin_for_testing_only' in processed_object.processed_analysis, 'object not processed')
        self.assertEqual(processed_object.processed_analysis['dummy_plugin_for_testing_only']['plugin_version'], '0.0', 'plugin version missing in results')
        self.assertGreater(processed_object.processed_analysis['dummy_plugin_for_testing_only']['analysis_date'], 1, 'analysis date missing in results')

    def test_object_processing_one_child(self):
        root_object = FileObject(binary=b'root_file')
        child_object = FileObject(binary=b'first_child_object')
        root_object.add_included_file(child_object)
        self.base_plugin.in_queue.put(root_object)
        processed_object = self.base_plugin.out_queue.get()
        self.assertEqual(processed_object.uid, root_object.uid, 'uid changed')
        self.assertTrue(child_object.uid in root_object.files_included, 'child object not in processed file')


class TestPluginBaseAddJob(TestPluginBase):

    def test_analysis_depth_not_reached_yet(self):
        fo = FileObject(binary=b'test', scheduled_analysis=[])

        fo.depth = 1
        self.base_plugin.RECURSIVE = False
        self.assertFalse(self.base_plugin._analysis_depth_not_reached_yet(fo), 'positive but not root object')

        fo.depth = 0
        self.base_plugin.RECURSIVE = False
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

        fo.depth = 1
        self.base_plugin.RECURSIVE = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

        fo.depth = 0
        self.base_plugin.RECURSIVE = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

    def test__add_job__recursive_is_set(self):
        fo = FileObject(binary=b'test', scheduled_analysis=[])
        fo.depth = 1
        self.base_plugin.recursive = False
        self.base_plugin.add_job(fo)
        out_fo = self.base_plugin.out_queue.get(timeout=5)
        self.assertIsInstance(out_fo, FileObject, 'not added to out_queue')
        self.base_plugin.recursive = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo), 'not positive but recursive')


class TestPluginBaseOffline:

    def test_get_view_file_path(self):
        code_path = PLUGIN_PATH / 'file_type' / 'code' / 'file_type.py'
        expected_view_path = PLUGIN_PATH / 'file_type' / 'view' / 'file_type.html'

        assert AnalysisBasePlugin._get_view_file_path(str(code_path)) == expected_view_path

        without_view = PLUGIN_PATH / 'dummy' / 'code' / 'dummy.py'
        assert AnalysisBasePlugin._get_view_file_path(str(without_view)) is None


class TestPluginNotRunning(TestPluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()
        self.p_base = None

    def tearDown(self):
        pass

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def multithread_config_test(self, multithread_flag, threads_in_config, threads_wanted):
        self.p_base = DummyPlugin(self, no_multithread=multithread_flag)
        self.assertEqual(self.p_base.thread_count, int(threads_wanted), 'number of threads not correct')
        self.p_base.shutdown()

    @pytest.mark.cfg_defaults({
        'dummy_plugin_for_testing_only': {
            'threads': '4',
        }
    })
    def test_no_multithread(self):
        self.multithread_config_test(True, '4', '1')

    @pytest.mark.cfg_defaults({
        'dummy_plugin_for_testing_only': {
            'threads': '2',
        }
    })
    def test_normal_multithread(self):
        self.multithread_config_test(False, '2', '2')

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def test_init_result_dict(self):
        self.p_base = DummyPlugin(self, self.config)
        resultdict = self.p_base.init_dict()
        self.assertIn('analysis_date', resultdict, 'analysis date missing')
        self.assertEqual(resultdict['plugin_version'], '0.0', 'plugin version field not correct')
        self.p_base.shutdown()


class TestPluginTimeout(TestPluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()
        self.p_base = None

    def tearDown(self):
        pass

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    @mock.patch('plugins.analysis.dummy.code.dummy.AnalysisPlugin.TIMEOUT', 0)
    def test_timeout(self):
        self.p_base = DummyPlugin(self, self.config)
        fo_in = FileObject(binary=b'test', scheduled_analysis=[])
        self.p_base.add_job(fo_in)
        fo_out = self.p_base.out_queue.get(timeout=5)
        self.p_base.shutdown()
        self.assertNotIn('summary', fo_out.processed_analysis['dummy_plugin_for_testing_only'])

    def register_plugin(self, name, plugin_object):
        pass
