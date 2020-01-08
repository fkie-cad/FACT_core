# pylint: disable=protected-access
import gc
import os
import unittest
from configparser import ConfigParser
from time import sleep

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from plugins.analysis.dummy.code.dummy import AnalysisPlugin as DummyPlugin


class TestPluginBase(unittest.TestCase):

    def setUp(self):
        config = self.set_up_base_config()
        self.base_plugin = AnalysisBasePlugin(self, config)

    @staticmethod
    def set_up_base_config():
        config = ConfigParser()
        config.add_section('base')
        config.set('base', 'threads', '2')
        config.add_section('ExpertSettings')
        config.set('ExpertSettings', 'block_delay', '0.1')
        return config

    def tearDown(self):
        self.base_plugin.shutdown()
        gc.collect()

    def register_plugin(self, name, plugin_object):
        '''
        This is a mock checking if the plugin registers correctly
        '''
        self.assertEqual(name, 'base', 'plugin registers with wrong name')
        self.assertEqual(plugin_object.NAME, 'base', 'plugin object has wrong name')


class TestPluginBaseCore(TestPluginBase):

    @staticmethod
    def test_start_stop_workers():
        sleep(2)

    def test_object_processing_no_childs(self):
        root_object = FileObject(binary=b'root_file')
        self.base_plugin.in_queue.put(root_object)
        processed_object = self.base_plugin.out_queue.get()
        self.assertEqual(processed_object.uid, root_object.uid, 'uid changed')
        self.assertTrue('base' in processed_object.processed_analysis, 'object not processed')
        self.assertEqual(processed_object.processed_analysis['base']['plugin_version'], 'not set', 'plugin version missing in results')
        self.assertGreater(processed_object.processed_analysis['base']['analysis_date'], 1, 'analysis date missing in results')

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
        fo = FileObject(binary='test', scheduled_analysis=[])

        fo.depth = 1
        self.base_plugin.recursive = False
        self.assertFalse(self.base_plugin._analysis_depth_not_reached_yet(fo), 'positive but not root object')

        fo.depth = 0
        self.base_plugin.recursive = False
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

        fo.depth = 1
        self.base_plugin.recursive = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

        fo.depth = 0
        self.base_plugin.recursive = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo))

    def test__add_job__recursive_is_set(self):
        fo = FileObject(binary='test', scheduled_analysis=[])
        fo.depth = 1
        self.base_plugin.recursive = False
        self.base_plugin.add_job(fo)
        out_fo = self.base_plugin.out_queue.get(timeout=5)
        self.assertIsInstance(out_fo, FileObject, 'not added to out_queue')
        self.base_plugin.recursive = True
        self.assertTrue(self.base_plugin._analysis_depth_not_reached_yet(fo), 'not positive but recursive')


class TestPluginBaseOffline(TestPluginBase):

    def setUp(self):
        self.base_plugin = AnalysisBasePlugin(self, config=self.set_up_base_config(), offline_testing=True)

    def test_get_view_file_path(self):
        plugin_path = os.path.join(get_src_dir(), 'plugins/analysis/file_type/')
        code_path = os.path.join(plugin_path, 'code/file_type.py')
        estimated_view_path = os.path.join(plugin_path, 'view/file_type.html')

        assert self.base_plugin._get_view_file_path(code_path) == estimated_view_path

        plugin_path_without_view = os.path.join(get_src_dir(), 'plugins/analysis/dummy/code/dummy.py')
        assert self.base_plugin._get_view_file_path(plugin_path_without_view) is None


class TestPluginNotRunning(TestPluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()
        self.p_base = None

    def tearDown(self):
        pass

    def multithread_config_test(self, multithread_flag, threads_in_config, threads_wanted):
        self.config.set('base', 'threads', threads_in_config)
        self.p_base = AnalysisBasePlugin(self, self.config, no_multithread=multithread_flag)
        self.assertEqual(self.p_base.config[self.p_base.NAME]['threads'], threads_wanted, 'number of threads not correct')
        self.p_base.shutdown()

    def test_no_multithread(self):
        self.multithread_config_test(True, '4', '1')

    def test_normal_multithread(self):
        self.multithread_config_test(False, '2', '2')

    def test_init_result_dict(self):
        self.p_base = AnalysisBasePlugin(self, self.config)
        resultdict = self.p_base.init_dict()
        self.assertIn('analysis_date', resultdict, 'analysis date missing')
        self.assertEqual(resultdict['plugin_version'], 'not set', 'plugin version field not correct')
        self.p_base.shutdown()


class TestPluginTimeout(TestPluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()
        self.p_base = None

    def tearDown(self):
        pass

    def test_timeout(self):
        self.p_base = DummyPlugin(self, self.config, timeout=0)
        fo_in = FileObject(binary='test', scheduled_analysis=[])
        self.p_base.add_job(fo_in)
        fo_out = self.p_base.out_queue.get(timeout=5)
        self.p_base.shutdown()
        self.assertNotIn('summary', fo_out.processed_analysis['dummy_plugin_for_testing_only'])

    def register_plugin(self, name, plugin_object):
        pass
