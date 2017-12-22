from configparser import ConfigParser
import gc
import os
from time import sleep
import unittest

from analysis.PluginBase import BasePlugin
from helperFunctions.fileSystem import get_src_dir
from objects.file import FileObject
from plugins.analysis.dummy.code.dummy import AnalysisPlugin as DummyPlugin
from test.common_helper import create_test_file_object


class Test_PluginBase(unittest.TestCase):

    def setUp(self):
        config = self.set_up_base_config()
        self.pBase = BasePlugin(self, config)

    def set_up_base_config(self):
        config = ConfigParser()
        config.add_section('base')
        config.set('base', 'threads', '2')
        config.add_section('ExpertSettings')
        config.set('ExpertSettings', 'block_delay', '2')
        return config

    def tearDown(self):
        self.pBase.shutdown()
        gc.collect()

    def register_plugin(self, name, plugin_object):
        '''
        This is a mock checking if the plugin registers correctly
        '''
        self.assertEqual(name, 'base', 'plugin registers with wrong name')
        self.assertEqual(plugin_object.NAME, 'base', 'plugin object has wrong name')


class Test_PluginBaseCore(Test_PluginBase):

    def test_start_stop_workers(self):
        sleep(2)

    def test_object_processing_no_childs(self):
        root_object = FileObject(binary=b'root_file')
        self.pBase.in_queue.put(root_object)
        processed_object = self.pBase.out_queue.get()
        self.assertEqual(processed_object.get_uid(), root_object.get_uid(), 'uid changed')
        self.assertTrue('base' in processed_object.processed_analysis, 'object not processed')
        self.assertEqual(processed_object.processed_analysis['base']['plugin_version'], 'not set', 'plugin version missing in results')
        self.assertGreater(processed_object.processed_analysis['base']['analysis_date'], 1, 'analysis date missing in results')

    def test_object_processing_one_child(self):
        root_object = FileObject(binary=b'root_file')
        child_object = FileObject(binary=b'first_child_object')
        root_object.add_included_file(child_object)
        self.pBase.in_queue.put(root_object)
        processed_object = self.pBase.out_queue.get()
        self.assertEqual(processed_object.get_uid(), root_object.get_uid(), 'uid changed')
        self.assertTrue(child_object.get_uid() in root_object.get_included_files_uids(), 'child object not in processed file')


class Test_PluginBase_add_job(Test_PluginBase):

    def test_dependency_condition_check_no_deps(self):
        fo = FileObject(binary='test', scheduled_analysis=[])
        self.assertTrue(self.pBase.dependency_condition_check(fo), 'no deps specified')

    def test_dependency_condition_check_unmatched_deps(self):
        self.pBase.DEPENDENCYS = ['foo']
        fo = FileObject(binary='test', scheduled_analysis=[])
        self.assertFalse(self.pBase.dependency_condition_check(fo), 'deps specified and unmatched')
        out_fo = self.pBase.out_queue.get(timeout=5)
        self.assertEqual(out_fo.scheduled_analysis, ['base', 'foo'], 'analysis not scheduled')
        self.assertIn('foo', out_fo.analysis_dependency, 'analysis not added to needed dependencys')

    def test_dependency_condition_check_matched_deps(self):
        self.pBase.DEPENDENCYS = ['foo']
        fo = FileObject(binary='test', scheduled_analysis=[])
        fo.processed_analysis.update({'foo': []})
        self.assertTrue(self.pBase.dependency_condition_check(fo), 'Fals but deps matched')

    def test_recursive_condition_check(self):
        fo = FileObject(binary='test', scheduled_analysis=[])
        fo.depth = 1
        self.pBase.recursive = False
        self.assertFalse(self.pBase.recursive_condition_check(fo), 'positive but not root object')
        out_fo = self.pBase.out_queue.get(timeout=5)
        self.assertIsInstance(out_fo, FileObject, 'not added to out_queue')
        self.pBase.recursive = True
        self.assertTrue(self.pBase.recursive_condition_check(fo), 'not positvie but recursive')

    def test_add_job_dependency_not_matched(self):
        self.pBase.DEPENDENCYS = ['foo']
        fo = FileObject(binary='test', scheduled_analysis=[])
        self.pBase.add_job(fo)
        fo = self.pBase.out_queue.get(timeout=5)
        self.assertEqual(fo.scheduled_analysis, ['base', 'foo'], 'analysis not scheduled')
        self.assertNotIn('base', fo.processed_analysis, 'base added to processed analysis, but is not processed')


class Test_PluginBase_offline(Test_PluginBase):

    def setUp(self):
        self.pBase = BasePlugin(self, config=self.set_up_base_config(), offline_testing=True)

    def test_object_history(self):
        test_fo = create_test_file_object()
        self.pBase.add_job(test_fo)
        result = self.pBase.in_queue.get(timeout=5)
        self.assertTrue(self.pBase.out_queue.empty(), 'added to outque but not in history')
        self.pBase.add_job(test_fo)
        result = self.pBase.out_queue.get(timeout=5)
        self.assertTrue(self.pBase.in_queue.empty(), 'added to inque but already in history')
        # required dependency check
        test_fo.analysis_dependency.add(self.pBase.NAME)
        self.pBase.add_job(test_fo)
        result = self.pBase.in_queue.get(timeout=5)
        self.assertTrue(self.pBase.out_queue.empty(), 'added to out queue but should be reanalyzed because of dependency request')

    def test_get_view_file_path(self):
        plugin_path = os.path.join(get_src_dir(), 'plugins/analysis/file_type/')
        code_path = os.path.join(plugin_path, 'code/file_type.py')
        estimated_view_path = os.path.join(plugin_path, 'view/file_type.html')

        assert self.pBase._get_view_file_path(code_path) == estimated_view_path

        plugin_path_without_view = os.path.join(get_src_dir(), 'plugins/analysis/dummy/code/dummy.py')
        assert self.pBase._get_view_file_path(plugin_path_without_view) is None


class Test_Plugin_not_running(Test_PluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()

    def tearDown(self):
        pass

    def multithread_config_test(self, multithread_flag, threads_in_config, threads_wanted):
        self.config.set('base', 'threads', threads_in_config)
        self.pBase = BasePlugin(self, self.config, no_multithread=multithread_flag)
        self.assertEqual(self.pBase.config[self.pBase.NAME]['threads'], threads_wanted, 'number of threads not correct')
        self.pBase.shutdown()

    def test_no_multithread(self):
        self.multithread_config_test(True, '4', '1')

    def test_normal_multithread(self):
        self.multithread_config_test(False, '2', '2')

    def test_init_result_dict(self):
        self.pBase = BasePlugin(self, self.config)
        resultdict = self.pBase.init_dict()
        self.assertIn('analysis_date', resultdict, 'analysis date missing')
        self.assertEqual(resultdict['plugin_version'], 'not set', 'plugin version field not correct')
        self.pBase.shutdown()


class TestPluginTimeout(Test_PluginBase):

    def setUp(self):
        self.config = self.set_up_base_config()

    def tearDown(self):
        pass

    def test_timeout(self):
        self.pBase = DummyPlugin(self, self.config, timeout=0)
        fo_in = FileObject(binary='test', scheduled_analysis=[])
        self.pBase.add_job(fo_in)
        fo_out = self.pBase.out_queue.get(timeout=5)
        self.pBase.shutdown()
        self.assertNotIn('summary', fo_out.processed_analysis['dummy_plugin_for_testing_only'])

    def register_plugin(self, name, plugin_object):
        pass
