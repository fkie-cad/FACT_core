from configparser import ConfigParser
import gc
import unittest

from compare.PluginBase import CompareBasePlugin as ComparePlugin
from test.common_helper import create_test_firmware


class ComparePluginTest(unittest.TestCase):

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'base'

    def setUp(self):
        self.config = self.generate_config()
        self.config.add_section('ExpertSettings')
        self.config.set('ExpertSettings', 'ssdeep_ignore', '80')
        self.compare_plugins = {}
        self.c_plugin = self.setup_plugin()
        self.setup_test_fw()

    def tearDown(self):
        gc.collect()

    def setup_plugin(self):
        '''
        This function must be overwritten by the test instance.
        In most cases it is sufficient to copy this function.
        '''
        return ComparePlugin(self, config=self.config)

    def generate_config(self):
        '''
        This function can be overwritten by the test instance if a special config is needed
        '''
        return ConfigParser()

    def test_init(self):
        self.assertEqual(len(self.compare_plugins), 1, 'number of registered plugins not correct')
        self.assertEqual(self.compare_plugins[self.PLUGIN_NAME].NAME, self.PLUGIN_NAME, 'plugin instance not correct')

    def register_plugin(self, plugin_name, plugin_instance):
        '''
        Callback Function Mock
        '''
        self.compare_plugins[plugin_name] = plugin_instance

    def setup_test_fw(self):
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_two = create_test_firmware(device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True)
        self.fw_three = create_test_firmware(device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True)
