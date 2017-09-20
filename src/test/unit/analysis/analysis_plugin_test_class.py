import unittest

from configparser import ConfigParser
from helperFunctions.config import load_config


class AnalysisPluginTest(unittest.TestCase):
    '''
    This is the base class for analysis plugin test.unit
    '''

    PLUGIN_NAME = "plugin_test"

    def setUp(self):
        pass

    def tearDown(self):
        self.analysis_plugin.shutdown()

    def init_basic_config(self):
        config = ConfigParser()
        config.add_section(self.PLUGIN_NAME)
        config.set(self.PLUGIN_NAME, 'threads', "1")
        config.add_section('ExpertSettings')
        config.set('ExpertSettings', 'block_delay', "2")
        config.add_section('data_storage')
        faf_config = load_config("main.cfg")
        config.set('data_storage', 'db_admin_user', faf_config['data_storage']['db_admin_user'])
        config.set('data_storage', "db_admin_pw", faf_config['data_storage']['db_admin_pw'])
        config.set('data_storage', "db_readonly_user", faf_config['data_storage']['db_readonly_user'])
        config.set('data_storage', "db_readonly_pw", faf_config['data_storage']['db_readonly_pw'])
        return config

    def register_plugin(self, name, plugin_object):
        '''
        This is a mock checking if the plugin registers correctly
        '''
        self.assertEqual(name, self.PLUGIN_NAME, "plugin registers with wrong name")
        self.assertEqual(plugin_object.NAME, self.PLUGIN_NAME, "plugin object has wrong name")
        self.assertIsInstance(plugin_object.DESCRIPTION, str)
        self.assertIsInstance(plugin_object.VERSION, str)
        self.assertNotEqual(plugin_object.VERSION, "not set", "Plug-in version not set")
