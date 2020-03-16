import gc
import unittest
import unittest.mock
from configparser import ConfigParser

from test.common_helper import DatabaseMock, fake_exit, load_users_from_main_config


class AnalysisPluginTest(unittest.TestCase):
    '''
    This is the base class for analysis plugin test.unit
    '''

    PLUGIN_NAME = 'plugin_test'

    def setUp(self):
        self.mocked_interface = DatabaseMock()

        self.enter_patch = unittest.mock.patch(target='helperFunctions.database.ConnectTo.__enter__', new=lambda _: self.mocked_interface)
        self.enter_patch.start()

        self.exit_patch = unittest.mock.patch(target='helperFunctions.database.ConnectTo.__exit__', new=fake_exit)
        self.exit_patch.start()

    def tearDown(self):
        self.analysis_plugin.shutdown()  # pylint: disable=no-member

        self.enter_patch.stop()
        self.exit_patch.stop()

        self.mocked_interface.shutdown()
        gc.collect()

    def init_basic_config(self):
        config = ConfigParser()
        config.add_section(self.PLUGIN_NAME)
        config.set(self.PLUGIN_NAME, 'threads', '1')
        config.add_section('ExpertSettings')
        config.set('ExpertSettings', 'block_delay', '2')
        config.add_section('data_storage')
        load_users_from_main_config(config)
        config.set('data_storage', 'mongo_server', 'localhost')
        config.set('data_storage', 'mongo_port', '54321')
        config.set('data_storage', 'view_storage', 'tmp_view')
        return config

    def register_plugin(self, name, plugin_object):
        '''
        This is a mock checking if the plugin registers correctly
        '''
        self.assertEqual(name, self.PLUGIN_NAME, 'plugin registers with wrong name')
        self.assertEqual(plugin_object.NAME, self.PLUGIN_NAME, 'plugin object has wrong name')
        self.assertIsInstance(plugin_object.DESCRIPTION, str)
        self.assertIsInstance(plugin_object.VERSION, str)
        self.assertNotEqual(plugin_object.VERSION, 'not set', 'Plug-in version not set')
