import unittest.mock
from configparser import ConfigParser

from test.common_helper import CommonDatabaseMock, load_users_from_main_config  # pylint: disable=wrong-import-order


class AnalysisPluginTest(unittest.TestCase):
    '''
    This is the base class for analysis plugin test.unit
    '''

    # must be set by individual plugin test class
    PLUGIN_NAME = 'plugin_test'
    PLUGIN_CLASS = None

    def setUp(self):
        self.config = self.init_basic_config()
        self._set_config()
        self.analysis_plugin = self.setup_plugin()

    def _set_config(self):
        pass  # set individual config in plugin tests if necessary

    def setup_plugin(self):
        # overwrite in plugin tests if necessary
        return self.PLUGIN_CLASS(self, config=self.config, view_updater=CommonDatabaseMock())  # pylint: disable=not-callable

    def tearDown(self):
        self.analysis_plugin.shutdown()  # pylint: disable=no-member

    def init_basic_config(self):
        config = ConfigParser()
        config.add_section(self.PLUGIN_NAME)
        config.set(self.PLUGIN_NAME, 'threads', '1')
        config.add_section('ExpertSettings')
        config.set('ExpertSettings', 'block_delay', '0.1')
        config.add_section('data_storage')
        load_users_from_main_config(config)
        config.set('data_storage', 'mongo_server', 'localhost')
        config.set('data_storage', 'mongo_port', '54321')
        config.set('data_storage', 'view_storage', 'tmp_view')
        # -- postgres -- FixMe? --
        config.set('data_storage', 'postgres_server', 'localhost')
        config.set('data_storage', 'postgres_port', '5432')
        config.set('data_storage', 'postgres_database', 'fact_test')
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
