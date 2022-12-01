import unittest.mock
from configparser import ConfigParser
from typing import Callable

from test.common_helper import (  # pylint: disable=wrong-import-order
    CommonDatabaseMock,
    create_docker_mount_base_dir,
    load_users_from_main_config,
)


class AnalysisPluginTest(unittest.TestCase):
    '''
    This is the base class for analysis plugin test.unit
    '''

    # must be set by individual plugin test class
    PLUGIN_NAME = 'plugin_test'
    PLUGIN_CLASS: Callable = None

    def setUp(self):
        self.docker_mount_base_dir = create_docker_mount_base_dir()
        self.config = self.init_basic_config()
        self._set_config()
        self.analysis_plugin = self.setup_plugin()

    def _set_config(self):
        pass  # set individual config in plugin tests if necessary

    def setup_plugin(self):
        # overwrite in plugin tests if necessary
        return self.PLUGIN_CLASS(view_updater=CommonDatabaseMock())

    def tearDown(self):

        self.analysis_plugin.shutdown()  # pylint: disable=no-member

    def init_basic_config(self):
        config = ConfigParser()
        config.add_section(self.PLUGIN_NAME)
        config.set(self.PLUGIN_NAME, 'threads', '1')
        config.add_section('expert-settings')
        config.set('expert-settings', 'block-delay', '0.1')
        config.add_section('data-storage')
        load_users_from_main_config(config)
        config.set('data-storage', 'docker-mount-base-dir', str(self.docker_mount_base_dir))
        # -- postgres --
        config.set('data-storage', 'postgres-server', 'localhost')
        config.set('data-storage', 'postgres-port', '5432')
        config.set('data-storage', 'postgres-database', 'fact-test')

        return config
