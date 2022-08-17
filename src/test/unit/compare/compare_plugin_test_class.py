# pylint: disable=attribute-defined-outside-init,not-callable,no-self-use
import gc
from configparser import ConfigParser

from test.common_helper import CommonDatabaseMock, create_test_firmware  # pylint: disable=wrong-import-order


class ComparePluginTest:

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'base'
    PLUGIN_CLASS = None

    def setup(self):
        self.config = self.generate_config()
        self.config.add_section('expert-settings')
        self.config.set('expert-settings', 'ssdeep-ignore', '80')
        self.compare_plugins = {}
        self.c_plugin = self.setup_plugin()
        self.setup_test_fw()

    def teardown(self):
        gc.collect()

    def setup_plugin(self):
        '''
        This function can be overwritten by the test instance.
        '''
        return self.PLUGIN_CLASS(self, config=self.config, view_updater=CommonDatabaseMock())

    def generate_config(self):  # pylint: disable=no-self-use
        '''
        This function can be overwritten by the test instance if a special config is needed
        '''
        return ConfigParser()

    def test_init(self):
        assert len(self.compare_plugins) == 1, 'number of registered plugins not correct'
        assert self.compare_plugins[self.PLUGIN_NAME].NAME == self.PLUGIN_NAME, 'plugin instance not correct'

    def register_plugin(self, plugin_name, plugin_instance):
        '''
        Callback Function Mock
        '''
        self.compare_plugins[plugin_name] = plugin_instance

    def setup_test_fw(self):
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_two = create_test_firmware(
            device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True,
        )
        self.fw_three = create_test_firmware(
            device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True,
        )
