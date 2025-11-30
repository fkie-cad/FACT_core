import gc
from configparser import ConfigParser

from test.common_helper import CommonDatabaseMock, create_test_firmware


class ComparisonPluginTest:
    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'base'
    PLUGIN_CLASS = None

    def setup_method(self):
        self.config = self.generate_config()
        self.config.add_section('expert-settings')
        self.config.set('expert-settings', 'ssdeep-ignore', '80')
        self.comparison_plugins = {}
        self.c_plugin = self.setup_plugin()
        self.setup_test_fw()

    def teardown_method(self):
        gc.collect()

    def setup_plugin(self):
        """
        This function can be overwritten by the test instance.
        """
        return self.PLUGIN_CLASS(config=self.config, view_updater=CommonDatabaseMock())

    def generate_config(self):
        """
        This function can be overwritten by the test instance if a special config is needed
        """
        return ConfigParser()

    def setup_test_fw(self):
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_two = create_test_firmware(
            device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True
        )
        self.fw_three = create_test_firmware(
            device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True
        )
