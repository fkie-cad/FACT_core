from __future__ import annotations

import gc
from typing import Type, TYPE_CHECKING

from test.common_helper import CommonDatabaseMock, create_test_firmware

if TYPE_CHECKING:
    from compare.PluginBase import CompareBasePlugin


class ComparePluginTest:
    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'base'
    PLUGIN_CLASS: Type[CompareBasePlugin] | None = None

    def setup_method(self):
        self.compare_plugins = {}
        self.c_plugin = self.setup_plugin()
        self.setup_test_fw()

    def teardown_method(self):
        gc.collect()

    def setup_plugin(self):
        """
        This function can be overwritten by the test instance.
        """
        assert self.PLUGIN_CLASS is not None, f'PLUGIN_CLASS should be set by {self.__class__}'
        db_mock = CommonDatabaseMock()
        return self.PLUGIN_CLASS(
            db_interface=db_mock,
            view_updater=db_mock,
        )

    def setup_test_fw(self):
        self.fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
        self.fw_two = create_test_firmware(
            device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True
        )
        self.fw_three = create_test_firmware(
            device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True
        )
