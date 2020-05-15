# pylint: disable=protected-access
import gc
import os
from shutil import copyfile

import pytest

from intercom.common_mongo_binding import InterComListener
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import TestBase, create_test_file_object, create_test_firmware, get_test_data_dir

TESTS_DIR = get_test_data_dir()
TEST_FILE_ORIGINAL = os.path.join(TESTS_DIR, 'get_files_test/testfile1')
TEST_FILE_COPY = os.path.join(TESTS_DIR, 'get_files_test/testfile_copy')
TEST_FIRMWARE_ORIGINAL = os.path.join(TESTS_DIR, 'container/test.zip')
TEST_FIRMWARE_COPY = os.path.join(TESTS_DIR, 'container/test_copy.zip')


@pytest.mark.usefixtures('start_db')
class TestStorageDbInterfaceAdmin(TestBase):

    @classmethod
    def setup_class(cls):
        super().setup_class()
        cls.config.set('data_storage', 'sanitize_database', 'tmp_sanitize')
        cls.config.set('data_storage', 'report_threshold', '32')

    def setup(self):
        self.admin_interface = AdminDbInterface(config=self.config)
        self.db_backend_interface = BackEndDbInterface(config=self.config)
        copyfile(TEST_FIRMWARE_ORIGINAL, TEST_FIRMWARE_COPY)
        self.test_firmware = create_test_firmware(bin_path='container/test_copy.zip')
        self.uid = self.test_firmware.uid
        self.test_firmware.virtual_file_path = {self.uid: ['|{}|'.format(self.test_firmware.uid)]}
        copyfile(TEST_FILE_ORIGINAL, TEST_FILE_COPY)
        self.child_fo = create_test_file_object(TEST_FILE_COPY)
        self.child_fo.virtual_file_path = {self.uid: ['|{}|/folder/{}'.format(self.uid, self.child_fo.file_name)]}
        self.test_firmware.files_included = [self.child_fo.uid]
        self.child_uid = self.child_fo.uid

    def teardown(self):
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'main_database'))
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'sanitize_database'))
        self.admin_interface.shutdown()
        self.db_backend_interface.shutdown()
        gc.collect()

    @classmethod
    def teardown_class(cls):
        for test_file in [TEST_FILE_COPY, TEST_FIRMWARE_COPY]:
            if os.path.isfile(test_file):
                os.remove(test_file)
        super().teardown_class()

    def test_remove_object_field(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        assert self.uid in self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path']
        self.admin_interface.remove_object_field(self.child_uid, 'virtual_file_path.{}'.format(self.uid))
        assert self.uid not in self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path']

    def test_remove_virtual_path_entries_no_other_roots(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        assert self.uid in self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path']
        removed_vps, deleted_files = self.admin_interface._remove_virtual_path_entries(self.uid, self.child_fo.uid)
        assert self.db_backend_interface.file_objects.find_one(self.child_uid) is None
        assert removed_vps == 0
        assert deleted_files == 1

    def test_remove_virtual_path_entries_other_roots(self):
        self.child_fo.virtual_file_path.update({'someuid': ['|someuid|/some/virtual/path']})
        self.db_backend_interface.add_file_object(self.child_fo)
        assert self.uid in self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path']
        removed_vps, deleted_files = self.admin_interface._remove_virtual_path_entries(self.uid, self.child_fo.uid)
        assert self.uid not in self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path']
        assert removed_vps == 1
        assert deleted_files == 0

    def test_delete_swapped_analysis_entries(self):
        self.test_firmware.processed_analysis = {'test_plugin': {'result': 10000000000, 'misc': 'delete_swap_test'}}
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'sanitize_database'))
        self.admin_interface.sanitize_analysis(self.test_firmware.processed_analysis, self.uid)
        assert 'test_plugin_result_{}'.format(self.test_firmware.uid) in self.admin_interface.sanitize_fs.list()
        self.admin_interface._delete_swapped_analysis_entries(self.admin_interface.firmwares.find_one(self.uid))
        assert 'test_plugin_result_{}'.format(self.test_firmware.uid) not in self.admin_interface.sanitize_fs.list()

    def test_delete_file_object(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        db_entry = self.db_backend_interface.file_objects.find_one(self.child_fo.uid)
        assert db_entry is not None
        self.admin_interface._delete_file_object(db_entry)
        assert self.db_backend_interface.file_objects.find_one(self.child_fo.uid) is None, 'file not deleted from db'
        delete_tasks = self._get_delete_tasks()
        assert self.child_fo.uid in delete_tasks, 'file not found in delete tasks'

    def test_delete_firmware(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.db_backend_interface.add_file_object(self.child_fo)
        assert self.db_backend_interface.firmwares.find_one(self.uid) is not None
        assert self.db_backend_interface.file_objects.find_one(self.child_uid) is not None
        assert os.path.isfile(self.test_firmware.file_path)
        assert os.path.isfile(self.child_fo.file_path)
        removed_vps, deleted_files = self.admin_interface.delete_firmware(self.uid)
        assert self.db_backend_interface.firmwares.find_one(self.uid) is None, 'firmware not deleted from db'
        assert self.db_backend_interface.file_objects.find_one(self.child_uid) is None, 'child not deleted from db'
        assert removed_vps == 0
        assert deleted_files == 2, 'number of removed files not correct'

        # check if file delete tasks were created
        delete_tasks = self._get_delete_tasks()
        assert self.test_firmware.uid in delete_tasks, 'fw delete task not found'
        assert self.child_fo.uid in delete_tasks, 'child delete task not found'
        assert len(delete_tasks) == 2, 'number of delete tasks not correct'

    def _get_delete_tasks(self):
        intercom = InterComListener(config=self.config)
        intercom.CONNECTION_TYPE = 'file_delete_task'
        delete_tasks = []
        while True:
            tmp = intercom.get_next_task()
            if tmp is None:
                break
            delete_tasks.append(tmp['_id'])
        intercom.shutdown()
        return delete_tasks
