import gc
import os
from shutil import copyfile
from tempfile import TemporaryDirectory
import unittest

from helperFunctions.config import get_config_for_testing
from helperFunctions.fileSystem import get_test_data_dir
from intercom.common_mongo_binding import InterComListener
from storage.MongoMgr import MongoMgr
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware, create_test_file_object


TESTS_DIR = get_test_data_dir()
test_file_original = os.path.join(TESTS_DIR, 'get_files_test/testfile1')
test_file_copy = os.path.join(TESTS_DIR, 'get_files_test/testfile_copy')
test_firmware_original = os.path.join(TESTS_DIR, 'container/test.zip')
test_firmware_copy = os.path.join(TESTS_DIR, 'container/test_copy.zip')
TMP_DIR = TemporaryDirectory(prefix='faf_test_')


class TestStorageDbInterfaceAdmin(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing(TMP_DIR)
        self.config.set('data_storage', 'sanitize_database', 'tmp_sanitize')
        self.config.set('data_storage', 'report_threshold', '32')
        self.mongo_server = MongoMgr(config=self.config)
        self.admin_interface = AdminDbInterface(config=self.config)
        self.db_backend_interface = BackEndDbInterface(config=self.config)
        copyfile(test_firmware_original, test_firmware_copy)
        self.test_firmware = create_test_firmware(bin_path='container/test_copy.zip')
        self.uid = self.test_firmware.get_uid()
        self.test_firmware.virtual_file_path = {self.uid: ['|{}|'.format(self.test_firmware.get_uid())]}
        copyfile(test_file_original, test_file_copy)
        self.child_fo = create_test_file_object(test_file_copy)
        self.child_fo.virtual_file_path = {self.uid: ['|{}|/folder/{}'.format(self.uid, self.child_fo.file_name)]}
        self.test_firmware.files_included = [self.child_fo.get_uid()]
        self.child_uid = self.child_fo.get_uid()

    def tearDown(self):
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'main_database'))
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'sanitize_database'))
        self.admin_interface.shutdown()
        self.db_backend_interface.shutdown()
        self.mongo_server.shutdown()
        for test_file in [test_file_copy, test_firmware_copy]:
            if os.path.isfile(test_file):
                os.remove(test_file)
        TMP_DIR.cleanup()
        gc.collect()

    def test_remove_object_field(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        self.assertIn(self.uid, self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path'])
        self.admin_interface.remove_object_field(self.child_uid, 'virtual_file_path.{}'.format(self.uid))
        self.assertNotIn(self.uid, self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path'])

    def test_remove_virtual_path_entries_no_other_roots(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        self.assertIn(self.uid, self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path'])
        removed_vps, deleted_files = self.admin_interface._remove_virtual_path_entries(self.uid, self.child_fo.get_uid())
        self.assertIsNone(self.db_backend_interface.file_objects.find_one(self.child_uid))
        self.assertEqual(removed_vps, 0)
        self.assertEqual(deleted_files, 1)

    def test_remove_virtual_path_entries_other_roots(self):
        self.child_fo.virtual_file_path.update({'someuid': ['|someuid|/some/virtual/path']})
        self.db_backend_interface.add_file_object(self.child_fo)
        self.assertIn(self.uid, self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path'])
        removed_vps, deleted_files = self.admin_interface._remove_virtual_path_entries(self.uid, self.child_fo.get_uid())
        self.assertNotIn(self.uid, self.db_backend_interface.file_objects.find_one(self.child_uid, {'virtual_file_path': 1})['virtual_file_path'])
        self.assertEqual(removed_vps, 1)
        self.assertEqual(deleted_files, 0)

    def test_delete_swapped_analysis_entries(self):
        self.test_firmware.processed_analysis = {'test_plugin': {'result': 10000000000, 'misc': 'delete_swap_test'}}
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.admin_interface.client.drop_database(self.config.get('data_storage', 'sanitize_database'))
        self.admin_interface.sanitize_analysis(self.test_firmware.processed_analysis, self.uid)
        self.assertIn('test_plugin_result_{}'.format(self.test_firmware.get_uid()), self.admin_interface.sanitize_fs.list())
        self.admin_interface._delete_swapped_analysis_entries(self.admin_interface.firmwares.find_one(self.uid))
        self.assertNotIn('test_plugin_result_{}'.format(self.test_firmware.get_uid()), self.admin_interface.sanitize_fs.list())

    def test_delete_file_object(self):
        self.db_backend_interface.add_file_object(self.child_fo)
        db_entry = self.db_backend_interface.file_objects.find_one(self.child_fo.get_uid())
        self.assertIsNotNone(db_entry)
        self.admin_interface._delete_file_object(db_entry)
        self.assertIsNone(self.db_backend_interface.file_objects.find_one(self.child_fo.get_uid()), 'file not deleted from db')
        delete_tasks = self._get_delete_tasks()
        self.assertIn(self.child_fo.get_uid(), delete_tasks, 'file not found in delete tasks')

    def test_delete_firmware(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.db_backend_interface.add_file_object(self.child_fo)
        self.assertIsNotNone(self.db_backend_interface.firmwares.find_one(self.uid))
        self.assertIsNotNone(self.db_backend_interface.file_objects.find_one(self.child_uid))
        self.assertTrue(os.path.isfile(self.test_firmware.file_path))
        self.assertTrue(os.path.isfile(self.child_fo.file_path))
        removed_vps, deleted_files = self.admin_interface.delete_firmware(self.uid)
        self.assertIsNone(self.db_backend_interface.firmwares.find_one(self.uid), 'firmware not deleted from db')
        self.assertIsNone(self.db_backend_interface.file_objects.find_one(self.child_uid), 'child not deleted from db')
        self.assertEqual(removed_vps, 0)
        self.assertEqual(deleted_files, 2, 'number of removed files not correct')

        # check if file delete tasks were created
        delete_tasks = self._get_delete_tasks()
        self.assertIn(self.test_firmware.get_uid(), delete_tasks, 'fw delete task not found')
        self.assertIn(self.child_fo.get_uid(), delete_tasks, 'child delete task not found')
        self.assertEqual(len(delete_tasks), 2, 'number of delete tasks not correct')

    def _get_delete_tasks(self):
        intercom = InterComListener(config=self.config)
        intercom.CONNECTION_TYPE = 'file_delete_task'
        delete_tasks = []
        while True:
            tmp = intercom.get_next_task()
            if tmp is None:
                break
            else:
                delete_tasks.append(tmp['_id'])
        intercom.shutdown()
        return delete_tasks
