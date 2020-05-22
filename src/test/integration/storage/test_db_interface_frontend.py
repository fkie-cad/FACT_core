import gc
import unittest
from tempfile import TemporaryDirectory

from helperFunctions.file_tree import FileTreeNode
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.MongoMgr import MongoMgr
from test.common_helper import create_test_file_object, create_test_firmware, get_config_for_testing, get_test_data_dir

TESTS_DIR = get_test_data_dir()
TMP_DIR = TemporaryDirectory(prefix='fact_test_')


class TestStorageDbInterfaceFrontend(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._config = get_config_for_testing(TMP_DIR)
        cls.mongo_server = MongoMgr(config=cls._config)

    def setUp(self):
        self.db_frontend_interface = FrontEndDbInterface(config=self._config)
        self.db_backend_interface = BackEndDbInterface(config=self._config)
        self.test_firmware = create_test_firmware()

    def tearDown(self):
        self.db_frontend_interface.shutdown()
        self.db_backend_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_backend_interface.shutdown()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()
        TMP_DIR.cleanup()

    def test_regression_meta_list(self):
        assert self.test_firmware.processed_analysis.pop('unpacker')
        self.db_backend_interface.add_firmware(self.test_firmware)
        list_of_firmwares = self.db_frontend_interface.get_meta_list()
        assert 'NOP' in list_of_firmwares.pop()[2]

    def test_get_meta_list(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        list_of_firmwares = self.db_frontend_interface.get_meta_list()
        test_output = list_of_firmwares.pop()
        self.assertEqual(test_output[1], 'test_vendor test_router - 0.1 (Router)', 'Firmware not successfully received')
        self.assertIsInstance(test_output[2], dict, 'tag field is not a dict')

    def test_get_meta_list_of_fo(self):
        test_fo = create_test_file_object()
        self.db_backend_interface.add_file_object(test_fo)
        files = self.db_frontend_interface.file_objects.find()
        meta_list = self.db_frontend_interface.get_meta_list(files)
        self.assertEqual(meta_list[0][0], test_fo.uid, 'uid of object not correct')
        self.assertEqual(meta_list[0][3], 0, 'non existing submission date should lead to 0')

    def test_get_hid_firmware(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        result = self.db_frontend_interface.get_hid(self.test_firmware.uid)
        self.assertEqual(result, 'test_vendor test_router - 0.1 (Router)', 'fw hid not correct')

    def test_get_hid_fo(self):
        test_fo = create_test_file_object(bin_path='get_files_test/testfile2')
        test_fo.virtual_file_path = {'a': ['|a|/test_file'], 'b': ['|b|/get_files_test/testfile2']}
        self.db_backend_interface.add_file_object(test_fo)
        result = self.db_frontend_interface.get_hid(test_fo.uid, root_uid='b')
        self.assertEqual(result, '/get_files_test/testfile2', 'fo hid not correct')
        result = self.db_frontend_interface.get_hid(test_fo.uid)
        self.assertIsInstance(result, str, 'result is not a string')
        self.assertEqual(result[0], '/', 'first character not correct if no root_uid set')
        result = self.db_frontend_interface.get_hid(test_fo.uid, root_uid='c')
        self.assertEqual(result[0], '/', 'first character not correct if invalid root_uid set')

    def test_get_file_name(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        result = self.db_frontend_interface.get_file_name(self.test_firmware.uid)
        self.assertEqual(result, 'test.zip', 'name not correct')

    def test_get_hid_invalid_uid(self):
        result = self.db_frontend_interface.get_hid('foo')
        self.assertEqual(result, '', 'invalid uid should result in empty string')

    def test_get_firmware_attribute_list(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.assertEqual(self.db_frontend_interface.get_device_class_list(), ['Router'])
        self.assertEqual(self.db_frontend_interface.get_vendor_list(), ['test_vendor'])
        self.assertEqual(self.db_frontend_interface.get_firmware_attribute_list('device_name', {'vendor': 'test_vendor', 'device_class': 'Router'}), ['test_router'])
        self.assertEqual(self.db_frontend_interface.get_firmware_attribute_list('version'), ['0.1'])
        self.assertEqual(self.db_frontend_interface.get_device_name_dict(), {'Router': {'test_vendor': ['test_router']}})

    def test_get_data_for_nice_list(self):
        uid_list = [self.test_firmware.uid]
        self.db_backend_interface.add_firmware(self.test_firmware)
        nice_list_data = self.db_frontend_interface.get_data_for_nice_list(uid_list, uid_list[0])
        self.assertEqual(sorted(['size', 'current_virtual_path', 'uid', 'mime-type', 'files_included']), sorted(nice_list_data[0].keys()))
        self.assertEqual(nice_list_data[0]['uid'], self.test_firmware.uid)

    def test_generic_search(self):
        self.db_backend_interface.add_firmware(self.test_firmware)
        # str input
        result = self.db_frontend_interface.generic_search('{"file_name": "test.zip"}')
        self.assertEqual(result, [self.test_firmware.uid], 'Firmware not successfully received')
        # dict input
        result = self.db_frontend_interface.generic_search({'file_name': 'test.zip'})
        self.assertEqual(result, [self.test_firmware.uid], 'Firmware not successfully received')

    def test_all_uids_found_in_database(self):
        self.db_backend_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        uid_list = [self.test_firmware.uid]
        self.assertFalse(self.db_frontend_interface.all_uids_found_in_database(uid_list))
        self.db_backend_interface.add_firmware(self.test_firmware)
        self.assertTrue(self.db_frontend_interface.all_uids_found_in_database([self.test_firmware.uid]))

    def test_get_x_last_added_firmwares(self):
        self.assertEqual(self.db_frontend_interface.get_last_added_firmwares(), [], 'empty db should result in empty list')
        test_fw_one = create_test_firmware(device_name='fw_one')
        self.db_backend_interface.add_firmware(test_fw_one)
        test_fw_two = create_test_firmware(device_name='fw_two', bin_path='container/test.7z')
        self.db_backend_interface.add_firmware(test_fw_two)
        test_fw_three = create_test_firmware(device_name='fw_three', bin_path='container/test.cab')
        self.db_backend_interface.add_firmware(test_fw_three)
        result = self.db_frontend_interface.get_last_added_firmwares(limit_x=2)
        self.assertEqual(len(result), 2, 'Number of results should be 2')
        self.assertEqual(result[0][0], test_fw_three.uid, 'last firmware is not first entry')
        self.assertEqual(result[1][0], test_fw_two.uid, 'second last firmware is not the second entry')

    def test_generate_file_tree_level(self):
        parent_fw = create_test_firmware()
        child_fo = create_test_file_object()
        child_fo.processed_analysis['file_type'] = {'mime': 'sometype'}
        uid = parent_fw.uid
        child_fo.virtual_file_path = {uid: ['|{}|/folder/{}'.format(uid, child_fo.file_name)]}
        parent_fw.files_included = {child_fo.uid}
        self.db_backend_interface.add_object(parent_fw)
        self.db_backend_interface.add_object(child_fo)
        for node in self.db_frontend_interface.generate_file_tree_level(uid, uid):
            self.assertIsInstance(node, FileTreeNode)
            self.assertEqual(node.name, parent_fw.file_name)
            self.assertTrue(node.has_children)
        for node in self.db_frontend_interface.generate_file_tree_level(child_fo.uid, uid):
            self.assertIsInstance(node, FileTreeNode)
            self.assertEqual(node.name, 'folder')
            self.assertTrue(node.has_children)
            virtual_grand_child = node.get_list_of_child_nodes()[0]
            self.assertEqual(virtual_grand_child.type, 'sometype')
            self.assertFalse(virtual_grand_child.has_children)
            self.assertEqual(virtual_grand_child.name, child_fo.file_name)

    def test_get_number_of_total_matches(self):
        parent_fw = create_test_firmware()
        child_fo = create_test_file_object()
        uid = parent_fw.uid
        child_fo.parent_firmware_uids = [uid]
        self.db_backend_interface.add_object(parent_fw)
        self.db_backend_interface.add_object(child_fo)
        query = '{{"$or": [{{"_id": "{}"}}, {{"_id": "{}"}}]}}'.format(uid, child_fo.uid)
        assert self.db_frontend_interface.get_number_of_total_matches(query, only_parent_firmwares=False, inverted=False) == 2
        assert self.db_frontend_interface.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=False) == 1
        assert self.db_frontend_interface.get_number_of_total_matches(query, only_parent_firmwares=True, inverted=True) == 0

    def test_get_other_versions_of_firmware(self):
        parent_fw1 = create_test_firmware(version='1')
        self.db_backend_interface.add_object(parent_fw1)
        parent_fw2 = create_test_firmware(version='2', bin_path='container/test.7z')
        self.db_backend_interface.add_object(parent_fw2)
        parent_fw3 = create_test_firmware(version='3', bin_path='container/test.cab')
        self.db_backend_interface.add_object(parent_fw3)

        other_versions = self.db_frontend_interface.get_other_versions_of_firmware(parent_fw1)
        self.assertEqual(len(other_versions), 2, 'wrong number of other versions')
        self.assertIn({'_id': parent_fw2.uid, 'version': '2'}, other_versions)
        self.assertIn({'_id': parent_fw3.uid, 'version': '3'}, other_versions)

        other_versions = self.db_frontend_interface.get_other_versions_of_firmware(parent_fw2)
        self.assertIn({'_id': parent_fw3.uid, 'version': '3'}, other_versions)

    def test_get_specific_fields_for_multiple_entries(self):
        test_fw_1 = create_test_firmware(device_name='fw_one', vendor='test_vendor_one')
        self.db_backend_interface.add_firmware(test_fw_1)
        test_fw_2 = create_test_firmware(device_name='fw_two', vendor='test_vendor_two', bin_path='container/test.7z')
        self.db_backend_interface.add_firmware(test_fw_2)
        test_fo = create_test_file_object()
        self.db_backend_interface.add_file_object(test_fo)

        test_uid_list = [test_fw_1.uid, test_fw_2.uid]
        result = list(self.db_frontend_interface.get_specific_fields_for_multiple_entries(
            uid_list=test_uid_list,
            field_dict={'vendor': 1, 'device_name': 1}
        ))
        assert len(result) == 2
        assert all(set(entry.keys()) == {'_id', 'vendor', 'device_name'} for entry in result)
        result_uids = [entry['_id'] for entry in result]
        assert all(uid in result_uids for uid in test_uid_list)

        test_uid_list = [test_fw_1.uid, test_fo.uid]
        result = list(self.db_frontend_interface.get_specific_fields_for_multiple_entries(
            uid_list=test_uid_list,
            field_dict={'virtual_file_path': 1}
        ))
        assert len(result) == 2
        assert all(set(entry.keys()) == {'_id', 'virtual_file_path'} for entry in result)
        result_uids = [entry['_id'] for entry in result]
        assert all(uid in result_uids for uid in test_uid_list)

    def test_find_missing_files(self):
        test_fw_1 = create_test_firmware()
        test_fw_1.files_included.add('uid1234')
        self.db_backend_interface.add_firmware(test_fw_1)
        missing_files = self.db_frontend_interface.find_missing_files()
        assert test_fw_1.uid in missing_files
        assert missing_files[test_fw_1.uid] == {'uid1234'}

        test_fo = create_test_file_object()
        test_fo.uid = 'uid1234'
        self.db_backend_interface.add_file_object(test_fo)
        missing_files = self.db_frontend_interface.find_missing_files()
        assert missing_files == {}

    def test_find_missing_analyses(self):
        test_fw_1 = create_test_firmware()
        test_fo = create_test_file_object()
        test_fw_1.files_included.add(test_fo.uid)
        test_fo.virtual_file_path = {test_fw_1.uid: ['|foo|bar|']}
        self.db_backend_interface.add_firmware(test_fw_1)
        self.db_backend_interface.add_file_object(test_fo)

        missing_analyses = self.db_frontend_interface.find_missing_analyses()
        assert missing_analyses == {}

        test_fw_1.processed_analysis['foobar'] = {'foo': 'bar'}
        self.db_backend_interface.add_analysis(test_fw_1)
        missing_analyses = self.db_frontend_interface.find_missing_analyses()
        assert test_fw_1.uid in missing_analyses
        assert missing_analyses[test_fw_1.uid] == {test_fo.uid}
