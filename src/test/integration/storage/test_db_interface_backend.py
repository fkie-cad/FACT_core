import unittest
from os import path
from tempfile import TemporaryDirectory
from time import time

from helperFunctions.config import get_config_for_testing
from helperFunctions.fileSystem import get_test_data_dir
from storage.MongoMgr import MongoMgr
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_common import MongoInterfaceCommon
from test.common_helper import create_test_firmware, create_test_file_object

TESTS_DIR = get_test_data_dir()
test_file_one = path.join(TESTS_DIR, 'get_files_test/testfile1')
TMP_DIR = TemporaryDirectory(prefix="faf_test_")


class TestStorageDbInterfaceBackend(unittest.TestCase):

    def setUp(self):
        self._config = get_config_for_testing(TMP_DIR)
        self.mongo_server = MongoMgr(config=self._config)
        self.db_interface = MongoInterfaceCommon(config=self._config)
        self.db_interface_backend = BackEndDbInterface(config=self._config)

        self.test_firmware = create_test_firmware()

        self.test_yara_match = {
            'rule': 'OpenSSH',
            'tags': [],
            'namespace': 'default',
            'strings': [(0, '$a', b'OpenSSH')],
            'meta': {
                'description': 'SSH library',
                'website': 'http://www.openssh.com',
                'open_source': True,
                'software_name': 'OpenSSH'
            },
            'matches': True
        }

        self.test_fo = create_test_file_object()

    def tearDown(self):
        self.db_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_interface.shutdown()
        self.mongo_server.shutdown()

    def _get_all_firmware_uids(self):
        uid_list = []
        tmp = self.db_interface.firmwares.find()
        for item in tmp:
            uid_list.append(item['_id'])
        return uid_list

    def test_add_firmware(self):
        self.db_interface_backend.add_firmware(self.test_firmware)
        self.assertGreater(len(self._get_all_firmware_uids()), 0, 'No entry added to DB')
        recoverd_firmware_entry = self.db_interface_backend.firmwares.find_one()
        self.assertAlmostEqual(recoverd_firmware_entry['submission_date'], time(), msg="submission time not set correctly", delta=5.0)

    def test_add_and_get_firmware(self):
        self.db_interface_backend.add_firmware(self.test_firmware)
        result_backend = self.db_interface_backend.get_firmware(self.test_firmware.get_uid())
        self.assertIsNotNone(result_backend.binary, "binary not set in backend result")
        result_common = self.db_interface.get_firmware(self.test_firmware.get_uid())
        self.assertIsNone(result_common.binary, "binary set in common result")
        self.assertEqual(result_common.size, 787, "file size not correct in common")

    def test_add_and_get_file_object(self):
        self.db_interface_backend.add_file_object(self.test_fo)
        result_backend = self.db_interface_backend.get_file_object(self.test_fo.get_uid())
        self.assertIsNotNone(result_backend.binary, "binary not set in backend result")
        result_common = self.db_interface.get_file_object(self.test_fo.get_uid())
        self.assertIsNone(result_common.binary, "binary set in common result")
        self.assertEqual(result_common.size, 62, "file size not correct in common")

    def test_update_firmware(self):
        first_dict = {'stub_plugin': {'result': 0}, 'other_plugin': {'field': 'day'}}
        second_dict = {'stub_plugin': {'result': 1}}

        self.test_firmware.processed_analysis = first_dict
        self.db_interface_backend.add_firmware(self.test_firmware)
        self.assertEqual(0, self.db_interface.get_object(self.test_firmware.get_uid()).processed_analysis['stub_plugin']['result'])
        self.test_firmware.processed_analysis = second_dict
        self.db_interface_backend.add_firmware(self.test_firmware)
        self.assertEqual(1, self.db_interface.get_object(self.test_firmware.get_uid()).processed_analysis['stub_plugin']['result'])
        self.assertIn('other_plugin', self.db_interface.get_object(self.test_firmware.get_uid()).processed_analysis.keys())

    def test_update_file_object(self):
        first_dict = {'other_plugin': {'result': 0}}
        second_dict = {'stub_plugin': {'result': 1}}

        self.test_fo.processed_analysis = first_dict
        self.test_fo.files_included = {"file a", "file b"}
        self.db_interface_backend.add_file_object(self.test_fo)
        self.test_fo.processed_analysis = second_dict
        self.test_fo.files_included = {"file b", "file c"}
        self.db_interface_backend.add_file_object(self.test_fo)
        received_object = self.db_interface.get_object(self.test_fo.get_uid())
        self.assertEqual(0, received_object.processed_analysis['other_plugin']['result'])
        self.assertEqual(1, received_object.processed_analysis['stub_plugin']['result'])
        self.assertEqual(3, len(received_object.files_included))

    def test_add_and_get_object_including_comment(self):
        comment, author, date, uid = "this is a test comment!", "author", "1473431685", self.test_fo.get_uid()
        self.test_fo.comments.append(
            {"time": str(date), "author": author, "comment": comment}
        )
        self.db_interface_backend.add_file_object(self.test_fo)

        retrieved_comment = self.db_interface.get_object(uid).comments[0]
        self.assertEqual(author, retrieved_comment["author"])
        self.assertEqual(comment, retrieved_comment["comment"])
        self.assertEqual(date, retrieved_comment["time"])
