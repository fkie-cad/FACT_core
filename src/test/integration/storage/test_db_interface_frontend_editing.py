import gc
import unittest
from tempfile import TemporaryDirectory

from helperFunctions.uid import create_uid
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_frontend_editing import FrontendEditingDbInterface
from storage.MongoMgr import MongoMgr
from test.common_helper import create_test_firmware, get_config_for_testing

TMP_DIR = TemporaryDirectory(prefix='fact_test_')


class TestStorageDbInterfaceFrontendEditing(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._config = get_config_for_testing(TMP_DIR)
        cls.mongo_server = MongoMgr(config=cls._config)

    def setUp(self):
        self.db_frontend_editing = FrontendEditingDbInterface(config=self._config)
        self.db_frontend_interface = FrontEndDbInterface(config=self._config)
        self.db_backend_interface = BackEndDbInterface(config=self._config)

    def tearDown(self):
        self.db_frontend_editing.shutdown()
        self.db_frontend_interface.shutdown()
        self.db_backend_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_backend_interface.shutdown()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()
        TMP_DIR.cleanup()

    def test_add_comment(self):
        test_fw = create_test_firmware()
        self.db_backend_interface.add_object(test_fw)
        comment, author, uid, time = 'this is a test comment!', 'author', test_fw.uid, 1234567890
        self.db_frontend_editing.add_comment_to_object(uid, comment, author, time)
        test_fw = self.db_backend_interface.get_object(uid)
        self.assertEqual(
            test_fw.comments[0],
            {'time': str(time), 'author': author, 'comment': comment}
        )

    def test_get_latest_comments(self):
        comments = [
            {'time': '1234567890', 'author': 'author1', 'comment': 'test comment'},
            {'time': '1234567899', 'author': 'author2', 'comment': 'test comment2'}
        ]
        test_fw = self._add_test_fw_with_comments_to_db()
        latest_comments = self.db_frontend_interface.get_latest_comments()
        comments.sort(key=lambda x: x['time'], reverse=True)
        for i, comment in enumerate(comments):
            assert latest_comments[i]['time'] == comment['time']
            assert latest_comments[i]['author'] == comment['author']
            assert latest_comments[i]['comment'] == comment['comment']
            assert latest_comments[i]['uid'] == test_fw.uid

    def test_remove_element_from_array_in_field(self):
        test_fw = self._add_test_fw_with_comments_to_db()
        retrieved_fw = self.db_backend_interface.get_object(test_fw.uid)
        self.assertEqual(len(retrieved_fw.comments), 2, 'comments were not saved correctly')

        self.db_frontend_editing.remove_element_from_array_in_field(test_fw.uid, 'comments', {'time': '1234567899'})
        retrieved_fw = self.db_backend_interface.get_object(test_fw.uid)
        self.assertEqual(len(retrieved_fw.comments), 1, 'comment was not deleted')

    def test_delete_comment(self):
        test_fw = self._add_test_fw_with_comments_to_db()
        retrieved_fw = self.db_backend_interface.get_object(test_fw.uid)
        self.assertEqual(len(retrieved_fw.comments), 2, 'comments were not saved correctly')

        self.db_frontend_editing.delete_comment(test_fw.uid, '1234567899')
        retrieved_fw = self.db_backend_interface.get_object(test_fw.uid)
        self.assertEqual(len(retrieved_fw.comments), 1, 'comment was not deleted')

    def _add_test_fw_with_comments_to_db(self):
        test_fw = create_test_firmware()
        comments = [
            {'time': '1234567890', 'author': 'author1', 'comment': 'test comment'},
            {'time': '1234567899', 'author': 'author2', 'comment': 'test comment2'}
        ]
        test_fw.comments.extend(comments)
        self.db_backend_interface.add_object(test_fw)
        return test_fw

    def test_update_object_field(self):
        test_fw = create_test_firmware(vendor='foo')
        self.db_backend_interface.add_object(test_fw)

        result = self.db_frontend_editing.get_object(test_fw.uid)
        assert result.vendor == 'foo'

        self.db_frontend_editing.update_object_field(test_fw.uid, 'vendor', 'bar')
        result = self.db_frontend_editing.get_object(test_fw.uid)
        assert result.vendor == 'bar'

    def test_add_to_search_query_cache(self):
        query = '{"device_class": "Router"}'
        uid = create_uid(query)
        assert self.db_frontend_editing.add_to_search_query_cache(query) == uid
        assert self.db_frontend_editing.search_query_cache.find_one({'_id': uid})['search_query'] == query
        # check what happens if search is added again
        assert self.db_frontend_editing.add_to_search_query_cache(query) == uid
        assert self.db_frontend_editing.search_query_cache.count_documents({'_id': uid}) == 1
