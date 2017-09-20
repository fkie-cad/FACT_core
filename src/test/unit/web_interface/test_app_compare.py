from test.unit.web_interface.base import WebInterfaceTest


class TestAppCompare(WebInterfaceTest):

    def test_app_start_compare_get(self):
        rv = self.test_client.get('/compare')
        assert b'<h2>Compare Firmwares</h2>' in rv.data

    def test_app_start_compare_post_invalid(self):
        rv = self.test_client.post('/compare', content_type='multipart/form-data', data={'uid_list': 'invalid_uid', 'force': ""}, follow_redirects=True)
        assert b'<strong>Error:</strong>' in rv.data
        self.assertEqual(len(self.mocked_interface.tasks), 0, "task added but should not")

    def test_app_start_compare_post_valid_not_in_db(self):
        rv = self.test_client.post('/compare', content_type='multipart/form-data', data={'uid_list': 'valid_uid_list_not_in_db', 'force': ""}, follow_redirects=True)
        assert b'<strong>Info:</strong> Your compare task is in progress.' in rv.data
        self.assertEqual(len(self.mocked_interface.tasks), 1, "task not added")
        self.assertEqual(self.mocked_interface.tasks[0], ("valid_uid_list_not_in_db", None), "task not correct")

    def test_app_start_compare_post_valid_in_db_force(self):
        rv = self.test_client.post('/compare', content_type='multipart/form-data', data={'uid_list': 'valid_uid_list_in_db', 'force': "true"}, follow_redirects=True)
        assert b'<strong>Info:</strong> Your compare task is in progress.' in rv.data
        self.assertEqual(len(self.mocked_interface.tasks), 1, "task not added")
        self.assertEqual(self.mocked_interface.tasks[0], ("valid_uid_list_in_db", True), "task not correct")
