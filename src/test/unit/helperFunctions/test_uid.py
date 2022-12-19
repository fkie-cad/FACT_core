import unittest

from helperFunctions.uid import create_uid, is_list_of_uids, is_uid


class TestHelperFunctionsUID(unittest.TestCase):

    test_uid = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_4'

    def test_create_uid(self):
        result = create_uid('test')
        assert result == self.test_uid, 'uid not correct'

    def test_is_uid(self):
        assert not is_uid(None)
        assert not is_uid('blah')
        assert is_uid(self.test_uid)
        assert not is_uid(self.test_uid + 'foobar')

    def test_is_uid_list(self):
        assert not is_list_of_uids('blah')
        assert not is_list_of_uids(['foobar'])
        assert not is_list_of_uids([])
        assert is_list_of_uids([self.test_uid]), 'uid list not recognized'
