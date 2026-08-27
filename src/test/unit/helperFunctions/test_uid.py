import unittest
from pathlib import Path
from tempfile import NamedTemporaryFile

from helperFunctions.uid import create_uid, create_uid_from_path, is_list_of_uids, is_uid


class TestHelperFunctionsUID(unittest.TestCase):
    test_uid = '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08_4'

    def test_create_uid(self):
        result = create_uid(b'test')
        assert result == self.test_uid, 'uid not correct'

    def test_create_uid_from_path(self):
        with NamedTemporaryFile() as file:
            path = Path(file.name)
            path.write_bytes(b'test')
            result = create_uid_from_path(path)
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
