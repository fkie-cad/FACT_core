from tempfile import TemporaryDirectory

import pytest

from objects.file import FileObject
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import create_test_file_object, get_test_data_dir
from unpacker.unpack import Unpacker

TEST_DATA_DIR = get_test_data_dir()
EXTRACTION_DIR = TEST_DATA_DIR / 'files'


@pytest.fixture
def unpacker():
    return Unpacker(unpacking_locks=UnpackingLockManager())


@pytest.fixture
def test_fo():
    return create_test_file_object()


@pytest.mark.backend_config_overwrite(
    {
        'unpacking': {
            'max_depth': 3,
            'whitelist': ['text/plain', 'image/png'],
        },
    }
)
class TestUnpackerCore:
    def test_dont_store_zero_file(self, unpacker, test_fo):
        file_paths = [EXTRACTION_DIR / 'zero_byte', EXTRACTION_DIR / 'get_files_test' / 'testfile2']
        file_objects = unpacker.generate_objects_and_store_files(file_paths, EXTRACTION_DIR, test_fo)
        assert len(file_objects) == 1, 'number of objects not correct'
        child_fo = file_objects[0]
        assert child_fo.file_name == 'testfile2', 'wrong object created'
        assert '/get_files_test/testfile2' in child_fo.virtual_file_path[test_fo.uid]

    def test_remove_duplicates_child_equals_parent(self, unpacker, test_fo):
        file_paths = [EXTRACTION_DIR / 'get_files_test' / 'testfile1']
        # testfile1 is the same file as test_fo -> should be removed
        file_objects = unpacker.generate_objects_and_store_files(file_paths, EXTRACTION_DIR, test_fo)
        assert len(file_objects) == 0, 'the same file should not be unpacked from itself'

    def test_file_is_locked(self, unpacker, test_fo):
        assert not unpacker.unpacking_locks.unpacking_lock_is_set(test_fo.uid)
        file_paths = [TEST_DATA_DIR / 'get_files_test' / 'testfile1']
        unpacker.generate_objects_and_store_files(file_paths, EXTRACTION_DIR, test_fo)
        assert unpacker.unpacking_locks.unpacking_lock_is_set(test_fo.uid)


@pytest.mark.backend_config_overwrite(
    {
        'unpacking': {
            'max_depth': 3,
            'whitelist': ['text/plain', 'image/png'],
        },
    }
)
class TestUnpackerCoreMain:
    test_file_path = str(TEST_DATA_DIR / 'container/test.zip')

    def main_unpack_check(self, unpacker, test_object, number_unpacked_files, first_unpacker):
        with TemporaryDirectory() as tmp_dir:
            extracted_files = unpacker.unpack(test_object, tmp_dir)
        assert len(test_object.files_included) == number_unpacked_files, 'not all files added to parent'
        assert len(extracted_files) == number_unpacked_files, 'not all files found'
        assert (
            test_object.processed_analysis['unpacker']['result']['plugin_used'] == first_unpacker
        ), 'Wrong plugin in Meta'
        assert (
            test_object.processed_analysis['unpacker']['result']['number_of_unpacked_files'] == number_unpacked_files
        ), 'Number of unpacked files wrong in Meta'
        self.check_depths_of_children(test_object, extracted_files)

    @staticmethod
    def check_depths_of_children(parent, extracted_files):
        for item in extracted_files:
            assert item.depth == parent.depth + 1, 'depth of child not correct'

    def test_main_unpack_function(self, unpacker):
        test_file = FileObject(file_path=self.test_file_path)
        self.main_unpack_check(unpacker, test_file, 3, '7z')

    def test_unpacking_depth_reached(self, unpacker):
        test_file = FileObject(file_path=self.test_file_path)
        test_file.depth = 10
        with TemporaryDirectory() as tmp_dir:
            unpacker.unpack(test_file, tmp_dir)
        assert 'unpacker' in test_file.processed_analysis
        assert 'maximum unpacking depth was reached' in test_file.processed_analysis['unpacker']['result']['info']
