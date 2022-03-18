# pylint: disable=wrong-import-order
import gc
import grp
import os
import unittest
from configparser import ConfigParser
from pathlib import Path
from tempfile import TemporaryDirectory

from objects.file import FileObject
from storage.unpacking_locks import UnpackingLockManager
from test.common_helper import create_test_file_object, get_test_data_dir
from unpacker.unpack import Unpacker

TEST_DATA_DIR = Path(get_test_data_dir())
EXTRACTION_DIR = TEST_DATA_DIR / 'files'


class TestUnpackerBase(unittest.TestCase):
    def setUp(self):
        config = ConfigParser()
        self.ds_tmp_dir = TemporaryDirectory(prefix='fact_tests_')
        self.docker_mount_base_dir = Path('/tmp/fact-docker-mount-base-dir')
        try:
            self.docker_mount_base_dir.mkdir(0o770)
        except FileExistsError:
            pass
        else:
            docker_gid = grp.getgrnam('docker').gr_gid
            os.chown(self.docker_mount_base_dir, -1, docker_gid)
        config.add_section('data-storage')
        config.set('data-storage', 'firmware-file-storage-directory', self.ds_tmp_dir.name)
        config.set('data-storage', 'docker-mount-base-dir', str(self.docker_mount_base_dir))
        config.add_section('unpack')
        config.set('unpack', 'max-depth', '3')
        config.set('unpack', 'whitelist', 'text/plain, image/png')
        config.add_section('expert-settings')
        self.unpacker = Unpacker(config=config, unpacking_locks=UnpackingLockManager())
        self.tmp_dir = TemporaryDirectory(prefix='fact_tests_')
        self.test_fo = create_test_file_object()

    def tearDown(self):
        self.ds_tmp_dir.cleanup()
        self.tmp_dir.cleanup()
        gc.collect()


class TestUnpackerCore(TestUnpackerBase):
    def test_dont_store_zero_file(self):
        file_paths = [EXTRACTION_DIR / 'zero_byte', EXTRACTION_DIR / 'get_files_test' / 'testfile1']
        file_objects = self.unpacker.generate_and_store_file_objects(file_paths, EXTRACTION_DIR, self.test_fo)
        file_objects = list(file_objects.values())
        self.assertEqual(len(file_objects), 1, 'number of objects not correct')
        self.assertEqual(file_objects[0].file_name, 'testfile1', 'wrong object created')
        parent_uid = self.test_fo.uid
        self.assertIn(f'|{parent_uid}|/get_files_test/testfile1', file_objects[0].virtual_file_path[self.test_fo.uid])

    def test_remove_duplicates_child_equals_parent(self):
        parent = FileObject(binary=b'parent_content')
        result = self.unpacker.remove_duplicates({parent.uid: parent}, parent)
        self.assertEqual(len(result), 0, 'parent not removed from list')

    def test_file_is_locked(self):
        assert not self.unpacker.unpacking_locks.unpacking_lock_is_set(self.test_fo.uid)
        file_paths = [TEST_DATA_DIR / 'get_files_test' / 'testfile1']
        self.unpacker.generate_and_store_file_objects(file_paths, EXTRACTION_DIR, self.test_fo)
        assert self.unpacker.unpacking_locks.unpacking_lock_is_set(self.test_fo.uid)


class TestUnpackerCoreMain(TestUnpackerBase):

    test_file_path = str(TEST_DATA_DIR / 'container/test.zip')

    def main_unpack_check(self, test_object, number_unpacked_files, first_unpacker):
        extracted_files = self.unpacker.unpack(test_object)
        assert len(test_object.files_included) == number_unpacked_files, 'not all files added to parent'
        assert len(extracted_files) == number_unpacked_files, 'not all files found'
        assert test_object.processed_analysis['unpacker']['plugin_used'] == first_unpacker, 'Wrong plugin in Meta'
        assert (
            test_object.processed_analysis['unpacker']['number_of_unpacked_files'] == number_unpacked_files
        ), 'Number of unpacked files wrong in Meta'
        self.check_depths_of_children(test_object, extracted_files)

    @staticmethod
    def check_depths_of_children(parent, extracted_files):
        for item in extracted_files:
            assert item.depth == parent.depth + 1, 'depth of child not correct'

    def test_main_unpack_function(self):
        test_file = FileObject(file_path=self.test_file_path)
        self.main_unpack_check(test_file, 3, '7z')

    def test_unpacking_depth_reached(self):
        test_file = FileObject(file_path=self.test_file_path)
        test_file.depth = 10
        self.unpacker.unpack(test_file)
        assert 'unpacker' in test_file.processed_analysis
        assert 'maximum unpacking depth was reached' in test_file.processed_analysis['unpacker']['info']
