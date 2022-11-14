import gc
import os
import unittest
from configparser import ConfigParser
from tempfile import TemporaryDirectory

from common_helper_files import get_binary_from_file

from objects.file import FileObject
from storage.fsorganizer import FSOrganizer


class TestFsOrganizer(unittest.TestCase):
    def setUp(self):
        self.ds_tmp_dir = TemporaryDirectory(prefix='fact_tests_')
        config = ConfigParser()
        config.add_section('data-storage')
        config.set('data-storage', 'firmware-file-storage-directory', self.ds_tmp_dir.name)
        self.fs_organzier = FSOrganizer(config)

    def tearDown(self):
        self.ds_tmp_dir.cleanup()
        gc.collect()

    def check_file_presence_and_content(self, file_path, file_binary):
        self.assertTrue(os.path.exists(file_path), 'file exists')
        self.assertEqual(get_binary_from_file(file_path), file_binary, 'correct content')

    def test_generate_path(self):
        test_binary = b'abcde'
        file_object = FileObject(test_binary)
        file_path = self.fs_organzier.generate_path(file_object)
        # file path should be 'DATA_DIR/UID_PEFIX/UID'
        self.assertEqual(
            file_path,
            f'{self.ds_tmp_dir.name}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5',
            'generate file path',
        )

    def test_store_and_delete_file(self):
        test_binary = b'abcde'
        file_object = FileObject(test_binary)

        self.fs_organzier.store_file(file_object)
        self.check_file_presence_and_content(
            f'{self.ds_tmp_dir.name}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5', b'abcde'
        )
        self.assertEqual(
            file_object.file_path,
            f'{self.ds_tmp_dir.name}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5',
            'wrong file path set in file object',
        )

        self.fs_organzier.delete_file(file_object.uid)
        self.assertFalse(os.path.exists(file_object.file_path), 'file not deleted')
