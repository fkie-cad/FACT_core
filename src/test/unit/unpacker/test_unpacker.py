import gc
import os
import unittest
from configparser import ConfigParser
from tempfile import TemporaryDirectory
from test.common_helper import DatabaseMock, create_test_file_object

from helperFunctions.dataConversion import make_list_from_dict
from helperFunctions.fileSystem import get_test_data_dir
from objects.file import FileObject
from unpacker.unpack import Unpacker


class TestUnpackerBase(unittest.TestCase):
    def setUp(self):
        config = ConfigParser()
        self.ds_tmp_dir = TemporaryDirectory(prefix='faf_tests_')
        config.add_section('data_storage')
        config.set('data_storage', 'firmware_file_storage_directory', self.ds_tmp_dir.name)
        config.add_section('unpack')
        config.set('unpack', 'max_depth', '3')
        config.set('unpack', 'whitelist', 'text/plain, image/png')
        config.add_section('ExpertSettings')
        self.unpacker = Unpacker(config=config, db_interface=DatabaseMock())
        self.tmp_dir = TemporaryDirectory(prefix='faf_tests_')
        self.test_fo = create_test_file_object()

    def tearDown(self):
        self.ds_tmp_dir.cleanup()
        self.tmp_dir.cleanup()
        gc.collect()

    def check_unpacker_selection(self, mime_type, plugin_name, depth=0):
        name = self.unpacker.get_unpacker(mime_type, depth)[1]
        self.assertEqual(name, plugin_name, 'wrong unpacker plugin selected')

    def check_unpacking_of_standard_unpack_set(self, in_file, additional_prefix_folder='', output=True):
        files, meta_data = self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)
        files = set(files)
        self.assertEqual(len(files), 3, 'file number incorrect')
        self.assertEqual(files, {
            os.path.join(self.tmp_dir.name, additional_prefix_folder, 'testfile1'),
            os.path.join(self.tmp_dir.name, additional_prefix_folder, 'testfile2'),
            os.path.join(self.tmp_dir.name, additional_prefix_folder, 'generic folder/test file 3_.txt')
        }, 'not all files found')
        if output:
            self.assertIn('output', meta_data)
        return meta_data


class TestUnpackerCore(TestUnpackerBase):

    def test_generate_and_store_file_objects_zero_file(self):
        file_pathes = ['{}/zero_byte'.format(get_test_data_dir()), '{}/get_files_test/testfile1'.format(get_test_data_dir())]
        file_objects = self.unpacker.generate_and_store_file_objects(file_pathes, get_test_data_dir(), self.test_fo)
        file_objects = make_list_from_dict(file_objects)
        self.assertEqual(len(file_objects), 1, 'number of objects not correct')
        self.assertEqual(file_objects[0].file_name, 'testfile1', 'wrong object created')
        parentID = self.test_fo.get_uid()
        self.assertIn('|{}|/get_files_test/testfile1'.format(parentID), file_objects[0].virtual_file_path[self.test_fo.get_uid()])

    def test_remove_duplicates_child_equals_parent(self):
        parent = FileObject(binary=b'parent_content')
        result = self.unpacker.remove_duplicates({parent.get_uid(): parent}, parent)
        self.assertEqual(len(result), 0, 'parent not removed from list')

    def test_file_is_locked(self):
        assert not self.unpacker.db_interface.check_unpacking_lock(self.test_fo.uid)
        file_paths = ['{}/get_files_test/testfile1'.format(get_test_data_dir())]
        self.unpacker.generate_and_store_file_objects(file_paths, get_test_data_dir(), self.test_fo)
        assert self.unpacker.db_interface.check_unpacking_lock(self.test_fo.uid)


class TestUnpackerCoreMain(TestUnpackerBase):

    def main_unpack_check(self, test_object, number_unpacked_files, first_unpacker):
        extracted_files = self.unpacker.unpack(test_object)
        self.assertEqual(len(test_object.files_included), number_unpacked_files, 'not all files added to parent')
        self.assertEqual(len(extracted_files), number_unpacked_files, 'not all files found')
        self.assertEqual(test_object.processed_analysis['unpacker']['plugin_used'], first_unpacker, 'Wrong plugin in Meta')
        self.assertEqual(test_object.processed_analysis['unpacker']['number_of_unpacked_files'], number_unpacked_files, 'Number of unpacked files wrong in Meta')
        self.check_deps_of_childs(test_object, extracted_files)

    def check_deps_of_childs(self, parent, extracted_files):
        for item in extracted_files:
            self.assertEqual(item.depth, parent.depth + 1, 'depth of child not correct')

    def test_main_unpack_function(self):
        test_file = FileObject(file_path=os.path.join(get_test_data_dir(), 'container/test.zip'))
        self.main_unpack_check(test_file, 3, '7z')
