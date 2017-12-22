from configparser import ConfigParser
import gc
import os
from tempfile import TemporaryDirectory
import unittest

from helperFunctions.dataConversion import make_list_from_dict
from helperFunctions.fileSystem import get_test_data_dir
from objects.file import FileObject
from test.common_helper import create_test_file_object
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
        self.unpacker = Unpacker(config=config)
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

    def test_generic_carver_found(self):
        self.assertTrue('generic/carver' in list(self.unpacker.unpacker_plugins.keys()),
                        'generic carver plugin not found')
        name = self.unpacker.unpacker_plugins['generic/carver'][1]
        self.assertEqual(name, 'generic_carver', 'generic_carver plugin not found')

    def test_unpacker_selection_unkown(self):
        self.check_unpacker_selection('unknown/blah', 'generic_carver')

    def test_unpacker_selection_depth_reached(self):
        self.check_unpacker_selection('unknow/blah', 'generic_carver', 3)
        self.check_unpacker_selection('unknown/blah', 'NOP', 4)

    def test_unpacker_selection_whitelist(self):
        self.check_unpacker_selection('text/plain', 'NOP')
        self.check_unpacker_selection('image/png', 'NOP')

    def test_generate_and_store_file_objects_zero_file(self):
        file_pathes = ['{}/zero_byte'.format(get_test_data_dir()), '{}/get_files_test/testfile1'.format(get_test_data_dir())]
        file_objects = self.unpacker.generate_and_store_file_objects(file_pathes, get_test_data_dir(), self.test_fo)
        file_objects = make_list_from_dict(file_objects)
        self.assertEqual(len(file_objects), 1, 'number of objects not correct')
        self.assertEqual(file_objects[0].file_name, 'testfile1', 'wrong object created')
        parentID = self.test_fo.get_uid()
        self.assertIn('|{}|/get_files_test/testfile1'.format(parentID), file_objects[0].virtual_file_path[self.test_fo.get_uid()])

    def test_unpack_failure_generic_carver_fallback(self):
        self.unpacker.GENERIC_CARVER_FALLBACK_BLACKLIST = []
        self._unpack_fallback_check('generic/carver', 'generic_carver')

    def test_unpack_failure_gernic_fs_fallback(self):
        self.unpacker.GENERIC_FS_FALLBACK_CANDIDATES = ['7z']
        result = self._unpack_fallback_check('generic/fs', 'generic_carver')
        self.assertIn('0_FALLBACK_genericFS', result.processed_analysis['unpacker'], 'generic FS Fallback entry missing')
        self.assertIn('0_ERROR_genericFS', result.processed_analysis['unpacker'], 'generic FS ERROR entry missing')

    def _unpack_fallback_check(self, fallback_mime, fallback_plugin_name):
        broken_zip = FileObject(file_path=os.path.join(get_test_data_dir(), 'container/broken.zip'))
        self.unpacker.unpack(broken_zip)
        self.assertEqual(broken_zip.processed_analysis['unpacker']['0_ERROR_7z'][0:6], '\n7-Zip')
        self.assertEqual(broken_zip.processed_analysis['unpacker']['0_FALLBACK_7z'], '7z (failed) -> {} (fallback)'.format(fallback_mime))
        self.assertEqual(broken_zip.processed_analysis['unpacker']['plugin_used'], fallback_plugin_name)
        return broken_zip

    def test_remove_duplicates_child_equals_parent(self):
        parent = FileObject(binary=b'parent_content')
        result = self.unpacker.remove_duplicates({parent.get_uid(): parent}, parent)
        self.assertEqual(len(result), 0, 'parent not removed from list')

    def test_unpack_status_packed_file(self):
        test_fo_packed = create_test_file_object(bin_path='container/test.7z')
        test_fo_packed.processed_analysis['unpacker'] = {}
        self.unpacker.get_unpack_status(test_fo_packed, [])
        result = test_fo_packed.processed_analysis['unpacker']
        self.assertGreater(result['entropy'], 0.7, 'entropy not valid')
        self.assertEqual(result['summary'], ['packed'], '7z file should be packed')
        self.unpacker.VALID_COMPRESSED_FILE_TYPES = ['application/x-7z-compressed']
        self.unpacker.get_unpack_status(test_fo_packed, [])
        self.assertEqual(test_fo_packed.processed_analysis['unpacker']['summary'], ['unpacked'], 'Unpacking Whitelist does not work')

    def test_unpack_status_unpacked_file(self):
        test_fo_unpacked = FileObject(binary='aaaaa')
        test_fo_unpacked.file_path = '/dev/null'
        test_fo_unpacked.processed_analysis['unpacker'] = {}
        self.unpacker.get_unpack_status(test_fo_unpacked, [])
        result = test_fo_unpacked.processed_analysis['unpacker']
        self.assertLess(result['entropy'], 0.7, 'entropy not valid')
        self.assertEqual(result['summary'], ['unpacked'])

    def test_detect_unpack_loss_data_lost(self):
        container = FileObject(binary=512 * 'ABCDEFGH')
        container.processed_analysis['unpacker'] = {'summary': []}
        included_file = FileObject(binary=256 * 'ABCDEFGH')
        self.unpacker._detect_unpack_loss(container, [included_file])
        self.assertIn('data lost', container.processed_analysis['unpacker']['summary'])
        self.assertEqual(container.processed_analysis['unpacker']['size packed -> unpacked'], '3.75 KiB -> 2.00 KiB')

    def test_detect_unpack_loss_no_data_lost(self):
        container = FileObject(binary=512 * 'ABCDEFGH')
        container.processed_analysis['unpacker'] = {'summary': []}
        included_file = FileObject(binary=512 * 'ABCDEFGH')
        self.unpacker._detect_unpack_loss(container, [included_file])
        self.assertIn('no data lost', container.processed_analysis['unpacker']['summary'])
        self.assertNotIn('data loss', container.processed_analysis['unpacker'])


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
