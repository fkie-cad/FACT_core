from common_helper_files import get_binary_from_file
import unittest

from helperFunctions.fileSystem import get_test_data_dir
from objects.file import FileObject
from test.common_helper import create_test_file_object


class Test_Objects_File(unittest.TestCase):

    def test_get_file_from_binary(self):
        file_path = '{}/test_data_file.bin'.format(get_test_data_dir())
        test_object = FileObject()
        test_object.create_from_file(file_path)
        self.assertEqual(test_object.size, 19, 'correct size')
        self.assertEqual(test_object.binary, b'test string in file', 'correct binary data')
        self.assertEqual(test_object.sha256, '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8', 'correct sha256')
        self.assertEqual(test_object.file_name, 'test_data_file.bin', 'correct file name')
        self.assertEqual(test_object.file_path, file_path, 'correct file path')

    def test_file_object_init_raw(self):
        test_object = FileObject()
        self.assertEqual(test_object.binary, None, 'correct binary')

    def test_file_object_init_with_binary(self):
        bin_data = get_binary_from_file('{}/test_data_file.bin'.format(get_test_data_dir()))
        test_object = FileObject(bin_data)
        self.assertEqual(test_object.sha256, '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8', 'correct sha256')
        self.assertEqual(test_object.file_name, None, 'correct file name')

    def test_add_included_file(self):
        parent = FileObject(binary=b'parent_file')
        parent.scheduled_analysis = ['test']
        child = FileObject(binary=b'child')
        parent.add_included_file(child)
        self.assertEqual(len(parent.files_included), 1, 'number of included files not correct')
        self.assertIn(child.get_uid(), parent.files_included, 'child uid not stored correctly')
        self.assertIn(parent.get_uid(), child.parents, 'parent not added to child')
        self.assertEqual(child.depth, parent.depth + 1, 'child depth not updated')
        self.assertEqual(child.scheduled_analysis, ['test'], 'child did not get scheduled analysis list of parent')

    def test_get_included_files_uids(self):
        test_parent = FileObject(binary=b'parent_file')
        test_child = FileObject(binary=b'1st child')
        test_child2 = FileObject(binary=b'2nd child')
        test_parent.add_included_file(test_child)
        test_parent.add_included_file(test_child2)
        self.assertEqual(len(test_parent.get_included_files_uids()), 2, 'number of uids not correct')
        self.assertIn(test_child.get_uid(), test_parent.get_included_files_uids(), 'uid of first file not found')
        self.assertIn(test_child2.get_uid(), test_parent.get_included_files_uids(), 'uid of second file not found')

    def test_get_virtual_file_path(self):
        fo = FileObject(binary=b'file_object')
        self.assertIn(fo.get_uid(), fo.get_virtual_file_paths().keys(), 'not correct if path _ name not set')
        fo.set_name('the_file_name.txt')
        self.assertEqual(fo.get_virtual_file_paths()[fo.get_uid()][0], fo.get_uid(), 'not correct if path not set')
        fo.virtual_file_path = {fo.get_uid(): '/foo/bar/the_file_name.txt'}
        self.assertEqual(fo.get_virtual_file_paths()[fo.get_uid()], '/foo/bar/the_file_name.txt', 'not correct if path set')

    def test_get_root_of_virtual_path(self):
        fo = FileObject(binary=b'file_object')
        virtual_test_path = 'root_uid|child_1_uid|child_2_uid|directory/file.type'
        self.assertEqual(fo.get_root_of_virtual_path(virtual_test_path), 'root_uid')

    def test_get_base_of_virtual_path(self):
        fo = FileObject(binary=b'file_object')
        virtual_test_path = 'root_uid|child_1_uid|child_2_uid|directory/file.type'
        self.assertEqual(fo.get_base_of_virtual_path(virtual_test_path), 'root_uid|child_1_uid|child_2_uid')

    def test_get_base_of_virtual_path_root(self):
        fo = FileObject(binary=b'file_object')
        virtual_test_path = 'root_uid'
        self.assertEqual(fo.get_base_of_virtual_path(virtual_test_path), '')

    def test_get_root_uid(self):
        fo = FileObject(binary=b'file_object')
        fo.virtual_file_path = {'root_uid_1': 'virtual_file_path', 'root_uid_2': 'virtual_file_path'}
        self.assertEqual(fo.get_root_uid() in ['root_uid_1', 'root_uid_2'], True)

    def test_get_one_virtual_path(self):
        fo = FileObject(binary=b'foo')
        self.assertEqual(fo.get_virtual_paths_for_one_uid(), [fo.get_uid()], 'No Path set should be uid')
        fo.virtual_file_path = {'uid_a': ['test_file_path_a'], 'uid_b': ['test_file_path_b'], 'uid_c': ['test_file_path_c']}
        self.assertEqual(fo.get_virtual_paths_for_one_uid(), ['test_file_path_a'])
        self.assertEqual(fo.get_virtual_paths_for_one_uid(root_uid='uid_b'), ['test_file_path_b'])
        fo.root_uid = 'uid_c'
        self.assertEqual(fo.get_virtual_paths_for_one_uid(), ['test_file_path_c'])

    def test_get_virtual_path_for_none_existing_uid(self):
        fo = FileObject(binary=b'foo')
        self.assertEqual(fo.get_virtual_paths_for_one_uid(root_uid='none_existing'), ['insufficient information: firmware analysis not complete'])

    def test_get_top_of_virtual_path(self):
        fo = FileObject()
        result = fo.get_top_of_virtual_path('foo|bar|test')
        self.assertEqual(result, 'test', 'top should be test')

    def test_overwrite_uid(self):
        fo = create_test_file_object()
        orig_uid = fo.get_uid()
        fo.overwrite_uid('new_uid')
        self.assertNotEqual(fo.get_uid(), orig_uid, 'uid not changed')
        self.assertEqual(fo.get_uid(), 'new_uid', 'new uid not correct')
