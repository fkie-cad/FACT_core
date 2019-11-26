import unittest
from test.common_helper import create_test_firmware, create_test_file_object


class TestVirtualFilePath(unittest.TestCase):

    def test_add_file_object(self):
        root = create_test_firmware()
        self.assertEqual(root.virtual_file_path[root.uid], [root.uid], 'virtual file path of root file not correct')
        child_one = create_test_file_object()
        root.add_included_file(child_one)
        child_two = create_test_file_object(bin_path='get_files_test/testfile2')
        root.add_included_file(child_two)
        child_of_child_one = create_test_file_object(bin_path='get_files_test/testfile2')
        child_one.add_included_file(child_of_child_one)
        self.assertIn(root.uid, child_one.virtual_file_path.keys(), 'no virtual file path for root available')
        self.assertEqual(child_one.virtual_file_path[root.uid][0], '{}|{}'.format(root.uid, child_one.file_path), 'virtual file path not correct')
        self.assertEqual(child_of_child_one.virtual_file_path[root.uid][0], '{}|{}|{}'.format(root.uid, child_one.uid, child_of_child_one.file_path))

    def test_add_file_object_path_already_present(self):
        root = create_test_firmware()
        child = create_test_file_object()
        child.virtual_file_path = {root.uid: ['{}|some/known/path'.format(root.uid)]}
        root.add_included_file(child)
        print(child.virtual_file_path)
        self.assertEqual(len(child.virtual_file_path.keys()), 1, 'there should be just one root object')
        self.assertEqual(len(child.virtual_file_path[root.uid]), 1, 'number of pathes should be one')
