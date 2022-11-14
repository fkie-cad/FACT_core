from common_helper_files import get_binary_from_file

from objects.file import FileObject
from test.common_helper import get_test_data_dir


class TestObjectsFile:  # pylint: disable=no-self-use
    def test_get_file_from_binary(self):
        file_path = f'{get_test_data_dir()}/test_data_file.bin'
        test_object = FileObject(file_path=file_path)
        assert test_object.size == 19, 'correct size'
        assert test_object.binary == b'test string in file', 'correct binary data'
        assert (
            test_object.sha256 == '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8'
        ), 'correct sha256'
        assert test_object.file_name == 'test_data_file.bin', 'correct file name'
        assert test_object.file_path == file_path, 'correct file path'

    def test_file_object_init_raw(self):
        test_object = FileObject()
        assert test_object.binary is None, 'correct binary'

    def test_file_object_init_with_binary(self):
        bin_data = get_binary_from_file(f'{get_test_data_dir()}/test_data_file.bin')
        test_object = FileObject(bin_data)
        assert (
            test_object.sha256 == '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8'
        ), 'correct sha256'
        assert test_object.file_name is None, 'correct file name'

    def test_add_included_file(self):
        parent = FileObject(binary=b'parent_file')
        parent.scheduled_analysis = ['test']
        child = FileObject(binary=b'child')
        parent.add_included_file(child)
        assert len(parent.files_included) == 1, 'number of included files not correct'
        assert child.uid in parent.files_included, 'child uid not stored correctly'
        assert parent.uid in child.parents, 'parent not added to child'
        assert child.depth == parent.depth + 1, 'child depth not updated'
        assert child.scheduled_analysis == ['test'], 'child did not get scheduled analysis list of parent'

    def test_get_included_files(self):
        test_parent = FileObject(binary=b'parent_file')
        test_child = FileObject(binary=b'1st child')
        test_child2 = FileObject(binary=b'2nd child')
        test_parent.add_included_file(test_child)
        test_parent.add_included_file(test_child2)
        assert len(test_parent.files_included) == 2, 'number of uids not correct'
        assert test_child.uid in test_parent.files_included, 'uid of first file not found'
        assert test_child2.uid in test_parent.files_included, 'uid of second file not found'

    def test_get_virtual_file_path(self):
        fo = FileObject(binary=b'file_object')
        assert fo.uid in fo.get_virtual_file_paths().keys(), 'not correct if path _ name not set'
        fo.file_name = 'the_file_name.txt'
        assert fo.get_virtual_file_paths()[fo.uid][0] == fo.uid, 'not correct if path not set'
        fo.virtual_file_path = {fo.uid: '/foo/bar/the_file_name.txt'}
        assert fo.get_virtual_file_paths()[fo.uid] == '/foo/bar/the_file_name.txt', 'not correct if path set'

    def test_get_root_uid(self):
        fo = FileObject(binary=b'file_object')
        fo.virtual_file_path = {'root_uid_1': 'virtual_file_path', 'root_uid_2': 'virtual_file_path'}
        assert fo.get_root_uid() in ['root_uid_1', 'root_uid_2']

    def test_get_one_virtual_path(self):
        fo = FileObject(binary=b'foo')
        assert fo.get_virtual_paths_for_one_uid() == [fo.uid], 'No Path set should be uid'
        fo.virtual_file_path = {
            'uid_a': ['test_file_path_a'],
            'uid_b': ['test_file_path_b'],
            'uid_c': ['test_file_path_c'],
        }
        assert fo.get_virtual_paths_for_one_uid() == ['test_file_path_a']
        assert fo.get_virtual_paths_for_one_uid(root_uid='uid_b') == ['test_file_path_b']
        fo.root_uid = 'uid_c'
        assert fo.get_virtual_paths_for_one_uid() == ['test_file_path_c']

    def test_get_virtual_path_for_non_existing_root(self):
        fo = FileObject(binary=b'foo')  # fo.virtual_file_path is empty
        assert fo.get_virtual_paths_for_one_uid(root_uid='non_existing') == [fo.uid]
        fo.virtual_file_path = {'other_root': ['some_vfp']}
        assert fo.get_virtual_paths_for_one_uid(root_uid='non_existing') == ['some_vfp']

    def test_get_virtual_paths_for_all_uids(self):
        fo = FileObject(binary=b'foo')
        fo.virtual_file_path = {'root_uid_1': ['vfp1', 'vfp2'], 'root_uid_2': ['vfp3']}
        assert sorted(fo.get_virtual_paths_for_all_uids()) == ['vfp1', 'vfp2', 'vfp3']
