from objects.file import FileObject
from test.common_helper import create_test_file_object, create_test_firmware, get_test_data_dir

EXPECTED_SHA = '268d870ffa2b21784e4dc955d8e8b8eb5f3bcddd6720a1e6d31d2cf84bd1bff8'


class TestObjectsFile:
    def test_get_file_from_binary(self):
        file_path = get_test_data_dir() / 'test_data_file.bin'
        test_object = FileObject.from_path(file_path)
        assert test_object.size == 19, 'correct size'
        assert test_object.sha256 == EXPECTED_SHA, 'correct sha256'
        assert test_object.file_name == 'test_data_file.bin', 'correct file name'
        assert test_object.file_path == file_path, 'correct file path'

    def test_file_object_from_uid(self):
        test_object = FileObject.from_uid(f'{EXPECTED_SHA}_123', file_name='foo')
        assert test_object.sha256 == EXPECTED_SHA, 'correct sha256'
        assert test_object.size == 123, 'correct file size'
        assert test_object.file_name == 'foo', 'correct file name'

    def test_add_included_file(self):
        parent = create_test_firmware()
        parent.scheduled_analysis = ['test']
        child = create_test_file_object()
        parent.add_included_file(child)
        assert len(parent.files_included) == 1, 'number of included files not correct'
        assert child.uid in parent.files_included, 'child uid not stored correctly'
        assert parent.uid in child.parents, 'parent not added to child'
        assert child.depth == parent.depth + 1, 'child depth not updated'
        assert child.scheduled_analysis == ['test'], 'child did not get scheduled analysis list of parent'

    def test_get_included_files(self):
        test_parent = FileObject.from_uid('abc_123', 'parent_file')
        test_child = FileObject.from_uid('def_456', '1st_child')
        test_child2 = FileObject.from_uid('ghi_789', '2nd_child')
        test_parent.add_included_file(test_child)
        test_parent.add_included_file(test_child2)
        assert len(test_parent.files_included) == 2, 'number of uids not correct'
        assert test_child.uid in test_parent.files_included, 'uid of first file not found'
        assert test_child2.uid in test_parent.files_included, 'uid of second file not found'

    def test_get_virtual_paths_for_all_uids(self):
        fo = FileObject.from_uid('abc_123', 'foo')
        fo.virtual_file_path = {'root_uid_1': ['vfp1', 'vfp2'], 'root_uid_2': ['vfp3']}
        assert sorted(fo.get_virtual_paths_for_all_uids()) == ['vfp1', 'vfp2', 'vfp3']
