from helperFunctions.virtual_file_path import join_virtual_path
from test.common_helper import create_test_file_object, create_test_firmware


def test_root():
    root = create_test_firmware()
    assert root.virtual_file_path[root.uid] == [root.uid], 'virtual file path of root file not correct'


def test_add_file_object_to_firmware():
    root = create_test_firmware()
    child_one = create_test_file_object()
    root.add_included_file(child_one)
    assert root.uid in child_one.virtual_file_path.keys(), 'no virtual file path for root available'
    assert child_one.virtual_file_path[root.uid][0] == join_virtual_path(root.uid, child_one.file_path), 'virtual file path not correct'


def test_add_file_object_to_file_object():
    root = create_test_firmware()
    child_one = create_test_file_object()
    root.add_included_file(child_one)
    child_of_child_one = create_test_file_object(bin_path='get_files_test/testfile2')
    child_one.add_included_file(child_of_child_one)
    assert child_of_child_one.virtual_file_path[root.uid][0] == join_virtual_path(root.uid, child_one.uid, child_of_child_one.file_path)


def test_add_file_object_path_already_present():
    root = create_test_firmware()
    child = create_test_file_object()
    child.virtual_file_path = {root.uid: ['{}|some/known/path'.format(root.uid)]}
    root.add_included_file(child)
    assert len(child.virtual_file_path.keys()) == 1, 'there should be just one root object'
    assert len(child.virtual_file_path[root.uid]) == 1, 'number of paths should be one'
