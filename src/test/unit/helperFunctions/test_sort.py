from helperFunctions.sort import sort_nice_data_list_by_virtual_path


def test_sort_fo_list_by_virtual_path():
    a = {'virtual_file_paths': ['/a/foobar']}
    b = {'virtual_file_paths': ['/b/foobar']}
    c = {'virtual_file_paths': ['/c/foobar']}
    test_list = [c, b, a]
    assert sort_nice_data_list_by_virtual_path(test_list) == [a, b, c]
